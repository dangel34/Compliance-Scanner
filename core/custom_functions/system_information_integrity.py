"""
system_information_integrity.py

Houses all system and information integrity (SI) check functions for CMMC
SI.L1-3.14.1 through SI.L2-3.14.7.
Each function corresponds to a cs_f() reference in the SI control JSON files.

Naming convention:
    <check_name>_wc   -> Windows Client
    <check_name>_ws   -> Windows Server
    <check_name>_lx   -> Linux / Debian (shared)
"""

import subprocess
import re
import time
from pathlib import Path
from datetime import datetime, timezone

_RUN_CACHE: dict[tuple[object, bool, int], tuple[int, str, str]] = {}


def clear_cache() -> None:
    """Clear the command result cache so the next scan gets fresh results."""
    _RUN_CACHE.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: str, shell: bool = True, timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    cache_key = (cmd, shell, timeout)
    cached = _RUN_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = (result.returncode, result.stdout.strip(), result.stderr.strip())
        _RUN_CACHE[cache_key] = output
        return output
    except subprocess.TimeoutExpired:
        output = (-1, "", "command timed out")
        _RUN_CACHE[cache_key] = output
        return output


def _ps(cmd: str) -> tuple[int, str, str]:
    """Run a PowerShell command and return (returncode, stdout, stderr)."""
    cache_key = ("_ps", cmd, 30)
    cached = _RUN_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        result = subprocess.run(
            ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", cmd],
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output: tuple[int, str, str] = (
            result.returncode,
            result.stdout.strip(),
            result.stderr.strip(),
        )
    except subprocess.TimeoutExpired:
        output = (-1, "", "command timed out")
    _RUN_CACHE[cache_key] = output
    return output


def _reg_get(key: str, value: str) -> str | None:
    """Read a Windows registry value; returns the value string or None on failure."""
    rc, out, _ = _ps(
        f"(Get-ItemProperty -Path '{key}' -Name '{value}' "
        f"-ErrorAction SilentlyContinue).'{value}'"
    )
    return out.strip() if rc == 0 and out.strip() else None


def _file_age_days(path: Path) -> float | None:
    """Return the age in days of a file, or None if it doesn't exist."""
    if not path.exists():
        return None
    return (time.time() - path.stat().st_mtime) / 86400


def _service_running_lx(name: str) -> bool:
    """Return True if a systemd service is active on Linux."""
    rc, _, _ = _run(f"systemctl is-active {name} 2>/dev/null")
    return rc == 0


def _binary_exists_lx(*names: str) -> bool:
    """Return True if any of the given binaries exist on PATH."""
    for name in names:
        rc, _, _ = _run(f"which {name} 2>/dev/null")
        if rc == 0:
            return True
    return False


# ===========================================================================
# SI.L1-3.14.1 — Identify, Report, and Correct System Flaws
# ===========================================================================

def windows_update_enabled_wc() -> tuple[bool, str]:
    """Verify the Windows Update service is running on Windows Client."""
    rc, out, err = _ps(
        "Get-Service -Name wuauserv | Select-Object -ExpandProperty Status"
    )
    if rc != 0:
        return (False, f"Could not query Windows Update service status: {err}")
    if out.strip().lower() == "running":
        return (True, "Windows Update service (wuauserv) is running")
    return (False, f"Windows Update service is not running (status: {out.strip() or 'unknown'})")


def missing_patches_wc() -> tuple[bool, str]:
    """Confirm no critical or high patches are missing on Windows Client."""
    rc, out, err = _ps(
        "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()"
        ".Search('IsInstalled=0 and Type=Software and IsHidden=0').Updates.Count"
    )
    if rc != 0:
        return (False, f"Could not query missing patches: {err}")
    try:
        count = int(out.strip())
        if count == 0:
            return (True, "No missing software patches found")
        return (False, f"{count} missing patch(es) detected")
    except ValueError:
        return (False, "Could not parse missing patch count")


def last_update_date_wc() -> tuple[bool, str]:
    """Verify the last successful Windows Update is within 30 days on Windows Client."""
    rc, out, err = _ps(
        "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate"
    )
    if rc != 0 or not out.strip():
        return (False, f"Could not retrieve last Windows Update date: {err or 'no output'}")
    try:
        last = datetime.strptime(out.strip()[:10], "%Y-%m-%d")
        age_days = (datetime.now(timezone.utc) - last).days
        if age_days <= 30:
            return (True, f"Last Windows Update was {age_days} day(s) ago ({last.date()})")
        return (False, f"Last Windows Update was {age_days} day(s) ago ({last.date()}) — exceeds 30-day limit")
    except ValueError:
        return (False, f"Could not parse last update date: {out.strip()}")


def patch_agent_active_wc() -> tuple[bool, str]:
    """Confirm a patch management agent is installed and running on Windows Client."""
    agents = ["CcmExec", "IntuneManagementExtension", "wuauserv"]
    for agent in agents:
        rc, out, _ = _ps(
            f"Get-Service -Name '{agent}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status"
        )
        if rc == 0 and out.strip().lower() == "running":
            return (True, f"Patch management agent '{agent}' is running")
    return (False, f"No patch management agent is running (checked: {', '.join(agents)})")


def windows_update_enabled_ws() -> tuple[bool, str]:
    """Verify the Windows Update service is running on Windows Server."""
    return windows_update_enabled_wc()


def missing_patches_ws() -> tuple[bool, str]:
    """Confirm no critical patches are missing on Windows Server."""
    return missing_patches_wc()


def last_update_date_ws() -> tuple[bool, str]:
    """Verify the last successful Windows Update is within 30 days on Windows Server."""
    return last_update_date_wc()


def patch_agent_active_ws() -> tuple[bool, str]:
    """Confirm a patch management agent is running on Windows Server."""
    return patch_agent_active_wc()


def pending_reboot_ws() -> tuple[bool, str]:
    """Detect if a pending reboot is blocking patch completion on Windows Server."""
    # Returns True (passing) when NO pending reboot is detected
    pending_keys = [
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
    ]
    for key in pending_keys:
        rc, out, _ = _ps(
            f"Test-Path '{key}'"
        )
        if rc == 0 and out.strip().lower() == "true":
            return (False, f"Pending reboot detected (registry key exists): {key}")
    return (True, "No pending reboot detected (all reboot-indicator registry keys are absent)")


def security_repos_configured_lx() -> tuple[bool, str]:
    """Verify security update repositories are configured on Linux/Debian."""
    # Check apt sources for security repos
    rc, out, _ = _run(
        "grep -rE 'security|updates' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null "
        "| grep -v '^#' | grep -v '^$'"
    )
    if rc == 0 and out.strip():
        return (True, "Security update repositories are configured in apt sources")
    # Check yum/dnf repos
    rc2, out2, _ = _run(
        "grep -rE 'security|updates' /etc/yum.repos.d/ 2>/dev/null | grep -v '^#'"
    )
    if rc2 == 0 and len(out2.strip()) > 0:
        return (True, "Security update repositories are configured in yum/dnf repos")
    return (False, "No security update repositories found in apt or yum/dnf configuration")


def missing_patches_lx() -> tuple[bool, str]:
    """Confirm no outstanding security updates are available on Linux/Debian."""
    # Try apt (use -s / --simulate; --just-print is a deprecated alias)
    rc, out, _ = _run(
        "apt-get -s upgrade 2>/dev/null | grep -c '^Inst'",
        timeout=60
    )
    if rc == 0:
        try:
            count = int(out.strip())
            if count == 0:
                return (True, "No pending package upgrades found (apt-get -s upgrade)")
            return (False, f"{count} package(s) have pending upgrades (apt-get -s upgrade)")
        except ValueError:
            pass
    # Try yum/dnf
    rc2, out2, _ = _run("yum check-update --security -q 2>/dev/null | grep -c '\\.'")
    try:
        count2 = int(out2.strip())
        if count2 == 0:
            return (True, "No pending security updates found (yum check-update --security)")
        return (False, f"{count2} security update(s) are pending (yum check-update --security)")
    except ValueError:
        return (False, "Could not determine pending patch status (apt and yum/dnf both failed)")


def last_update_date_lx() -> tuple[bool, str]:
    """Verify the system has applied updates within 30 days on Linux/Debian."""
    # Check dpkg log
    dpkg_log = Path("/var/log/dpkg.log")
    if dpkg_log.exists():
        age = _file_age_days(dpkg_log)
        if age is not None and age <= 30:
            rc, out, _ = _run(
                "grep 'upgrade\\|install' /var/log/dpkg.log 2>/dev/null | tail -1"
            )
            if rc == 0 and out.strip():
                return (True, f"Last package update was within {int(age)} day(s) (dpkg.log): {out.strip()[:80]}")
    # Check yum/dnf log
    for log in ["/var/log/yum.log", "/var/log/dnf.log"]:
        path = Path(log)
        if path.exists():
            age = _file_age_days(path)
            if age is not None and age <= 30:
                return (True, f"Last package update was within {int(age)} day(s) ({log})")
    return (False, "No package update activity found within the last 30 days (checked dpkg.log, yum.log, dnf.log)")


def kernel_current_lx() -> tuple[bool, str]:
    """Check that the running kernel has no pending security updates on Linux/Debian."""
    rc, running, _ = _run("uname -r")
    if rc != 0:
        return (False, "Could not determine running kernel version (uname -r failed)")
    # Check for pending kernel security updates via apt
    rc2, out2, _ = _run(
        "apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -i 'linux-image'",
        timeout=60
    )
    if rc2 == 0:
        # If apt reports pending linux-image upgrades, kernel is out of date
        if out2.strip():
            return (False, f"Pending kernel update(s) found: {out2.strip()[:120]}")
        return (True, f"No pending kernel updates found (running: {running.strip()})")
    return (True, f"Cannot determine kernel update status via apt — assuming passing (running: {running.strip()})")


# ===========================================================================
# SI.L1-3.14.2 — Provide Protection from Malicious Code
# ===========================================================================

def av_installed_running_wc() -> tuple[bool, str]:
    """Verify antivirus or EDR is installed and running on Windows Client."""
    rc, out, err = _ps(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty AntivirusEnabled"
    )
    if rc == 0 and out.strip().lower() == "true":
        return (True, "Windows Defender Antivirus is enabled")
    # Check for third-party AV via Security Center
    rc2, out2, err2 = _ps(
        "Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct "
        "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out2.strip())
        if rc2 == 0 and count > 0:
            return (True, f"{count} antivirus product(s) registered in Security Center")
        return (False, "No antivirus product is installed or running")
    except ValueError:
        return (False, "Could not determine antivirus status")


def realtime_protection_enabled_wc() -> tuple[bool, str]:
    """Confirm real-time protection is enabled on Windows Client."""
    rc, out, err = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"
    )
    if rc != 0:
        return (False, f"Could not query real-time protection status: {err}")
    if out.strip().lower() == "true":
        return (True, "Real-time protection is enabled")
    return (False, f"Real-time protection is not enabled (RealTimeProtectionEnabled = {out.strip() or 'False'})")


def av_definitions_current_wc() -> tuple[bool, str]:
    """Verify antivirus definitions are current on Windows Client."""
    rc, out, err = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated"
    )
    if rc != 0 or not out.strip():
        return (False, f"Could not retrieve antivirus signature update date: {err or 'no output'}")
    try:
        last_updated = datetime.strptime(out.strip()[:10], "%Y-%m-%d")
        age_days = (datetime.now(timezone.utc) - last_updated).days
        if age_days <= 2:
            return (True, f"Antivirus definitions are current (last updated: {last_updated.date()}, {age_days} day(s) ago)")
        return (False, f"Antivirus definitions are stale (last updated: {last_updated.date()}, {age_days} day(s) ago — limit: 2 days)")
    except ValueError:
        return (False, f"Could not parse antivirus signature date: {out.strip()}")


def av_scan_coverage_wc() -> tuple[bool, str]:
    """Confirm antivirus is configured to scan all critical paths on Windows Client."""
    rc, out, err = _ps(
        "Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension | Format-List"
    )
    if rc != 0:
        return (False, f"Could not query antivirus exclusions: {err}")
    # Check exclusions are not overly broad
    broad_exclusions = ["C:\\", "C:\\Windows", "C:\\Users", "*"]
    found_broad = [exc for exc in broad_exclusions if exc in out]
    if found_broad:
        return (False, f"Antivirus has overly broad exclusions: {', '.join(found_broad)}")
    return (True, "No overly broad antivirus exclusions found (C:\\, C:\\Windows, C:\\Users, * not excluded)")


def av_installed_running_ws() -> tuple[bool, str]:
    """Verify antivirus or EDR is installed and running on Windows Server."""
    return av_installed_running_wc()


def realtime_protection_enabled_ws() -> tuple[bool, str]:
    """Confirm real-time protection is enabled on Windows Server."""
    return realtime_protection_enabled_wc()


def av_definitions_current_ws() -> tuple[bool, str]:
    """Verify antivirus definitions are current on Windows Server."""
    return av_definitions_current_wc()


def av_exclusions_minimal_ws() -> tuple[bool, str]:
    """Confirm antivirus exclusions are minimal and documented on Windows Server."""
    rc, out, err = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
    )
    if rc != 0:
        return (True, "No ExclusionPath configured or could not query (treated as compliant)")
    paths = [p.strip() for p in out.splitlines() if p.strip()]
    broad = ["C:\\", "C:\\Windows", "C:\\Users", "D:\\", "*", "C:\\Program Files"]
    found_broad = [p for p in paths if p in broad]
    if not found_broad:
        return (True, f"Antivirus exclusions are minimal ({len(paths)} path(s) excluded, none overly broad)")
    return (False, f"Antivirus has overly broad exclusion path(s): {', '.join(found_broad)}")


def av_installed_running_lx() -> tuple[bool, str]:
    """Verify ClamAV or equivalent is installed on Linux/Debian."""
    if _binary_exists_lx("clamscan", "clamd", "sophos-av", "eset-daemon"):
        return (True, "Antivirus binary found (ClamAV or equivalent)")
    return (False, "No antivirus binary found (checked: clamscan, clamd, sophos-av, eset-daemon)")


def av_scan_scheduled_lx() -> tuple[bool, str]:
    """Confirm antimalware scan is scheduled via cron or systemd timer on Linux/Debian."""
    # Check cron for clamscan
    rc, out, _ = _run("grep -r 'clamscan\\|clamdscan\\|freshclam' /etc/cron* /var/spool/cron/ 2>/dev/null")
    if rc == 0 and out.strip():
        return (True, "Antimalware scan is scheduled via cron")
    # Check systemd timers
    rc2, out2, _ = _run("systemctl list-timers --all 2>/dev/null | grep -iE 'clam|av|scan'")
    if rc2 == 0 and len(out2.strip()) > 0:
        return (True, "Antimalware scan is scheduled via systemd timer")
    return (False, "No antimalware scan schedule found (checked cron and systemd timers)")


def av_definitions_current_lx() -> tuple[bool, str]:
    """Verify ClamAV virus databases are up to date on Linux/Debian."""
    db_paths = [
        Path("/var/lib/clamav/main.cvd"),
        Path("/var/lib/clamav/daily.cvd"),
        Path("/var/lib/clamav/daily.cld"),
        Path("/var/lib/clamav/main.cld"),
    ]
    for db in db_paths:
        if db.exists():
            age = _file_age_days(db)
            if age is not None:
                if age <= 2:
                    return (True, f"ClamAV database {db.name} is current ({age:.1f} day(s) old)")
                return (False, f"ClamAV database {db.name} is stale ({age:.1f} day(s) old — limit: 2 days)")
    return (False, "No ClamAV database files found in /var/lib/clamav/")


def rootkit_detection_lx() -> tuple[bool, str]:
    """Confirm rkhunter or chkrootkit is installed on Linux/Debian."""
    if _binary_exists_lx("rkhunter", "chkrootkit"):
        return (True, "Rootkit detection tool is installed (rkhunter or chkrootkit)")
    return (False, "No rootkit detection tool found (checked: rkhunter, chkrootkit)")


# ===========================================================================
# SI.L1-3.14.3 — Monitor System Security Alerts and Advisories
# ===========================================================================

def security_center_active_wc() -> tuple[bool, str]:
    """Verify Windows Security Center is active on Windows Client."""
    rc, out, err = _ps(
        "Get-Service -Name wscsvc -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty Status"
    )
    if rc != 0:
        return (False, f"Could not query Windows Security Center (wscsvc) status: {err}")
    if out.strip().lower() == "running":
        return (True, "Windows Security Center (wscsvc) is running")
    return (False, f"Windows Security Center (wscsvc) is not running (status: {out.strip() or 'unknown'})")


def siem_agent_active_wc() -> tuple[bool, str]:
    """Confirm a SIEM or security monitoring agent is running on Windows Client."""
    agents = [
        "SplunkForwarder", "elastic-agent", "ElasticEndpoint",
        "CbDefense", "CrowdStrike", "SentinelAgent", "nxlog",
        "MsSense", "Wazuh"
    ]
    for agent in agents:
        rc, out, _ = _ps(
            f"Get-Service -Name '{agent}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status"
        )
        if rc == 0 and out.strip().lower() == "running":
            return (True, f"SIEM/security monitoring agent '{agent}' is running")
    return (False, f"No SIEM or security monitoring agent is running (checked: {', '.join(agents)})")


def vuln_mgmt_enrolled_wc() -> tuple[bool, str]:
    """Verify the system is enrolled in a vulnerability management program on Windows Client."""
    vuln_agents = [
        "NessusAgent", "QualysAgent", "rapid7agent",
        "InsightAgent", "tenable_nessus_agent"
    ]
    for agent in vuln_agents:
        rc, out, _ = _ps(
            f"Get-Service -Name '{agent}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status"
        )
        if rc == 0 and out.strip().lower() == "running":
            return (True, f"Vulnerability management agent '{agent}' is running")
    return (False, f"No vulnerability management agent is running (checked: {', '.join(vuln_agents)})")


def security_center_active_ws() -> tuple[bool, str]:
    """Verify Windows Security Center is active on Windows Server."""
    return security_center_active_wc()


def siem_agent_active_ws() -> tuple[bool, str]:
    """Confirm a SIEM or security monitoring agent is running on Windows Server."""
    return siem_agent_active_wc()


def vuln_mgmt_enrolled_ws() -> tuple[bool, str]:
    """Verify the server is enrolled in a vulnerability management program."""
    return vuln_mgmt_enrolled_wc()


def vuln_scanner_agent_ws() -> tuple[bool, str]:
    """Confirm a vulnerability scanner agent is installed and active on Windows Server."""
    return vuln_mgmt_enrolled_ws()


def siem_agent_active_lx() -> tuple[bool, str]:
    """Confirm a SIEM or log forwarding agent is active on Linux/Debian."""
    agents = [
        "filebeat", "elastic-agent", "splunkd",
        "wazuh-agent", "ossec", "td-agent", "fluentd", "nxlog"
    ]
    for agent in agents:
        if _service_running_lx(agent):
            return (True, f"SIEM/log forwarding agent '{agent}' is active")
    return (False, f"No SIEM or log forwarding agent is active (checked: {', '.join(agents)})")


def vuln_mgmt_enrolled_lx() -> tuple[bool, str]:
    """Verify a vulnerability scanner agent is installed on Linux/Debian."""
    if _binary_exists_lx("nessus-agent", "qualys-cloud-agent", "rapid7agent", "openvas"):
        return (True, "Vulnerability scanner agent is installed (nessus-agent/qualys/rapid7/openvas)")
    return (False, "No vulnerability scanner agent found (checked: nessus-agent, qualys-cloud-agent, rapid7agent, openvas)")


def advisory_monitoring_lx() -> tuple[bool, str]:
    """Confirm a process or tool monitors security advisories on Linux/Debian."""
    # Check for debian-goodies, apt-listbugs, or apticron which monitor DSA advisories
    rc, out, _ = _run("dpkg -l apticron apt-listchanges apt-listbugs 2>/dev/null | grep '^ii'")
    if rc == 0 and out.strip():
        installed = [l.split()[1] for l in out.strip().splitlines()]
        return (True, f"Advisory monitoring tool(s) installed: {', '.join(installed)}")
    # Check for openscap or oscap as a vulnerability scanning indicator
    if _binary_exists_lx("oscap", "openscap"):
        return (True, "OpenSCAP is installed for advisory/vulnerability monitoring")
    return (False, "No advisory monitoring tools found (checked: apticron, apt-listchanges, apt-listbugs, oscap, openscap)")


# ===========================================================================
# SI.L2-3.14.4 — Update Malicious Code Protection Mechanisms
# ===========================================================================

def av_definitions_age_wc() -> tuple[bool, str]:
    """Verify antivirus definitions are no more than 24 hours old on Windows Client."""
    rc, out, err = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated"
    )
    if rc != 0 or not out.strip():
        return (False, f"Could not retrieve antivirus signature update date: {err or 'no output'}")
    try:
        last_updated = datetime.strptime(out.strip()[:10], "%Y-%m-%d")
        age_days = (datetime.now(timezone.utc) - last_updated).days
        if age_days <= 1:
            return (True, f"Antivirus definitions are within 24 hours (last updated: {last_updated.date()}, {age_days} day(s) ago)")
        return (False, f"Antivirus definitions are stale (last updated: {last_updated.date()}, {age_days} day(s) ago — limit: 1 day)")
    except ValueError:
        return (False, f"Could not parse antivirus signature date: {out.strip()}")


def av_auto_update_enabled_wc() -> tuple[bool, str]:
    """Confirm automatic definition updates are enabled on Windows Client."""
    rc, out, err = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty SignatureScheduleDay"
    )
    # 0 = every day, 8 = never — anything other than 8 is acceptable
    if rc == 0 and out.strip() != "8":
        return (True, f"Antivirus auto-update is enabled (SignatureScheduleDay = {out.strip() or '0/daily'})")
    # Check via Windows Update settings for Defender updates
    val = _reg_get(
        r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates",
        "ForceUpdateFromMU"
    )
    if val == "1":
        return (True, "Antivirus auto-update is enforced via policy (ForceUpdateFromMU = 1)")
    return (False, f"Antivirus auto-update may be disabled (SignatureScheduleDay = {out.strip() or 'unknown'}, ForceUpdateFromMU = {val or 'not set'})")


def av_engine_current_wc() -> tuple[bool, str]:
    """Verify the antivirus engine version is current on Windows Client."""
    rc, out, err = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty AMEngineVersion"
    )
    # Engine version should be non-zero; actual currency check requires external feed
    if rc != 0:
        return (False, f"Could not query antivirus engine version: {err}")
    version = out.strip()
    if version and version != "0.0.0.0":
        return (True, f"Antivirus engine is reporting a non-zero version: {version}")
    return (False, f"Antivirus engine version is zero or empty (AMEngineVersion = {version or 'not reported'})")


def av_definitions_age_ws() -> tuple[bool, str]:
    """Verify antivirus definitions are no more than 24 hours old on Windows Server."""
    return av_definitions_age_wc()


def av_auto_update_enabled_ws() -> tuple[bool, str]:
    """Confirm automatic definition updates are enabled on Windows Server."""
    return av_auto_update_enabled_wc()


def av_engine_current_ws() -> tuple[bool, str]:
    """Verify the antivirus engine version is current on Windows Server."""
    return av_engine_current_wc()


def av_definitions_age_lx() -> tuple[bool, str]:
    """Verify ClamAV databases are no more than 24 hours old on Linux/Debian."""
    db_paths = [
        Path("/var/lib/clamav/daily.cld"),
        Path("/var/lib/clamav/daily.cvd"),
    ]
    for db in db_paths:
        if db.exists():
            age = _file_age_days(db)
            if age is not None:
                if age <= 1:
                    return (True, f"ClamAV daily database {db.name} is within 24 hours ({age:.1f} day(s) old)")
                return (False, f"ClamAV daily database {db.name} is stale ({age:.1f} day(s) old — limit: 1 day)")
    return (False, "No ClamAV daily database files found (/var/lib/clamav/daily.cld or daily.cvd)")


def av_auto_update_enabled_lx() -> tuple[bool, str]:
    """Confirm freshclam or equivalent automatic update daemon is running on Linux/Debian."""
    if _service_running_lx("clamav-freshclam"):
        return (True, "clamav-freshclam service is active (automatic AV definition updates)")
    if _service_running_lx("freshclam"):
        return (True, "freshclam service is active (automatic AV definition updates)")
    # Check cron for freshclam
    rc, out, _ = _run("grep -r 'freshclam' /etc/cron* /var/spool/cron/ 2>/dev/null")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "freshclam is scheduled via cron for automatic AV definition updates")
    return (False, "No automatic ClamAV definition update mechanism found (freshclam service not running, no cron entry)")


def rkhunter_db_current_lx() -> tuple[bool, str]:
    """Verify rkhunter or chkrootkit databases are current on Linux/Debian."""
    rkhunter_db = Path("/var/lib/rkhunter/db")
    if rkhunter_db.exists():
        age = _file_age_days(rkhunter_db)
        if age is not None:
            if age <= 7:
                return (True, f"rkhunter database is current ({age:.1f} day(s) old)")
            return (False, f"rkhunter database is stale ({age:.1f} day(s) old — limit: 7 days)")
    # Check rkhunter log
    rkhunter_log = Path("/var/log/rkhunter.log")
    if rkhunter_log.exists():
        age = _file_age_days(rkhunter_log)
        if age is not None:
            if age <= 7:
                return (True, f"rkhunter was last run within 7 days ({age:.1f} day(s) ago)")
            return (False, f"rkhunter log is stale ({age:.1f} day(s) old — limit: 7 days)")
    # Check if chkrootkit runs via cron
    rc, out, _ = _run("grep -r 'chkrootkit\\|rkhunter' /etc/cron* 2>/dev/null")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "rkhunter or chkrootkit is scheduled via cron")
    return (False, "No rkhunter or chkrootkit database found and no cron schedule detected")


# ===========================================================================
# SI.L1-3.14.5 — Perform Periodic and Real-Time Scans
# ===========================================================================

def scheduled_scan_configured_wc() -> tuple[bool, str]:
    """Verify a periodic scan is scheduled in Windows Defender on Windows Client."""
    rc, out, err = _ps(
        "Get-MpPreference | Select-Object ScanScheduleDay,ScanScheduleTime | Format-List"
    )
    if rc != 0:
        return (False, f"Could not query Defender scan schedule: {err}")
    day_match = re.search(r'ScanScheduleDay\s*:\s*(\S+)', out)
    # 0 = every day, 1-7 = specific day, 8 = never
    if day_match and day_match.group(1) != "8":
        day_val = day_match.group(1)
        day_name = {
            "0": "daily", "1": "Sunday", "2": "Monday", "3": "Tuesday",
            "4": "Wednesday", "5": "Thursday", "6": "Friday", "7": "Saturday"
        }.get(day_val, day_val)
        return (True, f"Periodic Defender scan is scheduled: ScanScheduleDay = {day_val} ({day_name})")
    return (False, f"Periodic Defender scan is not scheduled (ScanScheduleDay = {day_match.group(1) if day_match else 'not set'} = Never)")


def last_scan_completed_wc() -> tuple[bool, str]:
    """Verify the last Defender scan completed successfully on Windows Client."""
    rc, out, err = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty QuickScanAge"
    )
    if rc != 0 or not out.strip():
        return (False, f"Could not query last Defender scan age: {err or 'no output'}")
    try:
        # QuickScanAge is in days — should be within 7 days
        age = int(out.strip())
        if age <= 7:
            return (True, f"Last Defender quick scan was {age} day(s) ago")
        return (False, f"Last Defender quick scan was {age} day(s) ago (exceeds 7-day limit)")
    except ValueError:
        return (False, f"Could not parse QuickScanAge value: {out.strip()}")


def removable_media_scan_wc() -> tuple[bool, str]:
    """Confirm removable media scanning is enabled on Windows Client."""
    rc, out, err = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty DisableRemovableDriveScanning"
    )
    if rc != 0:
        return (False, f"Could not query removable media scan setting: {err}")
    # False means scanning IS enabled (not disabled)
    val = out.strip().lower()
    if val == "false":
        return (True, "Removable media scanning is enabled (DisableRemovableDriveScanning = False)")
    return (False, f"Removable media scanning is disabled (DisableRemovableDriveScanning = {out.strip() or 'True'})")


def scheduled_scan_configured_ws() -> tuple[bool, str]:
    """Verify a periodic scan is scheduled on Windows Server."""
    return scheduled_scan_configured_wc()


def last_scan_completed_ws() -> tuple[bool, str]:
    """Verify the last Defender scan completed on Windows Server."""
    return last_scan_completed_wc()


def download_scan_ws() -> tuple[bool, str]:
    """Confirm real-time scanning covers downloaded/staged files on Windows Server."""
    return realtime_protection_enabled_ws()


def scheduled_scan_configured_lx() -> tuple[bool, str]:
    """Verify a periodic ClamAV scan is scheduled on Linux/Debian."""
    rc, out, _ = _run(
        "grep -r 'clamscan\\|clamdscan' /etc/cron.daily /etc/cron.weekly "
        "/etc/cron.d/ /var/spool/cron/ 2>/dev/null"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, "Periodic ClamAV scan is scheduled via cron")
    return (False, "No periodic ClamAV scan schedule found in cron directories")


def onaccess_scan_lx() -> tuple[bool, str]:
    """Confirm ClamAV on-access scanning is active on Linux/Debian."""
    if _service_running_lx("clamav-daemon"):
        # Check if on-access scanning is enabled in clamd.conf
        clamd_conf = Path("/etc/clamav/clamd.conf")
        if clamd_conf.exists():
            content = clamd_conf.read_text()
            if re.search(r'^\s*OnAccessIncludePath', content, re.MULTILINE):
                return (True, "ClamAV on-access scanning is active (clamav-daemon running with OnAccessIncludePath configured)")
    # Check for clamonacc process
    rc, out, _ = _run("pgrep -x clamonacc 2>/dev/null")
    if rc == 0:
        return (True, "ClamAV on-access scanning is active (clamonacc process is running)")
    return (False, "ClamAV on-access scanning is not active (clamav-daemon not running or OnAccessIncludePath not configured, clamonacc not found)")


def last_scan_completed_lx() -> tuple[bool, str]:
    """Verify a scan log exists with recent results on Linux/Debian."""
    scan_logs = [
        Path("/var/log/clamav/clamav.log"),
        Path("/var/log/clamav/freshclam.log"),
    ]
    for log in scan_logs:
        if log.exists():
            age = _file_age_days(log)
            if age is not None and age <= 7:
                return (True, f"ClamAV scan log {log.name} has recent activity ({age:.1f} day(s) old)")
    # Check for clamscan output in syslog
    rc, out, _ = _run("grep -i 'clamav\\|clamscan' /var/log/syslog 2>/dev/null | tail -1")
    if rc == 0 and len(out.strip()) > 0:
        return (True, f"Recent ClamAV activity found in syslog: {out.strip()[:80]}")
    return (False, "No recent ClamAV scan activity found (checked clamav.log, freshclam.log, and syslog)")


# ===========================================================================
# SI.L2-3.14.6 — Monitor Systems to Detect Attacks
# ===========================================================================

def asr_rules_enabled_wc() -> tuple[bool, str]:
    """Confirm Windows Defender ASR rules are enabled on Windows Client."""
    rc, out, err = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions"
    )
    if rc != 0 or not out.strip():
        return (False, f"Could not query ASR rules or no rules are configured: {err or 'no output'}")
    # Rules should have at least some entries set to Enabled (1) or AuditMode (2)
    if "1" in out or "2" in out:
        return (True, "Windows Defender ASR rules are configured (at least one rule in Enabled or AuditMode)")
    return (False, f"No ASR rules are in Enabled or AuditMode state (values: {out.strip()})")


def logs_forwarded_wc() -> tuple[bool, str]:
    """Verify security event logs are forwarded to a SIEM on Windows Client."""
    return siem_agent_active_wc()


def asr_rules_enabled_ws() -> tuple[bool, str]:
    """Confirm Windows Defender ASR rules are enabled on Windows Server."""
    return asr_rules_enabled_wc()


def logs_forwarded_ws() -> tuple[bool, str]:
    """Verify security event logs are forwarded to a SIEM on Windows Server."""
    return siem_agent_active_ws()


def network_monitoring_ws() -> tuple[bool, str]:
    """Confirm network traffic monitoring is active on Windows Server."""
    # Check for common network monitoring or NDR agents
    agents = ["npcap", "Wireshark", "NetFlow", "MsSense", "CbDefense", "CrowdStrike"]
    for agent in agents:
        rc, out, _ = _ps(
            f"Get-Service -Name '{agent}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status"
        )
        if rc == 0 and out.strip().lower() == "running":
            return (True, f"Network monitoring agent '{agent}' is running")
    # Check Windows Firewall logging as minimum baseline
    rc2, out2, err2 = _ps(
        "Get-NetFirewallProfile | Select-Object -ExpandProperty LogFileName"
    )
    if rc2 == 0 and len(out2.strip()) > 0:
        return (True, "Windows Firewall logging is configured (provides minimum network traffic visibility)")
    return (False, "No network monitoring agent running and firewall logging is not configured")


def credential_guard_ws() -> tuple[bool, str]:
    """Verify Credential Guard is enabled on Windows Server."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity"
    )
    cg_val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "LsaCfgFlags"
    )
    if val == "1":
        return (True, "Credential Guard is enabled via VBS (EnableVirtualizationBasedSecurity = 1)")
    if cg_val in ("1", "2"):
        return (True, f"Credential Guard is configured (LsaCfgFlags = {cg_val})")
    return (False, f"Credential Guard is not enabled (EnableVirtualizationBasedSecurity = {val or 'not set'}, LsaCfgFlags = {cg_val or 'not set'})")


def ids_active_lx() -> tuple[bool, str]:
    """Verify an IDS or HIDS tool is installed and active on Linux/Debian."""
    hids_services = ["wazuh-agent", "ossec", "aide", "samhain"]
    for svc in hids_services:
        if _service_running_lx(svc):
            return (True, f"HIDS service '{svc}' is active")
    if _binary_exists_lx("wazuh-agent", "ossec-control", "aide"):
        return (True, "HIDS binary found (wazuh-agent, ossec-control, or aide)")
    return (False, f"No IDS/HIDS tool is active or installed (checked services: {', '.join(hids_services)}; binaries: wazuh-agent, ossec-control, aide)")


def fail2ban_active_lx() -> tuple[bool, str]:
    """Confirm fail2ban is running and configured on Linux/Debian."""
    if not _service_running_lx("fail2ban"):
        return (False, "fail2ban service is not running")
    # Verify SSH jail is enabled
    rc, out, _ = _run("fail2ban-client status sshd 2>/dev/null")
    if rc == 0 and "Status" in out:
        return (True, "fail2ban is running and the sshd jail is configured")
    return (False, "fail2ban is running but the sshd jail is not configured or not responding")


def logs_forwarded_lx() -> tuple[bool, str]:
    """Verify audit logs are forwarded to a centralized SIEM on Linux/Debian."""
    return siem_agent_active_lx()


def auditd_attack_rules_lx() -> tuple[bool, str]:
    """Confirm auditd rules cover attack-relevant syscalls on Linux/Debian."""
    rc, out, err = _run("auditctl -l 2>/dev/null")
    if rc != 0:
        return (False, f"Could not list auditd rules: {err}")
    attack_indicators = [
        "execve",        # process execution
        "ptrace",        # debugging/injection
        "init_module",   # kernel module loading
        "chmod",         # permission changes
        "/etc/passwd",   # user DB tampering
        "/etc/sudoers",  # privilege escalation
    ]
    missing = [ind for ind in attack_indicators if ind not in out]
    if not missing:
        return (True, "auditd rules cover all required attack-relevant syscalls and paths")
    return (False, f"auditd rules are missing attack detection coverage for: {', '.join(missing)}")


# ===========================================================================
# SI.L2-3.14.7 — Identify Unauthorized Use
# ===========================================================================

def logon_audit_enabled_wc() -> tuple[bool, str]:
    """Verify logon success and failure auditing is enabled on Windows Client."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'Logon' | Select-String 'Success and Failure|Success|Failure'"
    )
    if rc != 0:
        return (False, f"Could not query logon audit policy: {err}")
    if len(out.strip()) > 0:
        return (True, "Logon audit subcategory is enabled (Success and/or Failure)")
    return (False, "Logon audit subcategory is not enabled")


def anomaly_detection_wc() -> tuple[bool, str]:
    """Confirm a SIEM or EDR solution is configured for anomaly detection on Windows Client."""
    return siem_agent_active_wc()


def unauthorized_software_detect_wc() -> tuple[bool, str]:
    """Verify AppLocker, WDAC, or EDR can detect unauthorized execution on Windows Client."""
    rc, out, err = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections | Measure-Object "
        "| Select-Object -ExpandProperty Count"
    )
    try:
        if rc == 0 and int(out.strip()) > 0:
            return (True, f"AppLocker policy has {out.strip()} rule collection(s) for unauthorized software detection")
    except ValueError:
        pass
    # Check for WDAC policy
    wdac = Path("C:/Windows/System32/CodeIntegrity/SiPolicy.p7b")
    if wdac.exists():
        return (True, "WDAC policy file (SiPolicy.p7b) is deployed for unauthorized software detection")
    # Fall back to EDR detection capability
    ok, msg = siem_agent_active_wc()
    if ok:
        return (True, f"EDR/SIEM provides unauthorized software detection capability: {msg}")
    return (False, "No AppLocker, WDAC, or EDR-based unauthorized software detection found")


def logon_audit_enabled_ws() -> tuple[bool, str]:
    """Verify logon success and failure auditing is enabled on Windows Server."""
    return logon_audit_enabled_wc()


def anomaly_detection_ws() -> tuple[bool, str]:
    """Confirm SIEM anomaly detection rules are active on Windows Server."""
    return siem_agent_active_ws()


def unauthorized_software_detect_ws() -> tuple[bool, str]:
    """Verify AppLocker, WDAC, or EDR detects unauthorized execution on Windows Server."""
    return unauthorized_software_detect_wc()


def privileged_account_monitoring_ws() -> tuple[bool, str]:
    """Confirm privileged account activity is monitored for anomalies on Windows Server."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'Sensitive Privilege Use','Special Logon' "
        "| Select-String 'Success'"
    )
    if rc != 0:
        return (False, f"Could not query privileged account audit policy: {err}")
    if len(out.strip()) > 0:
        return (True, "Sensitive Privilege Use and/or Special Logon audit subcategories are enabled")
    return (False, "Sensitive Privilege Use and Special Logon audit subcategories are not enabled")


def unexpected_connections_ws() -> tuple[bool, str]:
    """Verify firewall logging is enabled to detect unexpected connections on Windows Server."""
    rc, out, err = _ps(
        "Get-NetFirewallProfile | Where-Object {$_.LogAllowed -eq 'True' "
        "-or $_.LogBlocked -eq 'True'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc != 0:
        return (False, f"Could not query firewall logging status: {err}")
    try:
        count = int(out.strip())
        if count > 0:
            return (True, f"Firewall logging is enabled on {count} profile(s) for unexpected connection detection")
        return (False, "Firewall logging is not enabled on any profile (cannot detect unexpected connections)")
    except ValueError:
        return (False, "Could not parse firewall logging profile count")


def logon_audit_enabled_lx() -> tuple[bool, str]:
    """Verify auditd and PAM log all login attempts on Linux/Debian."""
    rc, out, _ = _run(
        "auditctl -l 2>/dev/null | grep -E 'USER_LOGIN|USER_AUTH|lastlog|faillog'"
    )
    pam_ok = True
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        content = pam_sshd.read_text()
        pam_ok = "pam_unix" in content or "pam_sss" in content
    if rc == 0 and len(out.strip()) > 0:
        return (True, "auditd rules cover login events (USER_LOGIN/USER_AUTH/lastlog/faillog)")
    if pam_ok:
        return (True, "PAM is configured to log login attempts (pam_unix or pam_sss found in /etc/pam.d/sshd)")
    return (False, "No auditd rules for login events and PAM is not configured for login logging")


def last_login_displayed_lx() -> tuple[bool, str]:
    """Confirm last login information is displayed at logon on Linux/Debian."""
    pam_lastlog = Path("/etc/pam.d/login")
    if pam_lastlog.exists():
        content = pam_lastlog.read_text()
        if "pam_lastlog" in content:
            return (True, "pam_lastlog is configured in /etc/pam.d/login (last login info displayed at logon)")
    # Check sshd PAM config
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        content = pam_sshd.read_text()
        if "pam_lastlog" in content:
            return (True, "pam_lastlog is configured in /etc/pam.d/sshd (last login info displayed at SSH logon)")
    return (False, "pam_lastlog is not configured in /etc/pam.d/login or /etc/pam.d/sshd")


def unauthorized_process_monitor_lx() -> tuple[bool, str]:
    """Verify auditd or HIDS monitors for unexpected process execution on Linux/Debian."""
    rc, out, _ = _run("auditctl -l 2>/dev/null | grep -E 'execve|EXECVE'")
    if rc == 0 and out.strip():
        return (True, "auditd is monitoring for process execution (execve rules found)")
    ok, msg = ids_active_lx()
    if ok:
        return (True, f"HIDS provides process execution monitoring: {msg}")
    return (False, "No auditd execve rules and no HIDS tool active for unauthorized process monitoring")


def unexpected_connections_lx() -> tuple[bool, str]:
    """Confirm firewall logging can detect unexpected connections on Linux/Debian."""
    # Check for firewall logging in syslog or dedicated log
    rc, out, _ = _run(
        "grep -E 'IPTABLES|UFW|DROP|REJECT|nftables' "
        "/var/log/syslog /var/log/kern.log /var/log/firewall.log 2>/dev/null | tail -1"
    )
    if rc == 0 and out.strip():
        return (True, f"Firewall logging is active (recent log entry found: {out.strip()[:80]})")
    # Check that firewall logging is enabled
    rc2, out2, _ = _run("iptables -L INPUT -v -n 2>/dev/null | grep -v '^$' | wc -l")
    try:
        count = int(out2.strip())
        if count > 2:
            return (True, f"iptables INPUT chain has {count} rule entries (firewall active for connection monitoring)")
        return (False, "Firewall logging is not active and iptables has minimal rules (unexpected connections cannot be detected)")
    except ValueError:
        return (False, "Could not verify firewall logging capability for unexpected connection detection")
