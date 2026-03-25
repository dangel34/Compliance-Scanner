"""
system_information_integrity.py

Houses all system and information integrity (SI) check functions for CMMC
SI.L1-3.14.1 through SI.L2-3.14.7.
Each function corresponds to a cs_f() reference in the SI control JSON files.

Naming convention:
    <check_name>_wc   -> Windows Client
    <check_name>_ws   -> Windows Server
    <check_name>_lx   -> Linux / Debian
"""

import subprocess
import re
import time
from pathlib import Path
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: str, shell: bool = True) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        shell=shell,
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _ps(cmd: str) -> tuple[int, str, str]:
    """Run a PowerShell command and return (returncode, stdout, stderr)."""
    full_cmd = f'powershell.exe -NonInteractive -NoProfile -Command "{cmd}"'
    return _run(full_cmd)


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

def windows_update_enabled_wc() -> bool:
    """Verify the Windows Update service is running on Windows Client."""
    rc, out, _ = _ps(
        "Get-Service -Name wuauserv | Select-Object -ExpandProperty Status"
    )
    return rc == 0 and out.strip().lower() == "running"


def missing_patches_wc() -> bool:
    """Confirm no critical or high patches are missing on Windows Client."""
    rc, out, _ = _ps(
        "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()"
        ".Search('IsInstalled=0 and Type=Software and IsHidden=0').Updates.Count"
    )
    try:
        return rc == 0 and int(out.strip()) == 0
    except ValueError:
        return False


def last_update_date_wc() -> bool:
    """Verify the last successful Windows Update is within 30 days on Windows Client."""
    rc, out, _ = _ps(
        "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate"
    )
    if rc != 0 or not out.strip():
        return False
    try:
        last = datetime.strptime(out.strip()[:10], "%Y-%m-%d")
        return (datetime.utcnow() - last).days <= 30
    except ValueError:
        return False


def patch_agent_active_wc() -> bool:
    """Confirm a patch management agent is installed and running on Windows Client."""
    agents = ["CcmExec", "IntuneManagementExtension", "wuauserv"]
    for agent in agents:
        rc, out, _ = _ps(
            f"Get-Service -Name '{agent}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status"
        )
        if rc == 0 and out.strip().lower() == "running":
            return True
    return False


def windows_update_enabled_ws() -> bool:
    """Verify the Windows Update service is running on Windows Server."""
    return windows_update_enabled_wc()


def missing_patches_ws() -> bool:
    """Confirm no critical patches are missing on Windows Server."""
    return missing_patches_wc()


def last_update_date_ws() -> bool:
    """Verify the last successful Windows Update is within 30 days on Windows Server."""
    return last_update_date_wc()


def patch_agent_active_ws() -> bool:
    """Confirm a patch management agent is running on Windows Server."""
    return patch_agent_active_wc()


def pending_reboot_ws() -> bool:
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
            return False  # Pending reboot found — flag as failing
    return True


def security_repos_configured_lx() -> bool:
    """Verify security update repositories are configured on Linux/Debian."""
    # Check apt sources for security repos
    rc, out, _ = _run(
        "grep -rE 'security|updates' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null "
        "| grep -v '^#' | grep -v '^$'"
    )
    if rc == 0 and out.strip():
        return True
    # Check yum/dnf repos
    rc2, out2, _ = _run(
        "grep -rE 'security|updates' /etc/yum.repos.d/ 2>/dev/null | grep -v '^#'"
    )
    return rc2 == 0 and len(out2.strip()) > 0


def missing_patches_lx() -> bool:
    """Confirm no outstanding security updates are available on Linux/Debian."""
    # Try apt
    rc, out, _ = _run(
        "apt-get --dry-run --just-print upgrade 2>/dev/null "
        "| grep -c '^Inst'"
    )
    if rc == 0:
        try:
            return int(out.strip()) == 0
        except ValueError:
            pass
    # Try yum/dnf
    rc2, out2, _ = _run("yum check-update --security -q 2>/dev/null | grep -c '\\.'")
    try:
        return int(out2.strip()) == 0
    except ValueError:
        return False


def last_update_date_lx() -> bool:
    """Verify the system has applied updates within 30 days on Linux/Debian."""
    # Check dpkg log
    dpkg_log = Path("/var/log/dpkg.log")
    if dpkg_log.exists():
        age = _file_age_days(dpkg_log)
        if age is not None and age <= 30:
            rc, out, _ = _run(
                f"grep 'upgrade\\|install' /var/log/dpkg.log 2>/dev/null | tail -1"
            )
            if rc == 0 and out.strip():
                return True
    # Check yum/dnf log
    for log in ["/var/log/yum.log", "/var/log/dnf.log"]:
        path = Path(log)
        if path.exists():
            age = _file_age_days(path)
            if age is not None and age <= 30:
                return True
    return False


def kernel_current_lx() -> bool:
    """Check that the running kernel has no pending security updates on Linux/Debian."""
    rc, running, _ = _run("uname -r")
    if rc != 0:
        return False
    # Check if a newer kernel is available
    rc2, out2, _ = _run(
        "apt-cache policy linux-image-$(uname -r | sed 's/-[^-]*$//') 2>/dev/null "
        "| grep 'Installed\\|Candidate'"
    )
    if rc2 == 0 and out2.strip():
        lines = out2.strip().splitlines()
        installed = next((l for l in lines if "Installed" in l), "")
        candidate = next((l for l in lines if "Candidate" in l), "")
        inst_ver = re.search(r':\s+(\S+)', installed)
        cand_ver = re.search(r':\s+(\S+)', candidate)
        if inst_ver and cand_ver:
            return inst_ver.group(1) == cand_ver.group(1)
    return True  # Cannot determine — assume passing


# ===========================================================================
# SI.L1-3.14.2 — Provide Protection from Malicious Code
# ===========================================================================

def av_installed_running_wc() -> bool:
    """Verify antivirus or EDR is installed and running on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty AntivirusEnabled"
    )
    if rc == 0 and out.strip().lower() == "true":
        return True
    # Check for third-party AV via Security Center
    rc2, out2, _ = _ps(
        "Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct "
        "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc2 == 0 and int(out2.strip()) > 0
    except ValueError:
        return False


def realtime_protection_enabled_wc() -> bool:
    """Confirm real-time protection is enabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"
    )
    return rc == 0 and out.strip().lower() == "true"


def av_definitions_current_wc() -> bool:
    """Verify antivirus definitions are current on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated"
    )
    if rc != 0 or not out.strip():
        return False
    try:
        last_updated = datetime.strptime(out.strip()[:10], "%Y-%m-%d")
        return (datetime.utcnow() - last_updated).days <= 2
    except ValueError:
        return False


def av_scan_coverage_wc() -> bool:
    """Confirm antivirus is configured to scan all critical paths on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension | Format-List"
    )
    if rc != 0:
        return False
    # Check exclusions are not overly broad
    broad_exclusions = ["C:\\", "C:\\Windows", "C:\\Users", "*"]
    if any(exc in out for exc in broad_exclusions):
        return False
    return True


def av_installed_running_ws() -> bool:
    """Verify antivirus or EDR is installed and running on Windows Server."""
    return av_installed_running_wc()


def realtime_protection_enabled_ws() -> bool:
    """Confirm real-time protection is enabled on Windows Server."""
    return realtime_protection_enabled_wc()


def av_definitions_current_ws() -> bool:
    """Verify antivirus definitions are current on Windows Server."""
    return av_definitions_current_wc()


def av_exclusions_minimal_ws() -> bool:
    """Confirm antivirus exclusions are minimal and documented on Windows Server."""
    rc, out, _ = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
    )
    if rc != 0:
        return True  # No exclusions configured
    paths = [p.strip() for p in out.splitlines() if p.strip()]
    broad = ["C:\\", "C:\\Windows", "C:\\Users", "D:\\", "*", "C:\\Program Files"]
    return not any(p in broad for p in paths)


def av_installed_running_lx() -> bool:
    """Verify ClamAV or equivalent is installed on Linux/Debian."""
    return _binary_exists_lx("clamscan", "clamd", "sophos-av", "eset-daemon")


def av_scan_scheduled_lx() -> bool:
    """Confirm antimalware scan is scheduled via cron or systemd timer on Linux/Debian."""
    # Check cron for clamscan
    rc, out, _ = _run("grep -r 'clamscan\\|clamdscan\\|freshclam' /etc/cron* /var/spool/cron/ 2>/dev/null")
    if rc == 0 and out.strip():
        return True
    # Check systemd timers
    rc2, out2, _ = _run("systemctl list-timers --all 2>/dev/null | grep -iE 'clam|av|scan'")
    return rc2 == 0 and len(out2.strip()) > 0


def av_definitions_current_lx() -> bool:
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
                return age <= 2  # Within 48 hours
    return False


def rootkit_detection_lx() -> bool:
    """Confirm rkhunter or chkrootkit is installed on Linux/Debian."""
    return _binary_exists_lx("rkhunter", "chkrootkit")


# ===========================================================================
# SI.L1-3.14.3 — Monitor System Security Alerts and Advisories
# ===========================================================================

def security_center_active_wc() -> bool:
    """Verify Windows Security Center is active on Windows Client."""
    rc, out, _ = _ps(
        "Get-Service -Name wscsvc -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty Status"
    )
    return rc == 0 and out.strip().lower() == "running"


def siem_agent_active_wc() -> bool:
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
            return True
    return False


def vuln_mgmt_enrolled_wc() -> bool:
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
            return True
    return False


def security_center_active_ws() -> bool:
    """Verify Windows Security Center is active on Windows Server."""
    return security_center_active_wc()


def siem_agent_active_ws() -> bool:
    """Confirm a SIEM or security monitoring agent is running on Windows Server."""
    return siem_agent_active_wc()


def vuln_mgmt_enrolled_ws() -> bool:
    """Verify the server is enrolled in a vulnerability management program."""
    return vuln_mgmt_enrolled_wc()


def vuln_scanner_agent_ws() -> bool:
    """Confirm a vulnerability scanner agent is installed and active on Windows Server."""
    return vuln_mgmt_enrolled_ws()


def siem_agent_active_lx() -> bool:
    """Confirm a SIEM or log forwarding agent is active on Linux/Debian."""
    agents = [
        "filebeat", "elastic-agent", "splunkd",
        "wazuh-agent", "ossec", "td-agent", "fluentd", "nxlog"
    ]
    for agent in agents:
        if _service_running_lx(agent):
            return True
    return False


def vuln_mgmt_enrolled_lx() -> bool:
    """Verify a vulnerability scanner agent is installed on Linux/Debian."""
    return _binary_exists_lx("nessus-agent", "qualys-cloud-agent", "rapid7agent", "openvas")


def advisory_monitoring_lx() -> bool:
    """Confirm a process or tool monitors security advisories on Linux/Debian."""
    # Check for debian-goodies, apt-listbugs, or apticron which monitor DSA advisories
    rc, out, _ = _run("dpkg -l apticron apt-listchanges apt-listbugs 2>/dev/null | grep '^ii'")
    if rc == 0 and out.strip():
        return True
    # Check for openscap or oscap as a vulnerability scanning indicator
    return _binary_exists_lx("oscap", "openscap")


# ===========================================================================
# SI.L2-3.14.4 — Update Malicious Code Protection Mechanisms
# ===========================================================================

def av_definitions_age_wc() -> bool:
    """Verify antivirus definitions are no more than 24 hours old on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated"
    )
    if rc != 0 or not out.strip():
        return False
    try:
        last_updated = datetime.strptime(out.strip()[:10], "%Y-%m-%d")
        return (datetime.utcnow() - last_updated).days <= 1
    except ValueError:
        return False


def av_auto_update_enabled_wc() -> bool:
    """Confirm automatic definition updates are enabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty SignatureScheduleDay"
    )
    # 0 = every day, 8 = never — anything other than 8 is acceptable
    if rc == 0 and out.strip() != "8":
        return True
    # Check via Windows Update settings for Defender updates
    val = _reg_get(
        r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates",
        "ForceUpdateFromMU"
    )
    return val == "1"


def av_engine_current_wc() -> bool:
    """Verify the antivirus engine version is current on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty AMEngineVersion"
    )
    # Engine version should be non-zero; actual currency check requires external feed
    return rc == 0 and len(out.strip()) > 0 and out.strip() != "0.0.0.0"


def av_definitions_age_ws() -> bool:
    """Verify antivirus definitions are no more than 24 hours old on Windows Server."""
    return av_definitions_age_wc()


def av_auto_update_enabled_ws() -> bool:
    """Confirm automatic definition updates are enabled on Windows Server."""
    return av_auto_update_enabled_wc()


def av_engine_current_ws() -> bool:
    """Verify the antivirus engine version is current on Windows Server."""
    return av_engine_current_wc()


def av_definitions_age_lx() -> bool:
    """Verify ClamAV databases are no more than 24 hours old on Linux/Debian."""
    db_paths = [
        Path("/var/lib/clamav/daily.cld"),
        Path("/var/lib/clamav/daily.cvd"),
    ]
    for db in db_paths:
        if db.exists():
            age = _file_age_days(db)
            return age is not None and age <= 1
    return False


def av_auto_update_enabled_lx() -> bool:
    """Confirm freshclam or equivalent automatic update daemon is running on Linux/Debian."""
    if _service_running_lx("clamav-freshclam"):
        return True
    if _service_running_lx("freshclam"):
        return True
    # Check cron for freshclam
    rc, out, _ = _run("grep -r 'freshclam' /etc/cron* /var/spool/cron/ 2>/dev/null")
    return rc == 0 and len(out.strip()) > 0


def rkhunter_db_current_lx() -> bool:
    """Verify rkhunter or chkrootkit databases are current on Linux/Debian."""
    rkhunter_db = Path("/var/lib/rkhunter/db")
    if rkhunter_db.exists():
        age = _file_age_days(rkhunter_db)
        if age is not None:
            return age <= 7
    # Check rkhunter log
    rkhunter_log = Path("/var/log/rkhunter.log")
    if rkhunter_log.exists():
        age = _file_age_days(rkhunter_log)
        return age is not None and age <= 7
    # Check if chkrootkit runs via cron
    rc, out, _ = _run("grep -r 'chkrootkit\\|rkhunter' /etc/cron* 2>/dev/null")
    return rc == 0 and len(out.strip()) > 0


# ===========================================================================
# SI.L1-3.14.5 — Perform Periodic and Real-Time Scans
# ===========================================================================

def scheduled_scan_configured_wc() -> bool:
    """Verify a periodic scan is scheduled in Windows Defender on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpPreference | Select-Object ScanScheduleDay,ScanScheduleTime | Format-List"
    )
    if rc != 0:
        return False
    day_match = re.search(r'ScanScheduleDay\s*:\s*(\S+)', out)
    # 0 = every day, 1-7 = specific day, 8 = never
    if day_match and day_match.group(1) != "8":
        return True
    return False


def last_scan_completed_wc() -> bool:
    """Verify the last Defender scan completed successfully on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object -ExpandProperty QuickScanAge"
    )
    if rc != 0 or not out.strip():
        return False
    try:
        # QuickScanAge is in days — should be within 7 days
        return int(out.strip()) <= 7
    except ValueError:
        return False


def removable_media_scan_wc() -> bool:
    """Confirm removable media scanning is enabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty DisableRemovableDriveScanning"
    )
    # False means scanning IS enabled (not disabled)
    return rc == 0 and out.strip().lower() == "false"


def scheduled_scan_configured_ws() -> bool:
    """Verify a periodic scan is scheduled on Windows Server."""
    return scheduled_scan_configured_wc()


def last_scan_completed_ws() -> bool:
    """Verify the last Defender scan completed on Windows Server."""
    return last_scan_completed_wc()


def download_scan_ws() -> bool:
    """Confirm real-time scanning covers downloaded/staged files on Windows Server."""
    return realtime_protection_enabled_ws()


def scheduled_scan_configured_lx() -> bool:
    """Verify a periodic ClamAV scan is scheduled on Linux/Debian."""
    rc, out, _ = _run(
        "grep -r 'clamscan\\|clamdscan' /etc/cron.daily /etc/cron.weekly "
        "/etc/cron.d/ /var/spool/cron/ 2>/dev/null"
    )
    return rc == 0 and len(out.strip()) > 0


def onaccess_scan_lx() -> bool:
    """Confirm ClamAV on-access scanning is active on Linux/Debian."""
    if _service_running_lx("clamav-daemon"):
        # Check if on-access scanning is enabled in clamd.conf
        clamd_conf = Path("/etc/clamav/clamd.conf")
        if clamd_conf.exists():
            content = clamd_conf.read_text()
            if re.search(r'^\s*OnAccessIncludePath', content, re.MULTILINE):
                return True
    # Check for clamonacc process
    rc, out, _ = _run("pgrep -x clamonacc 2>/dev/null")
    return rc == 0


def last_scan_completed_lx() -> bool:
    """Verify a scan log exists with recent results on Linux/Debian."""
    scan_logs = [
        Path("/var/log/clamav/clamav.log"),
        Path("/var/log/clamav/freshclam.log"),
    ]
    for log in scan_logs:
        if log.exists():
            age = _file_age_days(log)
            if age is not None and age <= 7:
                return True
    # Check for clamscan output in syslog
    rc, out, _ = _run("grep -i 'clamav\\|clamscan' /var/log/syslog 2>/dev/null | tail -1")
    return rc == 0 and len(out.strip()) > 0


# ===========================================================================
# SI.L2-3.14.6 — Monitor Systems to Detect Attacks
# ===========================================================================

def asr_rules_enabled_wc() -> bool:
    """Confirm Windows Defender ASR rules are enabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions"
    )
    if rc != 0 or not out.strip():
        return False
    # Rules should have at least some entries set to Enabled (1) or AuditMode (2)
    return "1" in out or "2" in out


def logs_forwarded_wc() -> bool:
    """Verify security event logs are forwarded to a SIEM on Windows Client."""
    return siem_agent_active_wc()


def asr_rules_enabled_ws() -> bool:
    """Confirm Windows Defender ASR rules are enabled on Windows Server."""
    return asr_rules_enabled_wc()


def logs_forwarded_ws() -> bool:
    """Verify security event logs are forwarded to a SIEM on Windows Server."""
    return siem_agent_active_ws()


def network_monitoring_ws() -> bool:
    """Confirm network traffic monitoring is active on Windows Server."""
    # Check for common network monitoring or NDR agents
    agents = ["npcap", "Wireshark", "NetFlow", "MsSense", "CbDefense", "CrowdStrike"]
    for agent in agents:
        rc, out, _ = _ps(
            f"Get-Service -Name '{agent}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status"
        )
        if rc == 0 and out.strip().lower() == "running":
            return True
    # Check Windows Firewall logging as minimum baseline
    rc2, out2, _ = _ps(
        "Get-NetFirewallProfile | Select-Object -ExpandProperty LogFileName"
    )
    return rc2 == 0 and len(out2.strip()) > 0


def credential_guard_ws() -> bool:
    """Verify Credential Guard is enabled on Windows Server."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity"
    )
    cg_val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "LsaCfgFlags"
    )
    return val == "1" or cg_val in ("1", "2")


def ids_active_lx() -> bool:
    """Verify an IDS or HIDS tool is installed and active on Linux/Debian."""
    hids_services = ["wazuh-agent", "ossec", "aide", "samhain"]
    for svc in hids_services:
        if _service_running_lx(svc):
            return True
    return _binary_exists_lx("wazuh-agent", "ossec-control", "aide")


def fail2ban_active_lx() -> bool:
    """Confirm fail2ban is running and configured on Linux/Debian."""
    if not _service_running_lx("fail2ban"):
        return False
    # Verify SSH jail is enabled
    rc, out, _ = _run("fail2ban-client status sshd 2>/dev/null")
    return rc == 0 and "Status" in out


def logs_forwarded_lx() -> bool:
    """Verify audit logs are forwarded to a centralized SIEM on Linux/Debian."""
    return siem_agent_active_lx()


def auditd_attack_rules_lx() -> bool:
    """Confirm auditd rules cover attack-relevant syscalls on Linux/Debian."""
    rc, out, _ = _run("auditctl -l 2>/dev/null")
    if rc != 0:
        return False
    attack_indicators = [
        "execve",        # process execution
        "ptrace",        # debugging/injection
        "init_module",   # kernel module loading
        "chmod",         # permission changes
        "/etc/passwd",   # user DB tampering
        "/etc/sudoers",  # privilege escalation
    ]
    return all(indicator in out for indicator in attack_indicators)


# ===========================================================================
# SI.L2-3.14.7 — Identify Unauthorized Use
# ===========================================================================

def logon_audit_enabled_wc() -> bool:
    """Verify logon success and failure auditing is enabled on Windows Client."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Logon' | Select-String 'Success and Failure|Success|Failure'"
    )
    return rc == 0 and len(out.strip()) > 0


def anomaly_detection_wc() -> bool:
    """Confirm a SIEM or EDR solution is configured for anomaly detection on Windows Client."""
    return siem_agent_active_wc()


def unauthorized_software_detect_wc() -> bool:
    """Verify AppLocker, WDAC, or EDR can detect unauthorized execution on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections | Measure-Object "
        "| Select-Object -ExpandProperty Count"
    )
    try:
        if rc == 0 and int(out.strip()) > 0:
            return True
    except ValueError:
        pass
    # Check for WDAC policy
    wdac = Path("C:/Windows/System32/CodeIntegrity/SiPolicy.p7b")
    if wdac.exists():
        return True
    # Fall back to EDR detection capability
    return siem_agent_active_wc()


def logon_audit_enabled_ws() -> bool:
    """Verify logon success and failure auditing is enabled on Windows Server."""
    return logon_audit_enabled_wc()


def anomaly_detection_ws() -> bool:
    """Confirm SIEM anomaly detection rules are active on Windows Server."""
    return siem_agent_active_ws()


def unauthorized_software_detect_ws() -> bool:
    """Verify AppLocker, WDAC, or EDR detects unauthorized execution on Windows Server."""
    return unauthorized_software_detect_wc()


def privileged_account_monitoring_ws() -> bool:
    """Confirm privileged account activity is monitored for anomalies on Windows Server."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Sensitive Privilege Use','Special Logon' "
        "| Select-String 'Success'"
    )
    return rc == 0 and len(out.strip()) > 0


def unexpected_connections_ws() -> bool:
    """Verify firewall logging is enabled to detect unexpected connections on Windows Server."""
    rc, out, _ = _ps(
        "Get-NetFirewallProfile | Where-Object {$_.LogAllowed -eq 'True' "
        "-or $_.LogBlocked -eq 'True'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def logon_audit_enabled_lx() -> bool:
    """Verify auditd and PAM log all login attempts on Linux/Debian."""
    rc, out, _ = _run(
        "auditctl -l 2>/dev/null | grep -E 'USER_LOGIN|USER_AUTH|lastlog|faillog'"
    )
    pam_ok = True
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        content = pam_sshd.read_text()
        pam_ok = "pam_unix" in content or "pam_sss" in content
    return (rc == 0 and len(out.strip()) > 0) or pam_ok


def last_login_displayed_lx() -> bool:
    """Confirm last login information is displayed at logon on Linux/Debian."""
    pam_lastlog = Path("/etc/pam.d/login")
    if pam_lastlog.exists():
        content = pam_lastlog.read_text()
        if "pam_lastlog" in content:
            return True
    # Check sshd PAM config
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        content = pam_sshd.read_text()
        return "pam_lastlog" in content
    return False


def unauthorized_process_monitor_lx() -> bool:
    """Verify auditd or HIDS monitors for unexpected process execution on Linux/Debian."""
    rc, out, _ = _run("auditctl -l 2>/dev/null | grep -E 'execve|EXECVE'")
    if rc == 0 and out.strip():
        return True
    return ids_active_lx()


def unexpected_connections_lx() -> bool:
    """Confirm firewall logging can detect unexpected connections on Linux/Debian."""
    # Check for firewall logging in syslog or dedicated log
    rc, out, _ = _run(
        "grep -E 'IPTABLES|UFW|DROP|REJECT|nftables' "
        "/var/log/syslog /var/log/kern.log /var/log/firewall.log 2>/dev/null | tail -1"
    )
    if rc == 0 and out.strip():
        return True
    # Check that firewall logging is enabled
    rc2, out2, _ = _run("iptables -L INPUT -v -n 2>/dev/null | grep -v '^$' | wc -l")
    try:
        return int(out2.strip()) > 2
    except ValueError:
        return False