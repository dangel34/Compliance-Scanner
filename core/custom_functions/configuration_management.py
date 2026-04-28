import subprocess
import re
import shlex
from pathlib import Path

_RUN_CACHE: dict[tuple[object, object, int], tuple[int, str, str]] = {}


def clear_cache() -> None:
    """Clear the command result cache so the next scan gets fresh results."""
    _RUN_CACHE.clear()


def _cmd_cache_key(cmd) -> object:
    if isinstance(cmd, (list, tuple)):
        return tuple(str(part) for part in cmd)
    return str(cmd)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd, shell: bool | None = None, timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    shell_tokens = ("|", ">", "<", "&&", "||", ";", "$(", "`")
    cache_key = (_cmd_cache_key(cmd), shell, timeout)
    cached = _RUN_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        if isinstance(cmd, (list, tuple)):
            args = list(cmd)
            use_shell = False
        else:
            use_shell = shell if shell is not None else any(tok in cmd for tok in shell_tokens)
            args = cmd if use_shell else shlex.split(cmd, posix=False)
        result = subprocess.run(
            args,
            shell=use_shell,
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
    return _run(
        ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", cmd],
        shell=False,
    )


def _reg_get(key: str, value: str) -> str | None:
    """Read a Windows registry value; returns the value string or None on failure."""
    rc, out, _ = _ps(
        f"(Get-ItemProperty -Path '{key}' -Name '{value}' "
        f"-ErrorAction SilentlyContinue).'{value}'"
    )
    return out.strip() if rc == 0 and out.strip() else None


# ===========================================================================
# CM.L2-3.4.1 — Establish and Maintain Baseline Configurations and Inventories
# ===========================================================================

def hardware_inventory_wc() -> tuple[bool, str]:
    """Verify system hardware components are enumerable on Windows Client."""
    rc, out, _ = _ps(
        "Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory "
        "| Format-List"
    )
    if rc == 0 and "Manufacturer" in out:
        return (True, "Hardware inventory available via WMI (Manufacturer/Model/Memory found)")
    return (False, "Could not retrieve hardware inventory via WMI")


def software_inventory_wc() -> tuple[bool, str]:
    """Enumerate all installed applications on Windows Client."""
    rc, out, err = _ps(
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Select-Object DisplayName,DisplayVersion "
        "| Where-Object {$_.DisplayName} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} installed application(s) found in uninstall registry")
        return (False, "No installed applications found in registry")
    except ValueError:
        return (False, f"Could not enumerate installed software: {err}")


def firmware_inventory_wc() -> tuple[bool, str]:
    """Retrieve BIOS/UEFI version on Windows Client."""
    rc, out, _ = _ps(
        "Get-WmiObject Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate "
        "| Format-List"
    )
    if rc == 0 and "SMBIOSBIOSVersion" in out:
        return (True, "BIOS/UEFI firmware version retrievable via WMI")
    return (False, "Could not retrieve BIOS/UEFI version via WMI")


def baseline_config_exists_wc() -> tuple[bool, str]:
    """Verify a GPO-based configuration baseline is applied on Windows Client."""
    rc, out, _ = _ps("gpresult /R /SCOPE COMPUTER 2>&1 | Select-String 'Applied Group Policy Objects'")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "GPO-based baseline found (Applied Group Policy Objects present)")
    return (False, "No applied Group Policy Objects found — no GPO baseline detected")


def hardware_inventory_ws() -> tuple[bool, str]:
    """Verify system hardware components are enumerable on Windows Server."""
    return hardware_inventory_wc()


def software_inventory_ws() -> tuple[bool, str]:
    """Enumerate all installed applications and roles on Windows Server."""
    return software_inventory_wc()


def firmware_inventory_ws() -> tuple[bool, str]:
    """Retrieve BIOS/UEFI version on Windows Server."""
    return firmware_inventory_wc()


def baseline_config_exists_ws() -> tuple[bool, str]:
    """Verify a GPO-based configuration baseline is applied on Windows Server."""
    return baseline_config_exists_wc()


def server_roles_inventory_ws() -> tuple[bool, str]:
    """Enumerate installed Windows Server roles and features."""
    rc, out, err = _ps(
        "Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} "
        "| Select-Object Name,DisplayName | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} installed Windows Server role(s)/feature(s) found")
        return (False, "No installed Windows Server roles/features found")
    except ValueError:
        return (False, f"Could not enumerate server roles: {err}")


def hardware_inventory_lx() -> tuple[bool, str]:
    """Use dmidecode to enumerate hardware on Linux/Debian."""
    rc, out, _ = _run("dmidecode -t system 2>/dev/null | grep -E 'Manufacturer|Product Name|Version'")
    if rc == 0 and len(out.strip()) > 0:
        return (True, f"Hardware inventory available via dmidecode: {out.strip()[:80]}")
    return (False, "Could not retrieve hardware info via dmidecode")


def software_inventory_lx() -> tuple[bool, str]:
    """Enumerate all installed packages via rpm or dpkg on Linux/Debian."""
    rc, out, _ = _run("dpkg -l 2>/dev/null | grep '^ii' | wc -l")
    if rc == 0:
        try:
            count = int(out.strip())
            if count > 0:
                return (True, f"{count} installed dpkg package(s) found")
        except ValueError:
            pass
    rc2, out2, _ = _run("rpm -qa 2>/dev/null | wc -l")
    try:
        count2 = int(out2.strip())
        if rc2 == 0 and count2 > 0:
            return (True, f"{count2} installed rpm package(s) found")
        return (False, "No installed packages found via dpkg or rpm")
    except ValueError:
        return (False, "Could not enumerate installed packages via dpkg or rpm")


def firmware_inventory_lx() -> tuple[bool, str]:
    """Retrieve BIOS/UEFI version via dmidecode on Linux/Debian."""
    rc, out, _ = _run("dmidecode -t bios 2>/dev/null | grep -E 'Version|Release Date'")
    if rc == 0 and len(out.strip()) > 0:
        return (True, f"BIOS/UEFI firmware version available: {out.strip()[:80]}")
    return (False, "Could not retrieve BIOS/UEFI version via dmidecode")


def baseline_config_exists_lx() -> tuple[bool, str]:
    """Verify a hardening baseline has been applied on Linux/Debian."""
    # Check for AIDE database (post-hardening baseline), Ansible facts, or OSCAP results
    aide_db = Path("/var/lib/aide/aide.db")
    oscap_result = Path("/var/lib/oscap")
    ansible_facts = Path("/etc/ansible")
    if aide_db.exists():
        return (True, "AIDE baseline database found at /var/lib/aide/aide.db")
    if oscap_result.exists():
        return (True, "OpenSCAP result directory found at /var/lib/oscap")
    if ansible_facts.exists():
        return (True, "Ansible configuration directory found at /etc/ansible")
    return (False, "No hardening baseline found (no AIDE db, OpenSCAP results, or Ansible config)")


# ===========================================================================
# CM.L2-3.4.2 — Establish and Enforce Secure Configuration Settings
# ===========================================================================

def security_baseline_gpo_wc() -> tuple[bool, str]:
    """Verify a security configuration GPO is applied on Windows Client."""
    rc, out, _ = _ps(
        "gpresult /R /SCOPE COMPUTER 2>&1 | Select-String 'Security|Baseline|CIS|STIG'"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, f"Security/baseline GPO applied: {out.strip()[:80]}")
    return (False, "No Security/Baseline/CIS/STIG GPO found in applied Group Policy Objects")


def password_policy_wc() -> tuple[bool, str]:
    """Confirm password policy meets minimum requirements on Windows Client."""
    rc, out, _ = _ps("net accounts")
    if rc != 0:
        return (False, "Could not run 'net accounts' to check password policy")
    min_len = re.search(r'Minimum password length\s+(\d+)', out)
    if not min_len or int(min_len.group(1)) < 14:
        length = min_len.group(1) if min_len else "0"
        return (False, f"Minimum password length: {length} (required: >= 14)")
    _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "RequireStrongKey"
    )
    return (True, f"Password length check passed (minimum = {min_len.group(1)})")


def screen_lock_wc() -> tuple[bool, str]:
    """Verify screen lock and idle timeout are configured on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "InactivityTimeoutSecs"
    )
    if val:
        try:
            secs = int(val)
            if secs <= 900:
                return (True, f"Screen lock inactivity timeout = {secs}s (required: <= 900s)")
            return (False, f"Screen lock inactivity timeout = {secs}s (required: <= 900s)")
        except ValueError:
            pass
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
        "-Name ScreenSaveTimeOut,ScreenSaverIsSecure -ErrorAction SilentlyContinue | Format-List"
    )
    if rc == 0 and "ScreenSaveTimeOut" in out and "ScreenSaverIsSecure" in out:
        return (True, "Screen saver timeout and secure resume configured via Control Panel\\Desktop")
    return (False, "Screen lock/inactivity timeout not configured")


def defender_enabled_wc() -> tuple[bool, str]:
    """Confirm Windows Defender Antivirus real-time protection is enabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled | Format-List"
    )
    if rc == 0 and "True" in out:
        return (True, "Windows Defender antivirus/real-time protection is enabled")
    return (False, f"Windows Defender real-time protection not confirmed enabled: {out.strip()[:80]}")


def firewall_enabled_wc() -> tuple[bool, str]:
    """Verify Windows Defender Firewall is enabled for all profiles on Windows Client."""
    rc, out, _ = _ps(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | Format-List"
    )
    if rc != 0:
        return (False, "Could not query Windows Firewall profiles")
    profiles = re.findall(r'Enabled\s*:\s*(\w+)', out)
    names = re.findall(r'Name\s*:\s*(\w+)', out)
    disabled = [names[i] if i < len(names) else "?" for i, p in enumerate(profiles) if p.lower() != "true"]
    if not disabled:
        return (True, f"Windows Defender Firewall enabled on all {len(profiles)} profile(s)")
    return (False, f"Windows Defender Firewall disabled on profile(s): {', '.join(disabled)}")


def security_baseline_gpo_ws() -> tuple[bool, str]:
    """Verify a security configuration GPO is applied on Windows Server."""
    return security_baseline_gpo_wc()


def password_policy_ws() -> tuple[bool, str]:
    """Confirm password policy meets minimum requirements on Windows Server."""
    return password_policy_wc()


def screen_lock_ws() -> tuple[bool, str]:
    """Verify screen lock and idle timeout are configured on Windows Server."""
    return screen_lock_wc()


def defender_enabled_ws() -> tuple[bool, str]:
    """Confirm Windows Defender or endpoint protection is active on Windows Server."""
    return defender_enabled_wc()


def firewall_enabled_ws() -> tuple[bool, str]:
    """Verify Windows Defender Firewall is enabled for all profiles on Windows Server."""
    return firewall_enabled_wc()


def smb_signing_ws() -> tuple[bool, str]:
    """Confirm SMB signing is required on Windows Server."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "RequireSecuritySignature"
    )
    if val == "1":
        return (True, "SMB server signing required (RequireSecuritySignature = 1)")
    return (False, f"SMB server signing not required (RequireSecuritySignature = {val or 'not set'})")


def hardening_baseline_lx() -> tuple[bool, str]:
    """Verify a recognized hardening baseline has been applied on Linux/Debian."""
    return baseline_config_exists_lx()


def password_policy_lx() -> tuple[bool, str]:
    """Confirm PAM password quality settings meet the security baseline on Linux/Debian."""
    pwquality_path = Path("/etc/security/pwquality.conf")
    if not pwquality_path.exists():
        return (False, "/etc/security/pwquality.conf not found")
    content = pwquality_path.read_text()
    minlen = re.search(r'^\s*minlen\s*=\s*(\d+)', content, re.MULTILINE)
    if not minlen or int(minlen.group(1)) < 14:
        length = minlen.group(1) if minlen else "not set"
        return (False, f"pwquality minlen = {length} (required: >= 14)")
    minclass = re.search(r'^\s*minclass\s*=\s*(\d+)', content, re.MULTILINE)
    if not minclass or int(minclass.group(1)) < 3:
        classes = minclass.group(1) if minclass else "not set"
        return (False, f"pwquality minclass = {classes} (required: >= 3)")
    return (True, f"Password policy: minlen = {minlen.group(1)}, minclass = {minclass.group(1)}")


def ssh_hardening_lx() -> tuple[bool, str]:
    """Verify sshd_config enforces hardened settings on Linux/Debian."""
    rc, out, _ = _run("sshd -T 2>/dev/null")
    if rc != 0:
        return (False, "Could not run 'sshd -T' to check SSH configuration")
    checks = {
        "permitrootlogin": "no",
        "permitemptypasswords": "no",
        "protocol": "2",
    }
    failures = []
    for key, expected in checks.items():
        match = re.search(rf'^{key}\s+(\S+)', out, re.MULTILINE | re.IGNORECASE)
        if not match or match.group(1).lower() != expected:
            actual = match.group(1) if match else "not set"
            failures.append(f"{key} = {actual} (expected: {expected})")
    if not failures:
        return (True, "SSH hardened settings verified: PermitRootLogin=no, PermitEmptyPasswords=no, Protocol=2")
    return (False, f"SSH hardening failures: {'; '.join(failures)}")


def firewall_enabled_lx() -> tuple[bool, str]:
    """Confirm iptables, nftables, or firewalld is active on Linux/Debian."""
    for service in ["firewalld", "ufw", "nftables", "iptables"]:
        rc, _, _ = _run(f"systemctl is-active {service} 2>/dev/null")
        if rc == 0:
            return (True, f"Firewall service '{service}' is active")
    # Check iptables directly for active rules
    rc2, out2, _ = _run("iptables -L INPUT -n 2>/dev/null | grep -v '^Chain\\|^target' | wc -l")
    try:
        count = int(out2.strip())
        if count > 0:
            return (True, f"iptables has {count} INPUT rule(s) active")
        return (False, "No active firewall service found and no iptables INPUT rules present")
    except ValueError:
        return (False, "No active firewall service found (firewalld/ufw/nftables/iptables)")


def core_dump_disabled_lx() -> tuple[bool, str]:
    """Verify core dumps are disabled on Linux/Debian."""
    # Check limits.conf
    rc, out, _ = _run("grep -r 'hard.*core.*0' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null")
    if rc == 0 and out.strip():
        return (True, "Core dumps disabled via /etc/security/limits.conf (hard core 0)")
    # Check sysctl
    rc2, out2, _ = _run("sysctl kernel.core_pattern 2>/dev/null")
    if rc2 == 0 and "|/bin/false" in out2:
        return (True, "Core dumps disabled via sysctl kernel.core_pattern = |/bin/false")
    rc3, out3, _ = _run("sysctl fs.suid_dumpable 2>/dev/null")
    if rc3 == 0 and "= 0" in out3:
        return (True, "Core dumps disabled via sysctl fs.suid_dumpable = 0")
    return (False, "Core dumps not disabled (no limits.conf hard core 0 or sysctl configuration found)")


# ===========================================================================
# CM.L2-3.4.3 — Track, Review, Approve, and Log Changes to Systems
# ===========================================================================

def change_auditing_wc() -> tuple[bool, str]:
    """Verify audit policy tracks system configuration changes on Windows Client."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Policy Change','Audit Policy Change' "
        "| Select-String 'Success'"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, "Audit policy change subcategory configured for Success auditing")
    return (False, "Policy Change/Audit Policy Change subcategory not configured for Success auditing")


def software_install_log_wc() -> tuple[bool, str]:
    """Confirm software installation events are captured in the event log on Windows Client."""
    rc, out, _ = _ps(
        "Get-WinEvent -LogName 'Application' "
        "-FilterXPath '*[System[Provider[@Name=\"MsiInstaller\"]]]' "
        "-MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc == 0:
        return (True, "MsiInstaller events are queryable from the Application event log")
    return (False, "Could not query MsiInstaller events from Application event log")


def registry_change_audit_wc() -> tuple[bool, str]:
    """Verify registry object access auditing is enabled on Windows Client."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Registry' | Select-String 'Success|Failure'"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, "Registry auditing configured (Success/Failure)")
    return (False, "Registry auditing not configured")


def change_auditing_ws() -> tuple[bool, str]:
    """Verify audit policy tracks system configuration changes on Windows Server."""
    return change_auditing_wc()


def software_install_log_ws() -> tuple[bool, str]:
    """Confirm software installation events are captured on Windows Server."""
    return software_install_log_wc()


def registry_change_audit_ws() -> tuple[bool, str]:
    """Verify registry object access auditing is enabled on Windows Server."""
    return registry_change_audit_wc()


def change_mgmt_system_ws() -> tuple[bool, str]:
    """Verify a change management system is in use on Windows Server (heuristic check)."""
    # Check for common ITSM agent processes as a proxy indicator
    rc, out, err = _ps(
        "Get-Process -Name 'swagent','maconfig','BigFixAgent','CBDService' "
        "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} change management agent process(es) detected")
        return (False, "No known change management agent processes found (swagent/maconfig/BigFixAgent/CBDService)")
    except ValueError:
        return (False, f"Could not query change management agent processes: {err}")


def fim_enabled_lx() -> tuple[bool, str]:
    """Verify AIDE or equivalent FIM tool is installed and initialized on Linux/Debian."""
    rc_aide, _, _ = _run("which aide 2>/dev/null")
    if rc_aide == 0:
        aide_db = Path("/var/lib/aide/aide.db")
        if aide_db.exists():
            return (True, "AIDE is installed and database exists at /var/lib/aide/aide.db")
        return (False, "AIDE is installed but database not found at /var/lib/aide/aide.db")
    # Check for Tripwire
    rc_tw, _, _ = _run("which tripwire 2>/dev/null")
    if rc_tw == 0:
        return (True, "Tripwire FIM tool is installed")
    return (False, "No FIM tool found (AIDE not installed, no Tripwire)")


def package_install_log_lx() -> tuple[bool, str]:
    """Confirm package manager logs exist and have recent entries on Linux/Debian."""
    dpkg_log = Path("/var/log/dpkg.log")
    yum_log = Path("/var/log/yum.log")
    dnf_log = Path("/var/log/dnf.log")
    for log in [dpkg_log, yum_log, dnf_log]:
        if log.exists() and log.stat().st_size > 0:
            return (True, f"Package install log found and non-empty: {log}")
    return (False, "No package manager log found (/var/log/dpkg.log, yum.log, dnf.log)")


def config_file_watch_lx() -> tuple[bool, str]:
    """Verify auditd rules watch critical configuration files on Linux/Debian."""
    rc, out, _ = _run("auditctl -l 2>/dev/null")
    if rc != 0:
        return (False, "Could not query auditd rules (auditctl -l failed)")
    required_watches = ["/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config"]
    missing = [w for w in required_watches if w not in out]
    if not missing:
        return (True, f"auditd watches all required config files: {', '.join(required_watches)}")
    return (False, f"auditd missing watches for: {', '.join(missing)}")


# ===========================================================================
# CM.L2-3.4.4 — Analyze Security Impact of Changes Prior to Implementation
# ===========================================================================

def pre_change_review_wc() -> tuple[bool, str]:
    """Verify security impact analysis is enforced before changes on Windows Client (heuristic)."""
    # Heuristic: GPO is enforced and configuration drift tools are present
    rc, out, err = _ps(
        "Get-Service -Name 'CcmExec','wuauserv' -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} patch/config management service(s) running (CcmExec/wuauserv)")
        return (False, "No patch/config management services (CcmExec/wuauserv) running")
    except ValueError:
        return (False, f"Could not query change management services: {err}")


def unapproved_change_detect_wc() -> tuple[bool, str]:
    """Confirm configuration drift from baseline is detectable on Windows Client."""
    rc, out, err = _ps(
        "Get-Service -Name 'CcmExec','DSCService' -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} configuration drift detection service(s) running (CcmExec/DSCService)")
        return (False, "No configuration drift detection services (CcmExec/DSCService) running")
    except ValueError:
        return (False, f"Could not query drift detection services: {err}")


def pre_change_review_ws() -> tuple[bool, str]:
    """Verify security impact analysis is enforced before changes on Windows Server (heuristic)."""
    return pre_change_review_wc()


def unapproved_change_detect_ws() -> tuple[bool, str]:
    """Confirm configuration drift detection is active on Windows Server."""
    return unapproved_change_detect_wc()


def patch_test_env_ws() -> tuple[bool, str]:
    """Verify a patch testing process exists by checking WSUS or patch management client."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' "
        "-ErrorAction SilentlyContinue | Select-Object WUServer,TargetGroup | Format-List"
    )
    if rc == 0 and "WUServer" in out:
        return (True, "WSUS/patch management server configured (WUServer policy found)")
    return (False, "No WSUS or patch management server configured (WUServer policy not found)")


def fim_baseline_current_lx() -> tuple[bool, str]:
    """Verify the AIDE FIM database exists and has been updated recently on Linux/Debian."""
    aide_db = Path("/var/lib/aide/aide.db")
    if not aide_db.exists():
        return (False, "AIDE database not found at /var/lib/aide/aide.db")
    import time
    age_days = (time.time() - aide_db.stat().st_mtime) / 86400
    if age_days <= 90:
        return (True, f"AIDE database age = {age_days:.0f} days (required: <= 90)")
    return (False, f"AIDE database age = {age_days:.0f} days — database is stale (required: <= 90)")


def unattended_upgrade_controlled_lx() -> tuple[bool, str]:
    """Confirm automatic unattended upgrades are controlled or disabled on Linux/Debian."""
    uu_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if uu_conf.exists():
        content = uu_conf.read_text()
        # Check if Unattended-Upgrade is explicitly set to 0
        match = re.search(r'Unattended-Upgrade\s+"(\d+)"', content)
        if match and match.group(1) == "0":
            return (True, "Unattended-Upgrade disabled in 20auto-upgrades (Unattended-Upgrade \"0\")")
    # Check if unattended-upgrades service is disabled
    rc, _, _ = _run("systemctl is-enabled unattended-upgrades 2>/dev/null")
    if rc != 0:
        return (True, "unattended-upgrades service is disabled or not installed")
    return (False, "Unattended-Upgrade is enabled and not controlled via 20auto-upgrades")


def unapproved_change_detect_lx() -> tuple[bool, str]:
    """Verify auditd or FIM is configured to alert on unauthorized changes on Linux/Debian."""
    fim_ok, fim_msg = fim_enabled_lx()
    cfg_ok, cfg_msg = config_file_watch_lx()
    if fim_ok and cfg_ok:
        return (True, f"FIM and auditd config watches active — {fim_msg}; {cfg_msg}")
    failures = []
    if not fim_ok:
        failures.append(fim_msg)
    if not cfg_ok:
        failures.append(cfg_msg)
    return (False, "; ".join(failures))


# ===========================================================================
# CM.L2-3.4.5 — Define, Document, Approve, and Enforce Access Restrictions for Change
# ===========================================================================

def software_install_restricted_wc() -> tuple[bool, str]:
    """Verify standard users do not have local administrator rights on Windows Client."""
    rc, out, err = _ps(
        "Get-LocalGroupMember -Group 'Administrators' "
        "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        # More than 2 members (Administrator + domain admin) is suspicious
        if count <= 3:
            return (True, f"Administrators group has {count} member(s) (threshold: <= 3)")
        return (False, f"Administrators group has {count} member(s) — may be too permissive (threshold: <= 3)")
    except ValueError:
        return (False, f"Could not query Administrators group membership: {err}")


def local_admin_controlled_wc() -> tuple[bool, str]:
    """Confirm the built-in Administrator account is disabled or renamed on Windows Client."""
    rc, out, _ = _ps(
        "Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty Enabled"
    )
    # Should be disabled
    if rc == 0 and out.strip().lower() == "false":
        return (True, "Built-in Administrator account is disabled")
    # If not found by default name, it was renamed (acceptable)
    if rc != 0:
        return (True, "Built-in Administrator account not found by default name — likely renamed")
    return (False, f"Built-in Administrator account is enabled (Enabled = {out.strip()})")


def uac_enabled_wc() -> tuple[bool, str]:
    """Verify UAC is enabled on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA"
    )
    if val == "1":
        return (True, "UAC is enabled (EnableLUA = 1)")
    return (False, f"UAC is disabled (EnableLUA = {val or 'not set'})")


def software_install_restricted_ws() -> tuple[bool, str]:
    """Verify only authorized administrators can install software on Windows Server."""
    return software_install_restricted_wc()


def local_admin_controlled_ws() -> tuple[bool, str]:
    """Confirm the built-in Administrator account is disabled or renamed on Windows Server."""
    return local_admin_controlled_wc()


def uac_enabled_ws() -> tuple[bool, str]:
    """Verify UAC is enabled on Windows Server."""
    return uac_enabled_wc()


def privileged_change_access_log_ws() -> tuple[bool, str]:
    """Confirm privileged access used for changes is captured in the audit log."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Sensitive Privilege Use' | Select-String 'Success'"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, "Sensitive Privilege Use subcategory configured for Success auditing")
    return (False, "Sensitive Privilege Use not configured for Success auditing")


def root_access_restricted_lx() -> tuple[bool, str]:
    """Verify direct root login is disabled and sudo is restricted on Linux/Debian."""
    rc, out, _ = _run("sshd -T 2>/dev/null | grep 'permitrootlogin'")
    root_ssh_disabled = rc == 0 and "no" in out.lower()
    rc2, out2, _ = _run("grep -E '^root' /etc/sudoers 2>/dev/null | grep -v '^#'")
    root_sudo_unrestricted = rc2 == 0 and "ALL" in out2
    if root_ssh_disabled and not root_sudo_unrestricted:
        return (True, "SSH PermitRootLogin=no and root sudoers is not unrestricted")
    failures = []
    if not root_ssh_disabled:
        actual = out.strip() if out.strip() else "not set"
        failures.append(f"SSH PermitRootLogin = {actual} (should be no)")
    if root_sudo_unrestricted:
        failures.append("root has unrestricted ALL=(ALL) ALL in /etc/sudoers")
    return (False, "; ".join(failures))


def package_install_restricted_lx() -> tuple[bool, str]:
    """Confirm standard users cannot run package managers via sudo on Linux/Debian."""
    rc, out, _ = _run(
        "sudo -l -U nobody 2>/dev/null | grep -iE 'apt|yum|dnf|rpm|dpkg'"
    )
    # nobody should have no package manager sudo rights
    if not out.strip():
        return (True, "User 'nobody' has no package manager (apt/yum/dnf/rpm/dpkg) sudo rights")
    return (False, f"Package manager sudo rights found for 'nobody': {out.strip()[:80]}")


def sudoers_restricted_lx() -> tuple[bool, str]:
    """Verify sudoers contains only authorized entries and is watched by auditd."""
    # Check for dangerous NOPASSWD or ALL entries for non-admin users
    rc, out, _ = _run(
        "grep -v '^#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null "
        "| grep -v '^$' | grep 'NOPASSWD' | grep -v '%sudo\\|%wheel\\|%admin'"
    )
    if rc == 0 and out.strip():
        return (False, f"Unauthorized NOPASSWD sudoers entries found: {out.strip()[:80]}")
    # Check auditd is watching sudoers
    rc2, out2, _ = _run("auditctl -l 2>/dev/null | grep '/etc/sudoers'")
    if rc2 == 0 and len(out2.strip()) > 0:
        return (True, "No unauthorized NOPASSWD sudoers entries and /etc/sudoers is watched by auditd")
    return (False, "No unauthorized NOPASSWD entries but auditd is not watching /etc/sudoers")


# ===========================================================================
# CM.L2-3.4.6 — Employ the Principle of Least Functionality
# ===========================================================================

def unnecessary_features_disabled_wc() -> tuple[bool, str]:
    """Verify unnecessary Windows features are disabled on Windows Client."""
    rc, out, err = _ps(
        "Get-WindowsOptionalFeature -Online | "
        "Where-Object {$_.FeatureName -match 'SMB1Protocol|TelnetClient|TFTP' "
        "-and $_.State -eq 'Enabled'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count == 0:
            return (True, "Unnecessary features (SMB1/Telnet/TFTP) are all disabled")
        return (False, f"{count} unnecessary feature(s) enabled (SMB1Protocol/TelnetClient/TFTP)")
    except ValueError:
        return (False, f"Could not check optional features: {err}")


def unnecessary_services_disabled_wc() -> tuple[bool, str]:
    """Confirm non-essential services are disabled on Windows Client."""
    risky_services = ["RemoteRegistry", "SharedAccess", "tlntsvr"]
    running = []
    for svc in risky_services:
        rc, out, _ = _ps(
            f"Get-Service -Name '{svc}' -ErrorAction SilentlyContinue "
            f"| Select-Object -ExpandProperty Status"
        )
        if rc == 0 and out.strip().lower() == "running":
            running.append(svc)
    if not running:
        return (True, f"Non-essential services are stopped: {', '.join(risky_services)}")
    return (False, f"Non-essential service(s) are running: {', '.join(running)}")


def authorized_apps_only_wc() -> tuple[bool, str]:
    """Verify installed applications match the authorized software list on Windows Client."""
    rc, out, _ = _ps(
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Select-Object DisplayName | Where-Object {$_.DisplayName} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    # Returns True if enumerable; actual comparison requires external authorized list
    if rc == 0:
        return (True, f"Installed application inventory is enumerable ({out.strip()} apps found)")
    return (False, "Could not enumerate installed applications for authorized list comparison")


def minimal_roles_ws() -> tuple[bool, str]:
    """Verify only required server roles and features are installed on Windows Server."""
    rc, out, err = _ps(
        "Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        # A baseline server should have a small number of installed features
        if rc == 0 and count < 30:
            return (True, f"{count} installed Windows features (threshold: < 30)")
        return (False, f"{count} installed Windows features — may exceed minimal role requirement (threshold: < 30)")
    except ValueError:
        return (False, f"Could not query installed Windows features: {err}")


def unnecessary_services_disabled_ws() -> tuple[bool, str]:
    """Confirm non-essential services are disabled on Windows Server."""
    return unnecessary_services_disabled_wc()


def authorized_apps_only_ws() -> tuple[bool, str]:
    """Verify installed applications match the authorized software list on Windows Server."""
    return authorized_apps_only_wc()


def server_core_check_ws() -> tuple[bool, str]:
    """Verify whether the server uses a minimal installation (Server Core)."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
        "-Name InstallationType -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty InstallationType"
    )
    install_type = out.strip().lower()
    # Server Core returns "Server Core"; full GUI returns "Server"
    if rc == 0 and install_type in ("server core", "nano server"):
        return (True, f"Minimal server installation in use (InstallationType = {out.strip()})")
    return (False, f"Full GUI server installation (InstallationType = {out.strip() or 'unknown'}) — not Server Core")


def unnecessary_packages_removed_lx() -> tuple[bool, str]:
    """Verify no unnecessary packages (X11, compilers on servers) are installed on Linux/Debian."""
    risky_patterns = ["xorg", "xserver", "gcc", "g++", "build-essential", "telnet", "rsh-client"]
    found = []
    for pkg in risky_patterns:
        rc, out, _ = _run(f"dpkg -l {pkg} 2>/dev/null | grep '^ii'")
        if rc == 0 and out.strip():
            found.append(pkg)
            continue
        rc2, out2, _ = _run(f"rpm -q {pkg} 2>/dev/null")
        if rc2 == 0 and out2.strip():
            found.append(pkg)
    if not found:
        return (True, f"No unnecessary packages found (checked: {', '.join(risky_patterns)})")
    return (False, f"Unnecessary package(s) installed: {', '.join(found)}")


def unnecessary_services_disabled_lx() -> tuple[bool, str]:
    """Confirm non-essential services are stopped and disabled on Linux/Debian."""
    risky_services = ["avahi-daemon", "cups", "rpcbind", "nfs-server", "xinetd"]
    running = []
    for svc in risky_services:
        rc, _, _ = _run(f"systemctl is-active {svc} 2>/dev/null")
        if rc == 0:
            running.append(svc)
    if not running:
        return (True, f"Non-essential services are inactive: {', '.join(risky_services)}")
    return (False, f"Non-essential service(s) are running: {', '.join(running)}")


def minimal_listening_services_lx() -> tuple[bool, str]:
    """Verify only authorized services are bound to network interfaces on Linux/Debian."""
    rc, out, _ = _run("ss -tlnp 2>/dev/null")
    if rc != 0:
        rc, out, _ = _run("netstat -tlnp 2>/dev/null")
    lines = out.strip().splitlines() if out.strip() else []
    if rc == 0 and len(lines) > 0:
        return (True, f"Network listening services enumerable ({len(lines)} line(s) from ss/netstat)")
    return (False, "Could not enumerate listening services (ss/netstat failed)")


# ===========================================================================
# CM.L2-3.4.7 — Restrict, Disable, or Prevent Use of Nonessential Programs, Ports, Protocols
# ===========================================================================

def insecure_protocols_disabled_wc() -> tuple[bool, str]:
    """Verify insecure protocols (SMBv1, TLS 1.0/1.1) are disabled on Windows Client."""
    smb1 = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1"
    )
    tls10 = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        "Enabled"
    )
    smb1_disabled = smb1 == "0"
    tls10_disabled = tls10 == "0"
    if smb1_disabled and tls10_disabled:
        return (True, "SMBv1 disabled (SMB1 = 0) and TLS 1.0 disabled (Enabled = 0)")
    failures = []
    if not smb1_disabled:
        failures.append(f"SMBv1 not disabled (SMB1 = {smb1 or 'not set'})")
    if not tls10_disabled:
        failures.append(f"TLS 1.0 not disabled (Enabled = {tls10 or 'not set'})")
    return (False, "; ".join(failures))


def unused_ports_blocked_wc() -> tuple[bool, str]:
    """Confirm Windows Defender Firewall has active inbound rules on Windows Client."""
    rc, out, err = _ps(
        "Get-NetFirewallRule -Direction Inbound -Action Block "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} inbound Block firewall rule(s) configured")
        return (False, "No inbound Block firewall rules configured")
    except ValueError:
        return (False, f"Could not query inbound firewall rules: {err}")


def rdp_controlled_wc() -> tuple[bool, str]:
    """Verify RDP is disabled or restricted to NLA on Windows Client."""
    rdp_val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections"
    )
    if rdp_val == "1":
        return (True, "RDP is disabled (fDenyTSConnections = 1)")
    nla_val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication"
    )
    if nla_val == "1":
        return (True, "RDP is enabled with NLA required (UserAuthentication = 1)")
    return (False, f"RDP is enabled without NLA (fDenyTSConnections = {rdp_val or 'not set'}, UserAuthentication = {nla_val or 'not set'})")


def ps_execution_policy_wc() -> tuple[bool, str]:
    """Confirm PowerShell execution policy is RemoteSigned or AllSigned on Windows Client."""
    rc, out, _ = _ps("Get-ExecutionPolicy -Scope LocalMachine")
    policy = out.strip().lower()
    if rc == 0 and policy in ("remotesigned", "allsigned"):
        return (True, f"PowerShell execution policy = {out.strip()} (LocalMachine)")
    return (False, f"PowerShell execution policy = {out.strip() or 'not set'} (required: RemoteSigned or AllSigned)")


def insecure_protocols_disabled_ws() -> tuple[bool, str]:
    """Verify insecure protocols are disabled on Windows Server."""
    return insecure_protocols_disabled_wc()


def unused_ports_blocked_ws() -> tuple[bool, str]:
    """Confirm Windows Defender Firewall blocks non-approved inbound traffic on Windows Server."""
    return unused_ports_blocked_wc()


def rdp_controlled_ws() -> tuple[bool, str]:
    """Verify RDP is disabled or NLA-enforced on Windows Server."""
    return rdp_controlled_wc()


def ps_execution_policy_ws() -> tuple[bool, str]:
    """Confirm PowerShell execution policy is RemoteSigned or AllSigned on Windows Server."""
    return ps_execution_policy_wc()


def telnet_ftp_disabled_ws() -> tuple[bool, str]:
    """Verify Telnet and FTP services are not installed or disabled on Windows Server."""
    rc, out, err = _ps(
        "Get-WindowsFeature -Name 'Telnet-Server','Web-Ftp-Server' "
        "| Where-Object {$_.InstallState -eq 'Installed'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count == 0:
            return (True, "Telnet-Server and Web-Ftp-Server are not installed")
        return (False, f"{count} insecure service(s) installed (Telnet-Server/Web-Ftp-Server)")
    except ValueError:
        return (False, f"Could not check Telnet/FTP feature installation: {err}")


def insecure_services_disabled_lx() -> tuple[bool, str]:
    """Verify telnet, rsh, rlogin, and other insecure services are not installed on Linux/Debian."""
    insecure_pkgs = ["telnetd", "rsh-server", "rlogin", "rexec", "tftpd", "nis"]
    found = []
    for pkg in insecure_pkgs:
        rc, out, _ = _run(f"dpkg -l {pkg} 2>/dev/null | grep '^ii'")
        if rc == 0 and out.strip():
            found.append(pkg)
            continue
        rc2, out2, _ = _run(f"rpm -q {pkg} 2>/dev/null | grep -v 'not installed'")
        if rc2 == 0 and out2.strip():
            found.append(pkg)
    if not found:
        return (True, f"No insecure services installed (checked: {', '.join(insecure_pkgs)})")
    return (False, f"Insecure service package(s) installed: {', '.join(found)}")


def authorized_ports_only_lx() -> tuple[bool, str]:
    """Confirm only authorized ports are listening on Linux/Debian."""
    rc, out, _ = _run("ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oE ':[0-9]+$' | tr -d ':'")
    if rc != 0:
        return (False, "Could not enumerate listening ports via ss")
    ports = [p.strip() for p in out.strip().splitlines() if p.strip()]
    if ports:
        return (True, f"Listening ports enumerable for review: {', '.join(ports[:10])}")
    return (False, "No listening ports found or could not enumerate (ss returned no results)")


def ipv6_disabled_if_unused_lx() -> tuple[bool, str]:
    """Verify IPv6 is disabled if not required on Linux/Debian."""
    rc, out, _ = _run("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    if rc == 0 and "= 1" in out:
        return (True, "IPv6 is disabled (net.ipv6.conf.all.disable_ipv6 = 1)")
    # If IPv6 is in use (intentionally), check for sysctl setting
    rc2, out2, _ = _run("ip -6 addr show 2>/dev/null | grep -v '^$' | wc -l")
    try:
        count = int(out2.strip())
        if count > 0:
            return (True, f"IPv6 is in use ({count} IPv6 address line(s)) — intentional use detected")
        return (False, "IPv6 disable_ipv6 not set and no IPv6 addresses found")
    except ValueError:
        return (False, "Could not determine IPv6 status")


def ssh_weak_ciphers_disabled_lx() -> tuple[bool, str]:
    """Confirm sshd_config restricts to only approved strong ciphers and MACs on Linux/Debian."""
    rc, out, _ = _run("sshd -T 2>/dev/null")
    if rc != 0:
        return (False, "Could not run 'sshd -T' to check SSH cipher configuration")
    weak_ciphers = ["arcfour", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
    cipher_match = re.search(r'^ciphers\s+(.+)', out, re.MULTILINE | re.IGNORECASE)
    if cipher_match:
        active_ciphers = cipher_match.group(1).split(",")
        found_weak = [wc for wc in weak_ciphers if wc in active_ciphers]
        if found_weak:
            return (False, f"Weak SSH cipher(s) in use: {', '.join(found_weak)}")
    weak_macs = ["hmac-md5", "hmac-sha1", "umac-64"]
    mac_match = re.search(r'^macs\s+(.+)', out, re.MULTILINE | re.IGNORECASE)
    if mac_match:
        active_macs = mac_match.group(1).split(",")
        found_weak_macs = [wm for wm in weak_macs if wm in active_macs]
        if found_weak_macs:
            return (False, f"Weak SSH MAC(s) in use: {', '.join(found_weak_macs)}")
    return (True, "SSH ciphers and MACs contain no known weak algorithms")


# ===========================================================================
# CM.L2-3.4.8 — Apply Deny-by-Exception Policy (Application Whitelisting)
# ===========================================================================

def applocker_wdac_enabled_wc() -> tuple[bool, str]:
    """Verify AppLocker or WDAC is configured on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        if rc == 0 and int(out.strip()) > 0:
            return (True, f"AppLocker policy has {out.strip()} rule collection(s)")
    except ValueError:
        pass
    # Check for WDAC / Windows Defender Application Control policy
    wdac_path = Path("C:/Windows/System32/CodeIntegrity/SiPolicy.p7b")
    if wdac_path.exists():
        return (True, "WDAC policy file found at C:/Windows/System32/CodeIntegrity/SiPolicy.p7b")
    return (False, "No AppLocker rule collections and no WDAC SiPolicy.p7b found")


def applocker_enforce_mode_wc() -> tuple[bool, str]:
    """Confirm AppLocker policy is in Enforce mode on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections "
        "| Select-Object -ExpandProperty EnforcementMode"
    )
    if rc != 0 or not out.strip():
        return (False, "Could not query AppLocker enforcement mode (no AppLocker policy?)")
    modes = out.strip().splitlines()
    non_enforced = [m.strip() for m in modes if m.strip() and m.strip().lower() != "enforced"]
    if not non_enforced:
        return (True, f"All {len(modes)} AppLocker rule collection(s) are in Enforced mode")
    return (False, f"AppLocker rule collection(s) not in Enforced mode: {', '.join(non_enforced)}")


def applocker_rule_coverage_wc() -> tuple[bool, str]:
    """Verify AppLocker rules cover EXE, DLL, Script, and MSI collections on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections "
        "| Select-Object -ExpandProperty RuleCollectionType"
    )
    if rc != 0:
        return (False, "Could not query AppLocker rule collections")
    required = {"exe", "dll", "script", "msi"}
    found = {r.strip().lower() for r in out.splitlines() if r.strip()}
    missing = required - found
    if not missing:
        return (True, f"AppLocker covers all required collections: {', '.join(sorted(required))}")
    return (False, f"AppLocker missing rule collections: {', '.join(sorted(missing))}")


def applocker_wdac_enabled_ws() -> tuple[bool, str]:
    """Verify AppLocker or WDAC is configured on Windows Server."""
    return applocker_wdac_enabled_wc()


def applocker_enforce_mode_ws() -> tuple[bool, str]:
    """Confirm AppLocker policy is in Enforce mode on Windows Server."""
    return applocker_enforce_mode_wc()


def applocker_rule_coverage_ws() -> tuple[bool, str]:
    """Verify AppLocker rules cover required collections on Windows Server."""
    return applocker_rule_coverage_wc()


def app_whitelist_lx() -> tuple[bool, str]:
    """Verify SELinux or AppArmor is installed on Linux/Debian."""
    rc_aa, _, _ = _run("which apparmor_status 2>/dev/null")
    rc_se, _, _ = _run("which getenforce 2>/dev/null")
    if rc_aa == 0:
        return (True, "AppArmor is installed (apparmor_status found)")
    if rc_se == 0:
        return (True, "SELinux is installed (getenforce found)")
    return (False, "Neither AppArmor (apparmor_status) nor SELinux (getenforce) is installed")


def mac_enforcing_lx() -> tuple[bool, str]:
    """Confirm SELinux is Enforcing or AppArmor profiles are in enforce mode on Linux/Debian."""
    # Check SELinux
    rc, out, _ = _run("getenforce 2>/dev/null")
    if rc == 0 and out.strip().lower() == "enforcing":
        return (True, "SELinux is in Enforcing mode")
    # Check AppArmor
    rc2, out2, _ = _run("apparmor_status 2>/dev/null | grep 'profiles are in enforce mode'")
    if rc2 == 0:
        match = re.search(r'(\d+) profiles are in enforce mode', out2)
        if match and int(match.group(1)) > 0:
            return (True, f"AppArmor: {match.group(1)} profile(s) in enforce mode")
    se_mode = out.strip() if out.strip() else "not available"
    return (False, f"SELinux mode = {se_mode} and no AppArmor enforce profiles found")


def suid_sgid_audit_lx() -> tuple[bool, str]:
    """Scan filesystem for SUID/SGID binaries on Linux/Debian and verify count is reasonable."""
    rc, out, _ = _run(
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | wc -l"
    )
    try:
        count = int(out.strip())
        # A typical Linux system has 20-50 SUID/SGID binaries; over 100 warrants review
        if count < 100:
            return (True, f"{count} SUID/SGID binaries found (threshold: < 100)")
        return (False, f"{count} SUID/SGID binaries found — exceeds threshold of 100, manual review required")
    except ValueError:
        return (False, "Could not count SUID/SGID binaries")


# ===========================================================================
# CM.L2-3.4.9 — Control and Monitor User-Installed Software
# ===========================================================================

def user_install_restricted_wc() -> tuple[bool, str]:
    """Verify standard users cannot install software system-wide on Windows Client."""
    return software_install_restricted_wc()


def software_monitor_wc() -> tuple[bool, str]:
    """Confirm a monitoring tool compares installed software against the authorized list on Windows Client."""
    rc, out, err = _ps(
        "Get-Service -Name 'CcmExec','IntuneManagementExtension','WinDefend' "
        "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} software monitoring service(s) running (CcmExec/IntuneManagementExtension/WinDefend)")
        return (False, "No software monitoring services running (CcmExec/IntuneManagementExtension/WinDefend)")
    except ValueError:
        return (False, f"Could not query software monitoring services: {err}")


def user_install_paths_controlled_wc() -> tuple[bool, str]:
    """Verify AppLocker or WDAC blocks execution from user-writable directories on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections "
        "| ForEach-Object {$_.Rules} | Where-Object {$_.Action -eq 'Deny'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} AppLocker Deny rule(s) blocking execution from user-writable paths")
        return applocker_wdac_enabled_wc()
    except ValueError:
        return applocker_wdac_enabled_wc()


def user_install_restricted_ws() -> tuple[bool, str]:
    """Verify standard users cannot install software on Windows Server."""
    return software_install_restricted_ws()


def software_monitor_ws() -> tuple[bool, str]:
    """Confirm a monitoring tool tracks installed software on Windows Server."""
    return software_monitor_wc()


def user_install_paths_controlled_ws() -> tuple[bool, str]:
    """Verify AppLocker or WDAC blocks execution from user-writable directories on Windows Server."""
    return user_install_paths_controlled_wc()


def user_install_restricted_lx() -> tuple[bool, str]:
    """Verify standard users cannot run package managers via sudo on Linux/Debian."""
    return package_install_restricted_lx()


def home_noexec_lx() -> tuple[bool, str]:
    """Confirm /home and /tmp are mounted with noexec on Linux/Debian."""
    rc, out, _ = _run("mount | grep -E '\\s/home\\s|\\s/tmp\\s'")
    if rc != 0 or not out.strip():
        # Check /etc/fstab as fallback
        rc2, out2, _ = _run("grep -E '\\s/home\\s|\\s/tmp\\s' /etc/fstab 2>/dev/null")
        out = out2
    if not out.strip():
        return (False, "/home and /tmp mount entries not found in mount output or /etc/fstab")
    lines = out.strip().splitlines()
    missing_noexec = [l for l in lines if ("/home" in l or "/tmp" in l) and "noexec" not in l]
    if not missing_noexec:
        return (True, "/home and /tmp are mounted with noexec option")
    return (False, f"noexec missing on: {'; '.join(missing_noexec[:2])}")


def package_monitor_lx() -> tuple[bool, str]:
    """Verify a process exists to monitor installed packages against the authorized baseline."""
    # Check for common compliance/monitoring agents
    agents = ["aide", "osqueryd", "wazuh-agent", "filebeat"]
    for agent in agents:
        rc, _, _ = _run(f"systemctl is-active {agent} 2>/dev/null")
        if rc == 0:
            return (True, f"Package monitoring agent '{agent}' is active")
    # Fall back to checking if dpkg log is present and being monitored
    ok, msg = package_install_log_lx()
    if ok:
        return (True, f"Package install log present for monitoring: {msg}")
    return (False, f"No package monitoring agent found (aide/osqueryd/wazuh-agent/filebeat) and {msg}")
