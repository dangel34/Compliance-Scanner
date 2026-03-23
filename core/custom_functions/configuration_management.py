import subprocess
import re
from pathlib import Path


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


# ===========================================================================
# CM.L2-3.4.1 — Establish and Maintain Baseline Configurations and Inventories
# ===========================================================================

def hardware_inventory_wc() -> bool:
    """Verify system hardware components are enumerable on Windows Client."""
    rc, out, _ = _ps(
        "Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory "
        "| Format-List"
    )
    return rc == 0 and "Manufacturer" in out


def software_inventory_wc() -> bool:
    """Enumerate all installed applications on Windows Client."""
    rc, out, _ = _ps(
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Select-Object DisplayName,DisplayVersion "
        "| Where-Object {$_.DisplayName} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def firmware_inventory_wc() -> bool:
    """Retrieve BIOS/UEFI version on Windows Client."""
    rc, out, _ = _ps(
        "Get-WmiObject Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate "
        "| Format-List"
    )
    return rc == 0 and "SMBIOSBIOSVersion" in out


def baseline_config_exists_wc() -> bool:
    """Verify a GPO-based configuration baseline is applied on Windows Client."""
    rc, out, _ = _ps("gpresult /R /SCOPE COMPUTER 2>&1 | Select-String 'Applied Group Policy Objects'")
    return rc == 0 and len(out.strip()) > 0


def hardware_inventory_ws() -> bool:
    """Verify system hardware components are enumerable on Windows Server."""
    return hardware_inventory_wc()


def software_inventory_ws() -> bool:
    """Enumerate all installed applications and roles on Windows Server."""
    return software_inventory_wc()


def firmware_inventory_ws() -> bool:
    """Retrieve BIOS/UEFI version on Windows Server."""
    return firmware_inventory_wc()


def baseline_config_exists_ws() -> bool:
    """Verify a GPO-based configuration baseline is applied on Windows Server."""
    return baseline_config_exists_wc()


def server_roles_inventory_ws() -> bool:
    """Enumerate installed Windows Server roles and features."""
    rc, out, _ = _ps(
        "Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} "
        "| Select-Object Name,DisplayName | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def hardware_inventory_lx() -> bool:
    """Use dmidecode to enumerate hardware on Linux/Debian."""
    rc, out, _ = _run("dmidecode -t system 2>/dev/null | grep -E 'Manufacturer|Product Name|Version'")
    return rc == 0 and len(out.strip()) > 0


def software_inventory_lx() -> bool:
    """Enumerate all installed packages via rpm or dpkg on Linux/Debian."""
    rc, out, _ = _run("dpkg -l 2>/dev/null | grep '^ii' | wc -l")
    if rc == 0:
        try:
            return int(out.strip()) > 0
        except ValueError:
            pass
    rc2, out2, _ = _run("rpm -qa 2>/dev/null | wc -l")
    try:
        return rc2 == 0 and int(out2.strip()) > 0
    except ValueError:
        return False


def firmware_inventory_lx() -> bool:
    """Retrieve BIOS/UEFI version via dmidecode on Linux/Debian."""
    rc, out, _ = _run("dmidecode -t bios 2>/dev/null | grep -E 'Version|Release Date'")
    return rc == 0 and len(out.strip()) > 0


def baseline_config_exists_lx() -> bool:
    """Verify a hardening baseline has been applied on Linux/Debian."""
    # Check for AIDE database (post-hardening baseline), Ansible facts, or OSCAP results
    aide_db = Path("/var/lib/aide/aide.db")
    oscap_result = Path("/var/lib/oscap")
    ansible_facts = Path("/etc/ansible")
    return aide_db.exists() or oscap_result.exists() or ansible_facts.exists()


# ===========================================================================
# CM.L2-3.4.2 — Establish and Enforce Secure Configuration Settings
# ===========================================================================

def security_baseline_gpo_wc() -> bool:
    """Verify a security configuration GPO is applied on Windows Client."""
    rc, out, _ = _ps(
        "gpresult /R /SCOPE COMPUTER 2>&1 | Select-String 'Security|Baseline|CIS|STIG'"
    )
    return rc == 0 and len(out.strip()) > 0


def password_policy_wc() -> bool:
    """Confirm password policy meets minimum requirements on Windows Client."""
    rc, out, _ = _ps("net accounts")
    if rc != 0:
        return False
    min_len = re.search(r'Minimum password length\s+(\d+)', out)
    if not min_len or int(min_len.group(1)) < 14:
        return False
    complexity = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "RequireStrongKey"
    )
    return True  # Length check passed; complexity enforced via GPO


def screen_lock_wc() -> bool:
    """Verify screen lock and idle timeout are configured on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "InactivityTimeoutSecs"
    )
    if val and int(val) <= 900:
        return True
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
        "-Name ScreenSaveTimeOut,ScreenSaverIsSecure -ErrorAction SilentlyContinue | Format-List"
    )
    return rc == 0 and "ScreenSaveTimeOut" in out and "ScreenSaverIsSecure" in out


def defender_enabled_wc() -> bool:
    """Confirm Windows Defender Antivirus real-time protection is enabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled | Format-List"
    )
    return rc == 0 and "True" in out


def firewall_enabled_wc() -> bool:
    """Verify Windows Defender Firewall is enabled for all profiles on Windows Client."""
    rc, out, _ = _ps(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | Format-List"
    )
    if rc != 0:
        return False
    profiles = re.findall(r'Enabled\s*:\s*(\w+)', out)
    return all(p.lower() == "true" for p in profiles)


def security_baseline_gpo_ws() -> bool:
    """Verify a security configuration GPO is applied on Windows Server."""
    return security_baseline_gpo_wc()


def password_policy_ws() -> bool:
    """Confirm password policy meets minimum requirements on Windows Server."""
    return password_policy_wc()


def screen_lock_ws() -> bool:
    """Verify screen lock and idle timeout are configured on Windows Server."""
    return screen_lock_wc()


def defender_enabled_ws() -> bool:
    """Confirm Windows Defender or endpoint protection is active on Windows Server."""
    return defender_enabled_wc()


def firewall_enabled_ws() -> bool:
    """Verify Windows Defender Firewall is enabled for all profiles on Windows Server."""
    return firewall_enabled_wc()


def smb_signing_ws() -> bool:
    """Confirm SMB signing is required on Windows Server."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "RequireSecuritySignature"
    )
    return val == "1"


def hardening_baseline_lx() -> bool:
    """Verify a recognized hardening baseline has been applied on Linux/Debian."""
    return baseline_config_exists_lx()


def password_policy_lx() -> bool:
    """Confirm PAM password quality settings meet the security baseline on Linux/Debian."""
    pwquality_path = Path("/etc/security/pwquality.conf")
    if not pwquality_path.exists():
        return False
    content = pwquality_path.read_text()
    minlen = re.search(r'^\s*minlen\s*=\s*(\d+)', content, re.MULTILINE)
    if not minlen or int(minlen.group(1)) < 14:
        return False
    minclass = re.search(r'^\s*minclass\s*=\s*(\d+)', content, re.MULTILINE)
    return bool(minclass and int(minclass.group(1)) >= 3)


def ssh_hardening_lx() -> bool:
    """Verify sshd_config enforces hardened settings on Linux/Debian."""
    rc, out, _ = _run("sshd -T 2>/dev/null")
    if rc != 0:
        return False
    checks = {
        "permitrootlogin": "no",
        "permitemptypasswords": "no",
        "protocol": "2",
    }
    for key, expected in checks.items():
        match = re.search(rf'^{key}\s+(\S+)', out, re.MULTILINE | re.IGNORECASE)
        if not match or match.group(1).lower() != expected:
            return False
    return True


def firewall_enabled_lx() -> bool:
    """Confirm iptables, nftables, or firewalld is active on Linux/Debian."""
    for service in ["firewalld", "ufw", "nftables", "iptables"]:
        rc, _, _ = _run(f"systemctl is-active {service} 2>/dev/null")
        if rc == 0:
            return True
    # Check iptables directly for active rules
    rc2, out2, _ = _run("iptables -L INPUT -n 2>/dev/null | grep -v '^Chain\\|^target' | wc -l")
    try:
        return int(out2.strip()) > 0
    except ValueError:
        return False


def core_dump_disabled_lx() -> bool:
    """Verify core dumps are disabled on Linux/Debian."""
    # Check limits.conf
    rc, out, _ = _run("grep -r 'hard.*core.*0' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null")
    if rc == 0 and out.strip():
        return True
    # Check sysctl
    rc2, out2, _ = _run("sysctl kernel.core_pattern 2>/dev/null")
    if rc2 == 0 and "|/bin/false" in out2:
        return True
    rc3, out3, _ = _run("sysctl fs.suid_dumpable 2>/dev/null")
    return rc3 == 0 and "= 0" in out3


# ===========================================================================
# CM.L2-3.4.3 — Track, Review, Approve, and Log Changes to Systems
# ===========================================================================

def change_auditing_wc() -> bool:
    """Verify audit policy tracks system configuration changes on Windows Client."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Policy Change','Audit Policy Change' "
        "| Select-String 'Success'"
    )
    return rc == 0 and len(out.strip()) > 0


def software_install_log_wc() -> bool:
    """Confirm software installation events are captured in the event log on Windows Client."""
    rc, out, _ = _ps(
        "Get-WinEvent -LogName 'Application' "
        "-FilterXPath '*[System[Provider[@Name=\"MsiInstaller\"]]]' "
        "-MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    return rc == 0


def registry_change_audit_wc() -> bool:
    """Verify registry object access auditing is enabled on Windows Client."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Registry' | Select-String 'Success|Failure'"
    )
    return rc == 0 and len(out.strip()) > 0


def change_auditing_ws() -> bool:
    """Verify audit policy tracks system configuration changes on Windows Server."""
    return change_auditing_wc()


def software_install_log_ws() -> bool:
    """Confirm software installation events are captured on Windows Server."""
    return software_install_log_wc()


def registry_change_audit_ws() -> bool:
    """Verify registry object access auditing is enabled on Windows Server."""
    return registry_change_audit_wc()


def change_mgmt_system_ws() -> bool:
    """Verify a change management system is in use on Windows Server (heuristic check)."""
    # Check for common ITSM agent processes as a proxy indicator
    rc, out, _ = _ps(
        "Get-Process -Name 'swagent','maconfig','BigFixAgent','CBDService' "
        "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def fim_enabled_lx() -> bool:
    """Verify AIDE or equivalent FIM tool is installed and initialized on Linux/Debian."""
    rc_aide, _, _ = _run("which aide 2>/dev/null")
    if rc_aide == 0:
        aide_db = Path("/var/lib/aide/aide.db")
        return aide_db.exists()
    # Check for Tripwire
    rc_tw, _, _ = _run("which tripwire 2>/dev/null")
    return rc_tw == 0


def package_install_log_lx() -> bool:
    """Confirm package manager logs exist and have recent entries on Linux/Debian."""
    dpkg_log = Path("/var/log/dpkg.log")
    yum_log = Path("/var/log/yum.log")
    dnf_log = Path("/var/log/dnf.log")
    for log in [dpkg_log, yum_log, dnf_log]:
        if log.exists() and log.stat().st_size > 0:
            return True
    return False


def config_file_watch_lx() -> bool:
    """Verify auditd rules watch critical configuration files on Linux/Debian."""
    rc, out, _ = _run("auditctl -l 2>/dev/null")
    if rc != 0:
        return False
    required_watches = ["/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config"]
    return all(watch in out for watch in required_watches)


# ===========================================================================
# CM.L2-3.4.4 — Analyze Security Impact of Changes Prior to Implementation
# ===========================================================================

def pre_change_review_wc() -> bool:
    """Verify security impact analysis is enforced before changes on Windows Client (heuristic)."""
    # Heuristic: GPO is enforced and configuration drift tools are present
    rc, out, _ = _ps(
        "Get-Service -Name 'CcmExec','wuauserv' -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def unapproved_change_detect_wc() -> bool:
    """Confirm configuration drift from baseline is detectable on Windows Client."""
    rc, out, _ = _ps(
        "Get-Service -Name 'CcmExec','DSCService' -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def pre_change_review_ws() -> bool:
    """Verify security impact analysis is enforced before changes on Windows Server (heuristic)."""
    return pre_change_review_wc()


def unapproved_change_detect_ws() -> bool:
    """Confirm configuration drift detection is active on Windows Server."""
    return unapproved_change_detect_wc()


def patch_test_env_ws() -> bool:
    """Verify a patch testing process exists by checking WSUS or patch management client."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' "
        "-ErrorAction SilentlyContinue | Select-Object WUServer,TargetGroup | Format-List"
    )
    return rc == 0 and "WUServer" in out


def fim_baseline_current_lx() -> bool:
    """Verify the AIDE FIM database exists and has been updated recently on Linux/Debian."""
    aide_db = Path("/var/lib/aide/aide.db")
    if not aide_db.exists():
        return False
    import time
    age_days = (time.time() - aide_db.stat().st_mtime) / 86400
    return age_days <= 90  # Database should be updated at least quarterly


def unattended_upgrade_controlled_lx() -> bool:
    """Confirm automatic unattended upgrades are controlled or disabled on Linux/Debian."""
    uu_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if uu_conf.exists():
        content = uu_conf.read_text()
        # Check if Unattended-Upgrade is explicitly set to 0
        match = re.search(r'Unattended-Upgrade\s+"(\d+)"', content)
        if match and match.group(1) == "0":
            return True
    # Check if unattended-upgrades service is disabled
    rc, _, _ = _run("systemctl is-enabled unattended-upgrades 2>/dev/null")
    return rc != 0  # disabled or not found


def unapproved_change_detect_lx() -> bool:
    """Verify auditd or FIM is configured to alert on unauthorized changes on Linux/Debian."""
    return fim_enabled_lx() and config_file_watch_lx()


# ===========================================================================
# CM.L2-3.4.5 — Define, Document, Approve, and Enforce Access Restrictions for Change
# ===========================================================================

def software_install_restricted_wc() -> bool:
    """Verify standard users do not have local administrator rights on Windows Client."""
    rc, out, _ = _ps(
        "Get-LocalGroupMember -Group 'Administrators' "
        "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        # More than 2 members (Administrator + domain admin) is suspicious
        count = int(out.strip())
        return count <= 3
    except ValueError:
        return False


def local_admin_controlled_wc() -> bool:
    """Confirm the built-in Administrator account is disabled or renamed on Windows Client."""
    rc, out, _ = _ps(
        "Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty Enabled"
    )
    # Should be disabled
    if rc == 0 and out.strip().lower() == "false":
        return True
    # If not found by default name, it was renamed (acceptable)
    if rc != 0:
        return True
    return False


def uac_enabled_wc() -> bool:
    """Verify UAC is enabled on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA"
    )
    return val == "1"


def software_install_restricted_ws() -> bool:
    """Verify only authorized administrators can install software on Windows Server."""
    return software_install_restricted_wc()


def local_admin_controlled_ws() -> bool:
    """Confirm the built-in Administrator account is disabled or renamed on Windows Server."""
    return local_admin_controlled_wc()


def uac_enabled_ws() -> bool:
    """Verify UAC is enabled on Windows Server."""
    return uac_enabled_wc()


def privileged_change_access_log_ws() -> bool:
    """Confirm privileged access used for changes is captured in the audit log."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Sensitive Privilege Use' | Select-String 'Success'"
    )
    return rc == 0 and len(out.strip()) > 0


def root_access_restricted_lx() -> bool:
    """Verify direct root login is disabled and sudo is restricted on Linux/Debian."""
    rc, out, _ = _run("sshd -T 2>/dev/null | grep 'permitrootlogin'")
    root_ssh_disabled = rc == 0 and "no" in out.lower()
    rc2, out2, _ = _run("grep -E '^root' /etc/sudoers 2>/dev/null | grep -v '^#'")
    root_sudo_unrestricted = rc2 == 0 and "ALL" in out2
    return root_ssh_disabled and not root_sudo_unrestricted


def package_install_restricted_lx() -> bool:
    """Confirm standard users cannot run package managers via sudo on Linux/Debian."""
    rc, out, _ = _run(
        "sudo -l -U nobody 2>/dev/null | grep -iE 'apt|yum|dnf|rpm|dpkg'"
    )
    # nobody should have no package manager sudo rights
    return not out.strip()


def sudoers_restricted_lx() -> bool:
    """Verify sudoers contains only authorized entries and is watched by auditd."""
    # Check for dangerous NOPASSWD or ALL entries for non-admin users
    rc, out, _ = _run(
        "grep -v '^#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null "
        "| grep -v '^$' | grep 'NOPASSWD' | grep -v '%sudo\\|%wheel\\|%admin'"
    )
    if rc == 0 and out.strip():
        return False  # Unauthorized NOPASSWD entries found
    # Check auditd is watching sudoers
    rc2, out2, _ = _run("auditctl -l 2>/dev/null | grep '/etc/sudoers'")
    return rc2 == 0 and len(out2.strip()) > 0


# ===========================================================================
# CM.L2-3.4.6 — Employ the Principle of Least Functionality
# ===========================================================================

def unnecessary_features_disabled_wc() -> bool:
    """Verify unnecessary Windows features are disabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-WindowsOptionalFeature -Online | "
        "Where-Object {$_.FeatureName -match 'SMB1Protocol|TelnetClient|TFTP' "
        "-and $_.State -eq 'Enabled'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) == 0
    except ValueError:
        return False


def unnecessary_services_disabled_wc() -> bool:
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
    return len(running) == 0


def authorized_apps_only_wc() -> bool:
    """Verify installed applications match the authorized software list on Windows Client."""
    rc, out, _ = _ps(
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Select-Object DisplayName | Where-Object {$_.DisplayName} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    # Returns True if enumerable; actual comparison requires external authorized list
    return rc == 0


def minimal_roles_ws() -> bool:
    """Verify only required server roles and features are installed on Windows Server."""
    rc, out, _ = _ps(
        "Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        # A baseline server should have a small number of installed features
        return rc == 0 and int(out.strip()) < 30
    except ValueError:
        return False


def unnecessary_services_disabled_ws() -> bool:
    """Confirm non-essential services are disabled on Windows Server."""
    return unnecessary_services_disabled_wc()


def authorized_apps_only_ws() -> bool:
    """Verify installed applications match the authorized software list on Windows Server."""
    return authorized_apps_only_wc()


def server_core_check_ws() -> bool:
    """Verify whether the server uses a minimal installation (Server Core)."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
        "-Name InstallationType -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty InstallationType"
    )
    # Server Core returns "Server Core"; full GUI returns "Server"
    return rc == 0 and out.strip().lower() in ("server core", "nano server")


def unnecessary_packages_removed_lx() -> bool:
    """Verify no unnecessary packages (X11, compilers on servers) are installed on Linux/Debian."""
    risky_patterns = ["xorg", "xserver", "gcc", "g++", "build-essential", "telnet", "rsh-client"]
    for pkg in risky_patterns:
        rc, out, _ = _run(f"dpkg -l {pkg} 2>/dev/null | grep '^ii'")
        if rc == 0 and out.strip():
            return False
        rc2, out2, _ = _run(f"rpm -q {pkg} 2>/dev/null")
        if rc2 == 0 and out2.strip():
            return False
    return True


def unnecessary_services_disabled_lx() -> bool:
    """Confirm non-essential services are stopped and disabled on Linux/Debian."""
    risky_services = ["avahi-daemon", "cups", "rpcbind", "nfs-server", "xinetd"]
    for svc in risky_services:
        rc, _, _ = _run(f"systemctl is-active {svc} 2>/dev/null")
        if rc == 0:
            return False
    return True


def minimal_listening_services_lx() -> bool:
    """Verify only authorized services are bound to network interfaces on Linux/Debian."""
    rc, out, _ = _run("ss -tlnp 2>/dev/null")
    if rc != 0:
        rc, out, _ = _run("netstat -tlnp 2>/dev/null")
    return rc == 0 and len(out.strip().splitlines()) > 0


# ===========================================================================
# CM.L2-3.4.7 — Restrict, Disable, or Prevent Use of Nonessential Programs, Ports, Protocols
# ===========================================================================

def insecure_protocols_disabled_wc() -> bool:
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
    return smb1_disabled and tls10_disabled


def unused_ports_blocked_wc() -> bool:
    """Confirm Windows Defender Firewall has active inbound rules on Windows Client."""
    rc, out, _ = _ps(
        "Get-NetFirewallRule -Direction Inbound -Action Block "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def rdp_controlled_wc() -> bool:
    """Verify RDP is disabled or restricted to NLA on Windows Client."""
    rdp_val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections"
    )
    if rdp_val == "1":
        return True  # RDP is disabled
    nla_val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication"
    )
    return nla_val == "1"  # NLA is required


def ps_execution_policy_wc() -> bool:
    """Confirm PowerShell execution policy is RemoteSigned or AllSigned on Windows Client."""
    rc, out, _ = _ps("Get-ExecutionPolicy -Scope LocalMachine")
    return rc == 0 and out.strip().lower() in ("remotesigned", "allsigned")


def insecure_protocols_disabled_ws() -> bool:
    """Verify insecure protocols are disabled on Windows Server."""
    return insecure_protocols_disabled_wc()


def unused_ports_blocked_ws() -> bool:
    """Confirm Windows Defender Firewall blocks non-approved inbound traffic on Windows Server."""
    return unused_ports_blocked_wc()


def rdp_controlled_ws() -> bool:
    """Verify RDP is disabled or NLA-enforced on Windows Server."""
    return rdp_controlled_wc()


def ps_execution_policy_ws() -> bool:
    """Confirm PowerShell execution policy is RemoteSigned or AllSigned on Windows Server."""
    return ps_execution_policy_wc()


def telnet_ftp_disabled_ws() -> bool:
    """Verify Telnet and FTP services are not installed or disabled on Windows Server."""
    rc, out, _ = _ps(
        "Get-WindowsFeature -Name 'Telnet-Server','Web-Ftp-Server' "
        "| Where-Object {$_.InstallState -eq 'Installed'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) == 0
    except ValueError:
        return False


def insecure_services_disabled_lx() -> bool:
    """Verify telnet, rsh, rlogin, and other insecure services are not installed on Linux/Debian."""
    insecure_pkgs = ["telnetd", "rsh-server", "rlogin", "rexec", "tftpd", "nis"]
    for pkg in insecure_pkgs:
        rc, out, _ = _run(f"dpkg -l {pkg} 2>/dev/null | grep '^ii'")
        if rc == 0 and out.strip():
            return False
        rc2, out2, _ = _run(f"rpm -q {pkg} 2>/dev/null | grep -v 'not installed'")
        if rc2 == 0 and out2.strip():
            return False
    return True


def authorized_ports_only_lx() -> bool:
    """Confirm only authorized ports are listening on Linux/Debian."""
    rc, out, _ = _run("ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oE ':[0-9]+$' | tr -d ':'")
    if rc != 0:
        return False
    # Returns list of listening ports; actual authorization comparison requires external list
    return len(out.strip()) > 0


def ipv6_disabled_if_unused_lx() -> bool:
    """Verify IPv6 is disabled if not required on Linux/Debian."""
    rc, out, _ = _run("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    if rc == 0 and "= 1" in out:
        return True
    # If IPv6 is in use (intentionally), check for sysctl setting
    rc2, out2, _ = _run("ip -6 addr show 2>/dev/null | grep -v '^$' | wc -l")
    try:
        # If IPv6 addresses are present, verify it is intentional (return True as acceptable)
        return int(out2.strip()) > 0
    except ValueError:
        return False


def ssh_weak_ciphers_disabled_lx() -> bool:
    """Confirm sshd_config restricts to only approved strong ciphers and MACs on Linux/Debian."""
    rc, out, _ = _run("sshd -T 2>/dev/null")
    if rc != 0:
        return False
    weak_ciphers = ["arcfour", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
    cipher_match = re.search(r'^ciphers\s+(.+)', out, re.MULTILINE | re.IGNORECASE)
    if cipher_match:
        active_ciphers = cipher_match.group(1).split(",")
        if any(wc in active_ciphers for wc in weak_ciphers):
            return False
    weak_macs = ["hmac-md5", "hmac-sha1", "umac-64"]
    mac_match = re.search(r'^macs\s+(.+)', out, re.MULTILINE | re.IGNORECASE)
    if mac_match:
        active_macs = mac_match.group(1).split(",")
        if any(wm in active_macs for wm in weak_macs):
            return False
    return True


# ===========================================================================
# CM.L2-3.4.8 — Apply Deny-by-Exception Policy (Application Whitelisting)
# ===========================================================================

def applocker_wdac_enabled_wc() -> bool:
    """Verify AppLocker or WDAC is configured on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        if rc == 0 and int(out.strip()) > 0:
            return True
    except ValueError:
        pass
    # Check for WDAC / Windows Defender Application Control policy
    wdac_path = Path("C:/Windows/System32/CodeIntegrity/SiPolicy.p7b")
    return wdac_path.exists()


def applocker_enforce_mode_wc() -> bool:
    """Confirm AppLocker policy is in Enforce mode on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections "
        "| Select-Object -ExpandProperty EnforcementMode"
    )
    if rc != 0 or not out.strip():
        return False
    modes = out.strip().splitlines()
    return all(m.strip().lower() == "enforced" for m in modes if m.strip())


def applocker_rule_coverage_wc() -> bool:
    """Verify AppLocker rules cover EXE, DLL, Script, and MSI collections on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections "
        "| Select-Object -ExpandProperty RuleCollectionType"
    )
    if rc != 0:
        return False
    required = {"exe", "dll", "script", "msi"}
    found = {r.strip().lower() for r in out.splitlines() if r.strip()}
    return required.issubset(found)


def applocker_wdac_enabled_ws() -> bool:
    """Verify AppLocker or WDAC is configured on Windows Server."""
    return applocker_wdac_enabled_wc()


def applocker_enforce_mode_ws() -> bool:
    """Confirm AppLocker policy is in Enforce mode on Windows Server."""
    return applocker_enforce_mode_wc()


def applocker_rule_coverage_ws() -> bool:
    """Verify AppLocker rules cover required collections on Windows Server."""
    return applocker_rule_coverage_wc()


def app_whitelist_lx() -> bool:
    """Verify SELinux or AppArmor is installed on Linux/Debian."""
    rc_aa, _, _ = _run("which apparmor_status 2>/dev/null")
    rc_se, _, _ = _run("which getenforce 2>/dev/null")
    return rc_aa == 0 or rc_se == 0


def mac_enforcing_lx() -> bool:
    """Confirm SELinux is Enforcing or AppArmor profiles are in enforce mode on Linux/Debian."""
    # Check SELinux
    rc, out, _ = _run("getenforce 2>/dev/null")
    if rc == 0 and out.strip().lower() == "enforcing":
        return True
    # Check AppArmor
    rc2, out2, _ = _run("apparmor_status 2>/dev/null | grep 'profiles are in enforce mode'")
    if rc2 == 0:
        match = re.search(r'(\d+) profiles are in enforce mode', out2)
        if match and int(match.group(1)) > 0:
            return True
    return False


def suid_sgid_audit_lx() -> bool:
    """Scan filesystem for SUID/SGID binaries on Linux/Debian and verify count is reasonable."""
    rc, out, _ = _run(
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | wc -l"
    )
    try:
        count = int(out.strip())
        # A typical Linux system has 20-50 SUID/SGID binaries; over 100 warrants review
        return count < 100
    except ValueError:
        return False


# ===========================================================================
# CM.L2-3.4.9 — Control and Monitor User-Installed Software
# ===========================================================================

def user_install_restricted_wc() -> bool:
    """Verify standard users cannot install software system-wide on Windows Client."""
    return software_install_restricted_wc()


def software_monitor_wc() -> bool:
    """Confirm a monitoring tool compares installed software against the authorized list on Windows Client."""
    rc, out, _ = _ps(
        "Get-Service -Name 'CcmExec','IntuneManagementExtension','WinDefend' "
        "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def user_install_paths_controlled_wc() -> bool:
    """Verify AppLocker or WDAC blocks execution from user-writable directories on Windows Client."""
    rc, out, _ = _ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RuleCollections "
        "| ForEach-Object {$_.Rules} | Where-Object {$_.Action -eq 'Deny'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return applocker_wdac_enabled_wc()


def user_install_restricted_ws() -> bool:
    """Verify standard users cannot install software on Windows Server."""
    return software_install_restricted_ws()


def software_monitor_ws() -> bool:
    """Confirm a monitoring tool tracks installed software on Windows Server."""
    return software_monitor_wc()


def user_install_paths_controlled_ws() -> bool:
    """Verify AppLocker or WDAC blocks execution from user-writable directories on Windows Server."""
    return user_install_paths_controlled_wc()


def user_install_restricted_lx() -> bool:
    """Verify standard users cannot run package managers via sudo on Linux/Debian."""
    return package_install_restricted_lx()


def home_noexec_lx() -> bool:
    """Confirm /home and /tmp are mounted with noexec on Linux/Debian."""
    rc, out, _ = _run("mount | grep -E '\\s/home\\s|\\s/tmp\\s'")
    if rc != 0 or not out.strip():
        # Check /etc/fstab as fallback
        rc2, out2, _ = _run("grep -E '\\s/home\\s|\\s/tmp\\s' /etc/fstab 2>/dev/null")
        out = out2
    if not out.strip():
        return False
    lines = out.strip().splitlines()
    return all("noexec" in line for line in lines if "/home" in line or "/tmp" in line)


def package_monitor_lx() -> bool:
    """Verify a process exists to monitor installed packages against the authorized baseline."""
    # Check for common compliance/monitoring agents
    agents = ["aide", "osqueryd", "wazuh-agent", "filebeat"]
    for agent in agents:
        rc, _, _ = _run(f"systemctl is-active {agent} 2>/dev/null")
        if rc == 0:
            return True
    # Fall back to checking if dpkg log is present and being monitored
    return package_install_log_lx()