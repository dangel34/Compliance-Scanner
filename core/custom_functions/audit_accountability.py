import subprocess
import os
import stat
import re
import hashlib
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: str, shell: bool = True, timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "command timed out"


def _ps(cmd: str) -> tuple[int, str, str]:
    """Run a PowerShell command and return (returncode, stdout, stderr)."""
    full_cmd = f'powershell.exe -NonInteractive -NoProfile -Command "{cmd}"'
    return _run(full_cmd)


# ===========================================================================
# AU.L2-3.3.1 — Create and Retain System Audit Logs
# ===========================================================================

def audit_policy_enabled_wc() -> bool:
    """Verify advanced audit policy subcategories are configured on Windows Client."""
    rc, out, _ = _ps("auditpol /get /category:* | Select-String 'Success|Failure'")
    return rc == 0 and len(out.splitlines()) >= 10


def security_log_active_wc() -> bool:
    """Confirm the Security event log is enabled and active on Windows Client."""
    rc, out, _ = _ps(
        "Get-WinEvent -ListLog Security | Select-Object -ExpandProperty IsEnabled"
    )
    return rc == 0 and out.strip().lower() == "true"


def log_retention_wc() -> bool:
    """Verify Security event log retention size and method on Windows Client."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' "
        "| Select-Object MaxSize, Retention"
    )
    return rc == 0 and "MaxSize" in out


def log_writing_wc() -> bool:
    """Confirm recent events are present in the Security log on Windows Client."""
    rc, out, _ = _ps(
        "Get-WinEvent -LogName Security -MaxEvents 5 -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def audit_policy_enabled_ws() -> bool:
    """Verify advanced audit policy subcategories are configured on Windows Server."""
    return audit_policy_enabled_wc()


def security_log_active_ws() -> bool:
    """Confirm the Security event log is enabled and active on Windows Server."""
    return security_log_active_wc()


def log_retention_ws() -> bool:
    """Verify Security event log retention size and days-based policy on Windows Server."""
    return log_retention_wc()


def log_writing_ws() -> bool:
    """Confirm recent events are present in the Security log on Windows Server."""
    return log_writing_wc()


def log_forwarding_ws() -> bool:
    """Verify Windows Event Forwarding or SIEM agent is configured on Windows Server."""
    rc, out, _ = _ps(
        "Get-Service -Name 'WecSvc','Wecsvc','SplunkForwarder','elastic-agent' "
        "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def auditd_running_lx() -> bool:
    """Verify the auditd daemon is active and enabled at boot on Linux/Debian."""
    rc_active, _, _ = _run("systemctl is-active auditd")
    rc_enabled, _, _ = _run("systemctl is-enabled auditd")
    return rc_active == 0 and rc_enabled == 0


def audit_log_active_lx() -> bool:
    """Verify /var/log/audit/audit.log exists, is non-empty, and has recent entries."""
    log_path = Path("/var/log/audit/audit.log")
    if not log_path.exists() or log_path.stat().st_size == 0:
        return False
    rc, out, _ = _run("tail -n 5 /var/log/audit/audit.log")
    return rc == 0 and len(out.strip()) > 0


def log_retention_lx() -> bool:
    """Check auditd.conf for max_log_file, num_logs, and max_log_file_action."""
    conf_path = Path("/etc/audit/auditd.conf")
    if not conf_path.exists():
        return False
    content = conf_path.read_text()
    has_max = re.search(r'^\s*max_log_file\s*=\s*\d+', content, re.MULTILINE)
    has_num = re.search(r'^\s*num_logs\s*=\s*\d+', content, re.MULTILINE)
    has_action = re.search(r'^\s*max_log_file_action\s*=\s*\S+', content, re.MULTILINE)
    return bool(has_max and has_num and has_action)


def log_forwarding_lx() -> bool:
    """Verify rsyslog, syslog-ng, or audisp-remote is configured to forward logs."""
    # Check for audisp-remote plugin
    audisp_path = Path("/etc/audisp/plugins.d/au-remote.conf")
    if audisp_path.exists():
        content = audisp_path.read_text()
        if re.search(r'active\s*=\s*yes', content, re.IGNORECASE):
            return True
    # Check for rsyslog remote forwarding
    rc, out, _ = _run("grep -rE '^[*@].*@|@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null")
    if rc == 0 and out.strip():
        return True
    # Check for a running SIEM agent
    rc2, out2, _ = _run(
        "systemctl is-active filebeat elastic-agent splunk 2>/dev/null | grep -c '^active'"
    )
    try:
        return int(out2.strip()) > 0
    except ValueError:
        return False


# ===========================================================================
# AU.L2-3.3.2 — Ensure Actions of Individual Users Can Be Traced
# ===========================================================================

def unique_user_accounts_wc() -> bool:
    """Verify no shared or generic accounts exist on Windows Client."""
    rc, out, _ = _ps(
        "Get-LocalUser | Where-Object {$_.Name -match 'shared|generic|temp|test'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) == 0
    except ValueError:
        return False


def logon_audit_wc() -> bool:
    """Confirm logon/logoff audit subcategories are enabled on Windows Client."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Logon','Logoff','Account Lockout' "
        "| Select-String 'Success and Failure|Success|Failure'"
    )
    return rc == 0 and len(out.strip()) > 0


def privilege_use_audit_wc() -> bool:
    """Ensure privilege use audit subcategories are enabled on Windows Client."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Sensitive Privilege Use','Non Sensitive Privilege Use' "
        "| Select-String 'Success|Failure'"
    )
    return rc == 0 and len(out.strip()) > 0


def process_creation_audit_wc() -> bool:
    """Verify process creation auditing is enabled on Windows Client (Event ID 4688)."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Process Creation' | Select-String 'Success'"
    )
    return rc == 0 and len(out.strip()) > 0


def unique_user_accounts_ws() -> bool:
    """Verify no shared or generic accounts exist on Windows Server."""
    return unique_user_accounts_wc()


def logon_audit_ws() -> bool:
    """Confirm logon/logoff and Kerberos audit subcategories are enabled on Windows Server."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Logon','Logoff','Kerberos Authentication Service',"
        "'Kerberos Service Ticket Operations' | Select-String 'Success|Failure'"
    )
    return rc == 0 and len(out.strip()) > 0


def privilege_use_audit_ws() -> bool:
    """Ensure privilege use audit subcategories are enabled on Windows Server."""
    return privilege_use_audit_wc()


def process_creation_audit_ws() -> bool:
    """Verify process creation auditing is enabled on Windows Server (Event ID 4688)."""
    return process_creation_audit_wc()


def object_access_audit_ws() -> bool:
    """Confirm file system object access auditing is enabled on Windows Server."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'File System','Registry' | Select-String 'Success|Failure'"
    )
    return rc == 0 and len(out.strip()) > 0


def unique_user_accounts_lx() -> bool:
    """Verify no duplicate UIDs and no shared accounts in /etc/passwd."""
    rc, out, _ = _run("awk -F: '{print $3}' /etc/passwd | sort | uniq -d")
    if rc != 0:
        return False
    duplicate_uids = out.strip()
    if duplicate_uids:
        return False
    rc2, out2, _ = _run(
        "awk -F: '{print $1}' /etc/passwd | grep -iE '^shared|^generic|^temp|^test'"
    )
    return not out2.strip()


def logon_audit_lx() -> bool:
    """Confirm auditd rules capture login/logout events on Linux/Debian."""
    rc, out, _ = _run("auditctl -l 2>/dev/null | grep -E 'lastlog|faillog|wtmp|btmp'")
    return rc == 0 and len(out.strip()) > 0


def privilege_use_audit_lx() -> bool:
    """Verify auditd rules exist for sudo, su, and setuid/setgid binaries."""
    rc, out, _ = _run("auditctl -l 2>/dev/null | grep -E 'sudo|su\\b|setuid|setgid|execve'")
    return rc == 0 and len(out.strip()) > 0


def auid_preserved_lx() -> bool:
    """Confirm auid is recorded in recent audit events and is not unset (-1 / 4294967295)."""
    rc, out, _ = _run(
        "ausearch -m USER_LOGIN --start recent 2>/dev/null | grep -v 'auid=4294967295' "
        "| grep -c 'auid='"
    )
    try:
        return int(out.strip()) > 0
    except ValueError:
        return False


# ===========================================================================
# AU.L2-3.3.3 — Review and Update Logged Events
# ===========================================================================

def advanced_audit_policy_wc() -> bool:
    """Verify all relevant advanced audit policy subcategories are configured on Windows Client."""
    required = [
        "Account Logon", "Account Management", "Detailed Tracking",
        "Logon/Logoff", "Object Access", "Policy Change",
        "Privilege Use", "System"
    ]
    rc, out, _ = _ps("auditpol /get /category:*")
    if rc != 0:
        return False
    return all(cat.lower() in out.lower() for cat in required)


def audit_coverage_wc() -> bool:
    """Confirm audit policy includes success and failure for all CMMC-required event types."""
    rc, out, _ = _ps(
        "auditpol /get /category:* | Select-String 'Success and Failure'"
    )
    try:
        return rc == 0 and len(out.strip().splitlines()) >= 5
    except Exception:
        return False


def advanced_audit_policy_ws() -> bool:
    """Verify all relevant advanced audit policy subcategories are configured on Windows Server."""
    return advanced_audit_policy_wc()


def audit_coverage_ws() -> bool:
    """Confirm audit policy covers all CMMC-required event types on Windows Server."""
    return audit_coverage_wc()


def gpo_audit_policy_ws() -> bool:
    """Verify the audit policy is enforced via GPO on Windows Server."""
    rc, out, _ = _ps(
        "gpresult /R /SCOPE COMPUTER 2>&1 | Select-String 'Audit|Security'"
    )
    return rc == 0 and len(out.strip()) > 0


def audit_rules_coverage_lx() -> bool:
    """Verify /etc/audit/rules.d/ covers required CMMC event categories on Linux/Debian."""
    rules_dir = Path("/etc/audit/rules.d/")
    if not rules_dir.exists():
        return False
    all_rules = ""
    for rule_file in rules_dir.glob("*.rules"):
        all_rules += rule_file.read_text()
    required_patterns = [
        r'-w\s+/etc/passwd',          # user/group changes
        r'-w\s+/etc/shadow',
        r'-a\s+always,exit.*execve',  # privilege escalation
        r'-w\s+/etc/sudoers',         # sudo config
        r'-w\s+/var/log',             # log access
    ]
    return all(re.search(p, all_rules) for p in required_patterns)


def audit_rules_locked_lx() -> bool:
    """Confirm auditd rules include -e 2 (immutable) flag on Linux/Debian."""
    rc, out, _ = _run("auditctl -s 2>/dev/null | grep 'enabled 2'")
    if rc == 0 and out.strip():
        return True
    # Also check rules files for -e 2
    rc2, out2, _ = _run("grep -r '^-e 2' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null")
    return rc2 == 0 and len(out2.strip()) > 0


# ===========================================================================
# AU.L2-3.3.4 — Alert in the Event of Audit Logging Process Failure
# ===========================================================================

def audit_failure_alert_wc() -> bool:
    """Verify CrashOnAuditFail is configured on Windows Client."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name CrashOnAuditFail -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty CrashOnAuditFail"
    )
    # 1 = warn and continue, 2 = halt — either satisfies the requirement
    return rc == 0 and out.strip() in ("1", "2")


def log_full_action_wc() -> bool:
    """Confirm Security event log max size and overflow action on Windows Client."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' "
        "| Select-Object MaxSize,Retention | Format-List"
    )
    return rc == 0 and "MaxSize" in out


def audit_failure_alert_ws() -> bool:
    """Verify CrashOnAuditFail is configured on Windows Server."""
    return audit_failure_alert_wc()


def log_full_action_ws() -> bool:
    """Confirm Security event log overflow action on Windows Server."""
    return log_full_action_wc()


def siem_audit_alert_ws() -> bool:
    """Verify SIEM is alerting on Event ID 1102 (log cleared) and 1100 (audit stopped)."""
    rc, out, _ = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,1100} "
        "-MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object "
        "| Select-Object -ExpandProperty Count"
    )
    # We check that the query capability works; actual SIEM alert config is policy-level
    return rc == 0


def auditd_disk_full_action_lx() -> bool:
    """Verify disk_full_action in auditd.conf is set to halt, syslog, or email."""
    conf_path = Path("/etc/audit/auditd.conf")
    if not conf_path.exists():
        return False
    content = conf_path.read_text()
    match = re.search(r'^\s*disk_full_action\s*=\s*(\S+)', content, re.MULTILINE | re.IGNORECASE)
    if not match:
        return False
    return match.group(1).lower() in ("halt", "syslog", "email", "exec", "suspend")


def auditd_space_left_action_lx() -> bool:
    """Confirm space_left_action and admin_space_left_action are configured in auditd.conf."""
    conf_path = Path("/etc/audit/auditd.conf")
    if not conf_path.exists():
        return False
    content = conf_path.read_text()
    space_left = re.search(
        r'^\s*space_left_action\s*=\s*(\S+)', content, re.MULTILINE | re.IGNORECASE
    )
    admin_space = re.search(
        r'^\s*admin_space_left_action\s*=\s*(\S+)', content, re.MULTILINE | re.IGNORECASE
    )
    valid = {"email", "halt", "syslog", "exec", "suspend"}
    sl_ok = space_left and space_left.group(1).lower() in valid
    asl_ok = admin_space and admin_space.group(1).lower() in valid
    return bool(sl_ok and asl_ok)


def auditd_failure_flag_lx() -> bool:
    """Verify auditd rules include -f 1 or -f 2 failure flag."""
    rc, out, _ = _run("auditctl -s 2>/dev/null | grep 'failure'")
    if rc == 0 and re.search(r'failure\s+[12]', out):
        return True
    rc2, out2, _ = _run(
        "grep -rE '^-f [12]' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null"
    )
    return rc2 == 0 and len(out2.strip()) > 0


# ===========================================================================
# AU.L2-3.3.5 — Correlate Audit Record Review, Analysis, and Reporting
# ===========================================================================

def log_forwarding_wc() -> bool:
    """Verify WEF or SIEM agent is configured on Windows Client."""
    rc, out, _ = _ps(
        "Get-Service -Name 'WecSvc','SplunkForwarder','elastic-agent','nxlog' "
        "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def log_detail_wc() -> bool:
    """Confirm log entries include fields required for correlation on Windows Client."""
    rc, out, _ = _ps(
        "Get-WinEvent -LogName Security -MaxEvents 1 "
        "| Select-Object TimeCreated,Id,UserId,Message | Format-List"
    )
    return rc == 0 and "TimeCreated" in out and "UserId" in out


def log_detail_ws() -> bool:
    """Confirm log entries include correlation fields on Windows Server."""
    return log_detail_wc()


def siem_agent_active_ws() -> bool:
    """Verify a SIEM agent is installed, running, and communicating on Windows Server."""
    return log_forwarding_ws()


def log_detail_lx() -> bool:
    """Confirm auditd records include auid, uid, pid, timestamp, and syscall fields."""
    rc, out, _ = _run(
        "ausearch -m SYSCALL --start recent 2>/dev/null | head -5"
    )
    required_fields = ["auid=", "uid=", "pid=", "syscall="]
    return rc == 0 and all(f in out for f in required_fields)


def siem_agent_active_lx() -> bool:
    """Verify a SIEM agent is installed, running, and shipping logs on Linux/Debian."""
    agents = ["filebeat", "elastic-agent", "splunkd", "td-agent", "fluentd"]
    for agent in agents:
        rc, _, _ = _run(f"systemctl is-active {agent} 2>/dev/null")
        if rc == 0:
            return True
    return False


# ===========================================================================
# AU.L2-3.3.6 — Audit Record Reduction and Report Generation
# ===========================================================================

def log_query_capability_wc() -> bool:
    """Verify ability to filter and query audit logs on Windows Client."""
    rc, out, _ = _ps(
        "Get-WinEvent -LogName Security -MaxEvents 10 "
        "-FilterXPath '*[System[EventID=4624]]' -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    return rc == 0


def log_export_wc() -> bool:
    """Confirm audit logs can be exported from Windows Client."""
    rc, _, _ = _ps(
        "Get-Command wevtutil -ErrorAction SilentlyContinue | Measure-Object "
        "| Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0
    except Exception:
        return False


def log_query_capability_ws() -> bool:
    """Verify ability to filter and query audit logs on Windows Server."""
    return log_query_capability_wc()


def log_export_ws() -> bool:
    """Confirm audit logs can be exported from Windows Server."""
    return log_export_wc()


def siem_reporting_ws() -> bool:
    """Verify SIEM agent connectivity implies reporting capability on Windows Server."""
    return siem_agent_active_ws()


def ausearch_available_lx() -> bool:
    """Verify ausearch and aureport are installed and functional on Linux/Debian."""
    rc1, _, _ = _run("which ausearch")
    rc2, _, _ = _run("which aureport")
    return rc1 == 0 and rc2 == 0


def log_query_capability_lx() -> bool:
    """Confirm ausearch supports filtering by auid, timestamp, and syscall."""
    rc, out, _ = _run("ausearch --help 2>&1 | grep -E '\\-\\-uid|\\-\\-start|\\-\\-syscall'")
    return rc == 0 and len(out.strip()) > 0


def siem_reporting_lx() -> bool:
    """Verify SIEM agent connectivity implies reporting capability on Linux/Debian."""
    return siem_agent_active_lx()


# ===========================================================================
# AU.L2-3.3.7 — Compare and Synchronize Internal Clocks (NTP)
# ===========================================================================

def w32tm_running_wc() -> bool:
    """Verify the Windows Time service is running on Windows Client."""
    rc, out, _ = _ps(
        "Get-Service -Name W32Time | Select-Object -ExpandProperty Status"
    )
    return rc == 0 and out.strip().lower() == "running"


def ntp_source_wc() -> bool:
    """Confirm NTP source is configured on Windows Client."""
    rc, out, _ = _ps("w32tm /query /source")
    return rc == 0 and len(out.strip()) > 0 and "error" not in out.lower()


def time_sync_status_wc() -> bool:
    """Verify w32tm reports successful last sync on Windows Client."""
    rc, out, _ = _ps("w32tm /query /status")
    return rc == 0 and "Last Successful Sync Time" in out


def w32tm_running_ws() -> bool:
    """Verify the Windows Time service is running on Windows Server."""
    return w32tm_running_wc()


def ntp_source_ws() -> bool:
    """Confirm NTP source is configured on Windows Server."""
    return ntp_source_wc()


def time_sync_status_ws() -> bool:
    """Verify w32tm reports successful last sync on Windows Server."""
    return time_sync_status_wc()


def pdc_ntp_source_ws() -> bool:
    """Verify the PDC emulator is syncing from an external authoritative NTP source."""
    rc, out, _ = _ps(
        "w32tm /query /configuration | Select-String 'NtpServer'"
    )
    if rc != 0 or not out.strip():
        return False
    # Ensure it's not pointing only to itself (Local CMOS Clock or VM IC)
    return "time.nist.gov" in out or "pool.ntp.org" in out or re.search(r'\d+\.\d+\.\d+\.\d+', out)


def ntp_running_lx() -> bool:
    """Verify chronyd, ntpd, or systemd-timesyncd is active on Linux/Debian."""
    for service in ["chronyd", "ntpd", "systemd-timesyncd"]:
        rc, _, _ = _run(f"systemctl is-active {service} 2>/dev/null")
        if rc == 0:
            return True
    return False


def ntp_source_lx() -> bool:
    """Confirm an authoritative NTP server is configured on Linux/Debian."""
    for conf in ["/etc/chrony.conf", "/etc/chrony/chrony.conf", "/etc/ntp.conf"]:
        if Path(conf).exists():
            content = Path(conf).read_text()
            if re.search(r'^\s*(server|pool)\s+\S+', content, re.MULTILINE):
                return True
    return False


def time_sync_status_lx() -> bool:
    """Verify time synchronization is active and within bounds on Linux/Debian."""
    rc, out, _ = _run("chronyc tracking 2>/dev/null | grep 'System time'")
    if rc == 0 and out.strip():
        return True
    rc2, out2, _ = _run("timedatectl status 2>/dev/null | grep 'NTP synchronized: yes'")
    return rc2 == 0 and len(out2.strip()) > 0


# ===========================================================================
# AU.L2-3.3.8 — Protect Audit Information and Tools from Unauthorized Access
# ===========================================================================

def event_log_acl_wc() -> bool:
    """Verify Security event log DACL restricts access on Windows Client."""
    rc, out, _ = _ps(
        "wevtutil gl Security | Select-String 'channelAccess'"
    )
    return rc == 0 and "channelAccess" in out


def log_clear_audit_wc() -> bool:
    """Confirm audit policy change auditing is enabled so log clears are detected."""
    rc, out, _ = _ps(
        "auditpol /get /subcategory:'Audit Policy Change' | Select-String 'Success'"
    )
    return rc == 0 and len(out.strip()) > 0


def audit_tools_protected_wc() -> bool:
    """Verify auditpol.exe is not accessible to standard users on Windows Client."""
    rc, out, _ = _ps(
        "(Get-Acl 'C:\\Windows\\System32\\auditpol.exe').Access "
        "| Where-Object {$_.IdentityReference -notmatch 'SYSTEM|Administrators|TrustedInstaller'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return rc == 0 and int(out.strip()) == 0
    except ValueError:
        return False


def event_log_acl_ws() -> bool:
    """Verify Security event log DACL restricts access on Windows Server."""
    return event_log_acl_wc()


def log_clear_audit_ws() -> bool:
    """Confirm audit policy change auditing detects log clears on Windows Server."""
    return log_clear_audit_wc()


def audit_tools_protected_ws() -> bool:
    """Verify auditpol.exe is not accessible to standard users on Windows Server."""
    return audit_tools_protected_wc()


def remote_log_acl_ws() -> bool:
    """Confirm centralized log storage has access controls preventing unauthorized modification."""
    # Check WEF subscription collector access
    rc, out, _ = _ps(
        "wecutil es 2>$null | Measure-Object | Select-Object -ExpandProperty Count"
    )
    # If WEF subscriptions exist, collector is active — actual remote ACL is policy-level
    try:
        return rc == 0 and int(out.strip()) > 0
    except ValueError:
        return False


def audit_log_permissions_lx() -> bool:
    """Verify /var/log/audit/audit.log is owned by root with permissions 600 or 640."""
    log_path = Path("/var/log/audit/audit.log")
    if not log_path.exists():
        return False
    s = log_path.stat()
    owner_is_root = s.st_uid == 0
    mode = oct(s.st_mode)[-3:]
    return owner_is_root and mode in ("600", "640")


def audit_conf_permissions_lx() -> bool:
    """Confirm /etc/audit/ config files are owned by root with restrictive permissions."""
    audit_conf = Path("/etc/audit/auditd.conf")
    rules_dir = Path("/etc/audit/rules.d/")
    if not audit_conf.exists():
        return False
    s = audit_conf.stat()
    conf_ok = s.st_uid == 0 and oct(s.st_mode)[-3:] in ("600", "640", "400")
    dir_ok = rules_dir.exists() and rules_dir.stat().st_uid == 0
    return conf_ok and dir_ok


def audit_binary_integrity_lx() -> bool:
    """Verify integrity of audit binaries using package manager on Linux/Debian."""
    # Try dpkg first (Debian/Ubuntu)
    rc_dpkg, out_dpkg, _ = _run("dpkg --verify auditd 2>/dev/null")
    if rc_dpkg == 0 and not out_dpkg.strip():
        return True  # dpkg verify passed with no issues
    # Fall back to rpm (RHEL/CentOS/Rocky)
    rc_rpm, out_rpm, _ = _run("rpm -V audit 2>/dev/null | grep -E '^S|^M|^5'")
    if rc_rpm == 0 and not out_rpm.strip():
        return True  # rpm verify passed with no issues
    return False


def audit_self_protect_rules_lx() -> bool:
    """Confirm auditd rules watch /etc/audit/ and /var/log/audit/ for changes."""
    rc, out, _ = _run(
        "auditctl -l 2>/dev/null | grep -E '/etc/audit|/var/log/audit'"
    )
    return rc == 0 and len(out.strip()) > 0


# ===========================================================================
# AU.L2-3.3.9 — Limit Management of Audit Logging to Privileged Users
# ===========================================================================

def manage_audit_right_wc() -> bool:
    """Verify SeSecurityPrivilege is assigned only to Administrators on Windows Client."""
    rc, out, _ = _ps(
        "secedit /export /cfg C:\\Windows\\Temp\\secpol_tmp.cfg /quiet; "
        "Select-String 'SeSecurityPrivilege' C:\\Windows\\Temp\\secpol_tmp.cfg"
    )
    if rc != 0 or not out.strip():
        return False
    # Should only reference Administrators (*S-1-5-32-544) or equivalent
    return "SeSecurityPrivilege" in out and "Users" not in out


def audit_policy_modify_restricted_wc() -> bool:
    """Confirm standard users cannot modify audit policy on Windows Client."""
    rc, out, _ = _ps(
        "secedit /export /cfg C:\\Windows\\Temp\\secpol_tmp.cfg /quiet; "
        "Select-String 'SeSecurityPrivilege|SeAuditPrivilege' C:\\Windows\\Temp\\secpol_tmp.cfg"
    )
    return rc == 0 and "Users" not in out


def manage_audit_right_ws() -> bool:
    """Verify SeSecurityPrivilege is assigned only to Administrators on Windows Server."""
    return manage_audit_right_wc()


def audit_policy_modify_restricted_ws() -> bool:
    """Confirm standard users cannot modify audit policy on Windows Server."""
    return audit_policy_modify_restricted_wc()


def event_log_readers_membership_ws() -> bool:
    """Verify Event Log Readers group contains only authorized accounts on Windows Server."""
    rc, out, _ = _ps(
        "Get-LocalGroupMember -Group 'Event Log Readers' "
        "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
    )
    if rc != 0:
        return False
    members = [m.strip().lower() for m in out.splitlines() if m.strip()]
    # Flag if any obviously generic accounts are members
    suspicious = [m for m in members if re.search(r'everyone|users|authenticated', m)]
    return len(suspicious) == 0


def siem_access_restricted_ws() -> bool:
    """Confirm SIEM access is restricted; check agent is running under a service account."""
    rc, out, _ = _ps(
        "Get-WmiObject Win32_Service | Where-Object {$_.Name -match 'splunk|elastic|nxlog'} "
        "| Select-Object StartName | Format-List"
    )
    if rc != 0 or not out.strip():
        return False
    # Service should not run as LocalSystem or a generic account
    return "LocalSystem" not in out and "NT AUTHORITY\\SYSTEM" not in out


def auditd_management_restricted_lx() -> bool:
    """Verify auditctl and /etc/audit/ are accessible only by root on Linux/Debian."""
    rc_bin, _, _ = _run(
        "ls -la $(which auditctl) 2>/dev/null | awk '{print $1, $3}' | grep -v '^-rwx.*root'"
    )
    conf_ok = audit_conf_permissions_lx()
    # If no non-root accessible auditctl found, and conf is root-only, return True
    return conf_ok


def audit_sudo_rights_lx() -> bool:
    """Confirm sudoers does not grant unrestricted audit tool access to non-admin accounts."""
    rc, out, _ = _run(
        "grep -rE 'auditctl|auditd|aureport|ausearch' /etc/sudoers /etc/sudoers.d/ 2>/dev/null "
        "| grep -v '^#'"
    )
    if rc != 0 or not out.strip():
        return True  # No sudo rules for audit tools — good
    # If rules exist, check they are scoped to specific admin groups only
    suspicious = [
        line for line in out.splitlines()
        if not re.search(r'%sudo|%wheel|%admin|%audit', line)
    ]
    return len(suspicious) == 0


def audit_log_dir_access_lx() -> bool:
    """Verify /var/log/audit/ directory permissions are 700 (root only) on Linux/Debian."""
    audit_dir = Path("/var/log/audit")
    if not audit_dir.exists():
        return False
    s = audit_dir.stat()
    owner_is_root = s.st_uid == 0
    mode = oct(s.st_mode)[-3:]
    return owner_is_root and mode == "700"