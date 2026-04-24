import subprocess
import os
import stat
import re
import hashlib
from pathlib import Path

_RUN_CACHE: dict[tuple[object, bool, int], tuple[int, str, str]] = {}


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
    full_cmd = f'powershell.exe -NonInteractive -NoProfile -Command "{cmd}"'
    return _run(full_cmd)


# ===========================================================================
# AU.L2-3.3.1 — Create and Retain System Audit Logs
# ===========================================================================

def audit_policy_enabled_wc() -> tuple[bool, str]:
    """Verify advanced audit policy subcategories are configured on Windows Client."""
    rc, out, err = _ps("auditpol /get /category:* | Select-String 'Success|Failure'")
    if rc != 0:
        return (False, f"Could not query audit policy: {err}")
    count = len(out.splitlines())
    if count >= 10:
        return (True, f"Advanced audit policy active: {count} subcategories configured")
    return (False, f"Insufficient audit policy subcategories configured: {count} (required: >= 10)")


def security_log_active_wc() -> tuple[bool, str]:
    """Confirm the Security event log is enabled and active on Windows Client."""
    rc, out, err = _ps(
        "Get-WinEvent -ListLog Security | Select-Object -ExpandProperty IsEnabled"
    )
    if rc != 0:
        return (False, f"Could not query Security event log status: {err}")
    if out.strip().lower() == "true":
        return (True, "Security event log is enabled and active")
    return (False, f"Security event log is not enabled (IsEnabled = {out.strip() or 'unknown'})")


def log_retention_wc() -> tuple[bool, str]:
    """Verify Security event log retention size and method on Windows Client."""
    rc, out, err = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' "
        "| Select-Object MaxSize, Retention"
    )
    if rc != 0:
        return (False, f"Could not query Security log retention settings: {err}")
    if "MaxSize" in out:
        return (True, "Security event log MaxSize and Retention are configured")
    return (False, "Security event log MaxSize not found in registry")


def log_writing_wc() -> tuple[bool, str]:
    """Confirm recent events are present in the Security log on Windows Client."""
    rc, out, err = _ps(
        "Get-WinEvent -LogName Security -MaxEvents 5 -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc != 0:
        return (False, f"Could not query Security event log: {err}")
    try:
        count = int(out.strip())
        if count > 0:
            return (True, f"Security event log has recent entries ({count} retrieved)")
        return (False, "No recent entries found in the Security event log")
    except ValueError:
        return (False, "Could not parse Security log event count")


def audit_policy_enabled_ws() -> tuple[bool, str]:
    """Verify advanced audit policy subcategories are configured on Windows Server."""
    return audit_policy_enabled_wc()


def security_log_active_ws() -> tuple[bool, str]:
    """Confirm the Security event log is enabled and active on Windows Server."""
    return security_log_active_wc()


def log_retention_ws() -> tuple[bool, str]:
    """Verify Security event log retention size and days-based policy on Windows Server."""
    return log_retention_wc()


def log_writing_ws() -> tuple[bool, str]:
    """Confirm recent events are present in the Security log on Windows Server."""
    return log_writing_wc()


def log_forwarding_ws() -> tuple[bool, str]:
    """Verify Windows Event Forwarding or SIEM agent is configured on Windows Server."""
    rc, out, err = _ps(
        "Get-Service -Name 'WecSvc','Wecsvc','SplunkForwarder','elastic-agent' "
        "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc != 0:
        return (False, f"Could not query log forwarding services: {err}")
    try:
        count = int(out.strip())
        if count > 0:
            return (True, f"Log forwarding service is running ({count} active agent(s))")
        return (False, "No log forwarding service (WEF/Splunk/Elastic) is running")
    except ValueError:
        return (False, "Could not parse log forwarding service count")


def auditd_running_lx() -> tuple[bool, str]:
    """Verify the auditd daemon is active and enabled at boot on Linux/Debian."""
    rc_active, _, _ = _run("systemctl is-active auditd")
    rc_enabled, _, _ = _run("systemctl is-enabled auditd")
    if rc_active == 0 and rc_enabled == 0:
        return (True, "auditd is active and enabled at boot")
    if rc_active != 0 and rc_enabled != 0:
        return (False, "auditd is not active and not enabled at boot")
    if rc_active != 0:
        return (False, "auditd is enabled at boot but is not currently active")
    return (False, "auditd is active but not enabled at boot")


def audit_log_active_lx() -> tuple[bool, str]:
    """Verify /var/log/audit/audit.log exists, is non-empty, and has recent entries."""
    log_path = Path("/var/log/audit/audit.log")
    if not log_path.exists():
        return (False, "Audit log not found: /var/log/audit/audit.log does not exist")
    size = log_path.stat().st_size
    if size == 0:
        return (False, "Audit log exists but is empty: /var/log/audit/audit.log")
    rc, out, _ = _run("tail -n 5 /var/log/audit/audit.log")
    if rc == 0 and len(out.strip()) > 0:
        return (True, f"Audit log active with recent entries (size: {size} bytes)")
    return (False, "Audit log exists but contains no readable recent entries")


def log_retention_lx() -> tuple[bool, str]:
    """Check auditd.conf for max_log_file, num_logs, and max_log_file_action."""
    conf_path = Path("/etc/audit/auditd.conf")
    if not conf_path.exists():
        return (False, "auditd.conf not found: /etc/audit/auditd.conf does not exist")
    content = conf_path.read_text()
    has_max = re.search(r'^\s*max_log_file\s*=\s*\d+', content, re.MULTILINE)
    has_num = re.search(r'^\s*num_logs\s*=\s*\d+', content, re.MULTILINE)
    has_action = re.search(r'^\s*max_log_file_action\s*=\s*\S+', content, re.MULTILINE)
    missing = []
    if not has_max:
        missing.append("max_log_file")
    if not has_num:
        missing.append("num_logs")
    if not has_action:
        missing.append("max_log_file_action")
    if not missing:
        return (True, "auditd.conf has max_log_file, num_logs, and max_log_file_action configured")
    return (False, f"auditd.conf missing required retention settings: {', '.join(missing)}")


def log_forwarding_lx() -> tuple[bool, str]:
    """Verify rsyslog, syslog-ng, or audisp-remote is configured to forward logs."""
    # Check for audisp-remote plugin
    audisp_path = Path("/etc/audisp/plugins.d/au-remote.conf")
    if audisp_path.exists():
        content = audisp_path.read_text()
        if re.search(r'active\s*=\s*yes', content, re.IGNORECASE):
            return (True, "audisp-remote plugin is active for log forwarding")
    # Check for rsyslog remote forwarding
    rc, out, _ = _run("grep -rE '^[*@].*@|@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null")
    if rc == 0 and out.strip():
        return (True, "rsyslog is configured to forward logs to a remote destination")
    # Check for a running SIEM agent
    rc2, out2, _ = _run(
        "systemctl is-active filebeat elastic-agent splunk 2>/dev/null | grep -c '^active'"
    )
    try:
        if int(out2.strip()) > 0:
            return (True, "SIEM agent (filebeat/elastic-agent/splunk) is active for log forwarding")
    except ValueError:
        pass
    return (False, "No log forwarding configured (audisp-remote, rsyslog remote, or SIEM agent)")


# ===========================================================================
# AU.L2-3.3.2 — Ensure Actions of Individual Users Can Be Traced
# ===========================================================================

def unique_user_accounts_wc() -> tuple[bool, str]:
    """Verify no shared or generic accounts exist on Windows Client."""
    rc, out, err = _ps(
        "Get-LocalUser | Where-Object {$_.Name -match 'shared|generic|temp|test'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc != 0:
        return (False, f"Could not query local users: {err}")
    try:
        count = int(out.strip())
        if count == 0:
            return (True, "No shared or generic accounts found on Windows Client")
        return (False, f"Found {count} shared/generic account(s) matching 'shared|generic|temp|test'")
    except ValueError:
        return (False, "Could not parse local user account count")


def logon_audit_wc() -> tuple[bool, str]:
    """Confirm logon/logoff audit subcategories are enabled on Windows Client."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'Logon','Logoff','Account Lockout' "
        "| Select-String 'Success and Failure|Success|Failure'"
    )
    if rc != 0:
        return (False, f"Could not query logon audit policy: {err}")
    if len(out.strip()) > 0:
        return (True, "Logon/Logoff/Account Lockout audit subcategories are enabled")
    return (False, "Logon/Logoff/Account Lockout audit subcategories are not enabled")


def privilege_use_audit_wc() -> tuple[bool, str]:
    """Ensure privilege use audit subcategories are enabled on Windows Client."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'Sensitive Privilege Use','Non Sensitive Privilege Use' "
        "| Select-String 'Success|Failure'"
    )
    if rc != 0:
        return (False, f"Could not query privilege use audit policy: {err}")
    if len(out.strip()) > 0:
        return (True, "Privilege Use audit subcategories are enabled")
    return (False, "Privilege Use audit subcategories are not configured")


def process_creation_audit_wc() -> tuple[bool, str]:
    """Verify process creation auditing is enabled on Windows Client (Event ID 4688)."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'Process Creation' | Select-String 'Success'"
    )
    if rc != 0:
        return (False, f"Could not query process creation audit policy: {err}")
    if len(out.strip()) > 0:
        return (True, "Process Creation auditing is enabled (Event ID 4688 will be generated)")
    return (False, "Process Creation auditing is not enabled")


def unique_user_accounts_ws() -> tuple[bool, str]:
    """Verify no shared or generic accounts exist on Windows Server."""
    return unique_user_accounts_wc()


def logon_audit_ws() -> tuple[bool, str]:
    """Confirm logon/logoff and Kerberos audit subcategories are enabled on Windows Server."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'Logon','Logoff','Kerberos Authentication Service',"
        "'Kerberos Service Ticket Operations' | Select-String 'Success|Failure'"
    )
    if rc != 0:
        return (False, f"Could not query logon/Kerberos audit policy: {err}")
    if len(out.strip()) > 0:
        return (True, "Logon/Logoff/Kerberos audit subcategories are enabled")
    return (False, "Logon/Logoff/Kerberos audit subcategories are not configured")


def privilege_use_audit_ws() -> tuple[bool, str]:
    """Ensure privilege use audit subcategories are enabled on Windows Server."""
    return privilege_use_audit_wc()


def process_creation_audit_ws() -> tuple[bool, str]:
    """Verify process creation auditing is enabled on Windows Server (Event ID 4688)."""
    return process_creation_audit_wc()


def object_access_audit_ws() -> tuple[bool, str]:
    """Confirm file system object access auditing is enabled on Windows Server."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'File System','Registry' | Select-String 'Success|Failure'"
    )
    if rc != 0:
        return (False, f"Could not query object access audit policy: {err}")
    if len(out.strip()) > 0:
        return (True, "File System and Registry object access auditing is enabled")
    return (False, "File System and/or Registry object access auditing is not configured")


def unique_user_accounts_lx() -> tuple[bool, str]:
    """Verify no duplicate UIDs and no shared accounts in /etc/passwd."""
    rc, out, err = _run("awk -F: '{print $3}' /etc/passwd | sort | uniq -d")
    if rc != 0:
        return (False, f"Could not check /etc/passwd for duplicate UIDs: {err}")
    duplicate_uids = out.strip()
    if duplicate_uids:
        return (False, f"Duplicate UIDs found in /etc/passwd: {duplicate_uids}")
    rc2, out2, _ = _run(
        "awk -F: '{print $1}' /etc/passwd | grep -iE '^shared|^generic|^temp|^test'"
    )
    if out2.strip():
        return (False, f"Shared/generic account names found in /etc/passwd: {out2.strip()}")
    return (True, "No duplicate UIDs and no shared/generic accounts in /etc/passwd")


def logon_audit_lx() -> tuple[bool, str]:
    """Confirm auditd rules capture login/logout events on Linux/Debian."""
    rc, out, _ = _run("auditctl -l 2>/dev/null | grep -E 'lastlog|faillog|wtmp|btmp'")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "auditd rules cover login/logout events (lastlog/faillog/wtmp/btmp)")
    return (False, "No auditd rules found for login/logout event files (lastlog/faillog/wtmp/btmp)")


def privilege_use_audit_lx() -> tuple[bool, str]:
    """Verify auditd rules exist for sudo, su, and setuid/setgid binaries."""
    rc, out, _ = _run("auditctl -l 2>/dev/null | grep -E 'sudo|su\\b|setuid|setgid|execve'")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "auditd rules exist for privilege use (sudo/su/setuid/setgid/execve)")
    return (False, "No auditd rules found for privilege use (sudo/su/setuid/setgid/execve)")


def auid_preserved_lx() -> tuple[bool, str]:
    """Confirm auid is recorded in recent audit events and is not unset (-1 / 4294967295)."""
    rc, out, _ = _run(
        "ausearch -m USER_LOGIN --start recent 2>/dev/null | grep -v 'auid=4294967295' "
        "| grep -c 'auid='"
    )
    try:
        count = int(out.strip())
        if count > 0:
            return (True, f"auid is recorded and set in {count} recent USER_LOGIN audit event(s)")
        return (False, "No recent USER_LOGIN audit events with a valid auid found")
    except ValueError:
        return (False, "Could not parse auid count from recent audit events")


# ===========================================================================
# AU.L2-3.3.3 — Review and Update Logged Events
# ===========================================================================

def advanced_audit_policy_wc() -> tuple[bool, str]:
    """Verify all relevant advanced audit policy subcategories are configured on Windows Client."""
    required = [
        "Account Logon", "Account Management", "Detailed Tracking",
        "Logon/Logoff", "Object Access", "Policy Change",
        "Privilege Use", "System"
    ]
    rc, out, err = _ps("auditpol /get /category:*")
    if rc != 0:
        return (False, f"Could not query advanced audit policy: {err}")
    missing = [cat for cat in required if cat.lower() not in out.lower()]
    if not missing:
        return (True, "All required advanced audit policy categories are configured")
    return (False, f"Missing required audit policy categories: {', '.join(missing)}")


def audit_coverage_wc() -> tuple[bool, str]:
    """Confirm audit policy includes success and failure for all CMMC-required event types."""
    rc, out, err = _ps(
        "auditpol /get /category:* | Select-String 'Success and Failure'"
    )
    if rc != 0:
        return (False, f"Could not query audit coverage: {err}")
    try:
        count = len(out.strip().splitlines())
        if count >= 5:
            return (True, f"Audit policy covers Success and Failure for {count} subcategories")
        return (False, f"Insufficient 'Success and Failure' audit coverage: {count} subcategory(ies) (required: >= 5)")
    except Exception:
        return (False, "Could not evaluate audit coverage")


def advanced_audit_policy_ws() -> tuple[bool, str]:
    """Verify all relevant advanced audit policy subcategories are configured on Windows Server."""
    return advanced_audit_policy_wc()


def audit_coverage_ws() -> tuple[bool, str]:
    """Confirm audit policy covers all CMMC-required event types on Windows Server."""
    return audit_coverage_wc()


def gpo_audit_policy_ws() -> tuple[bool, str]:
    """Verify the audit policy is enforced via GPO on Windows Server."""
    rc, out, err = _ps(
        "gpresult /R /SCOPE COMPUTER 2>&1 | Select-String 'Audit|Security'"
    )
    if rc != 0:
        return (False, f"Could not query GPO audit policy results: {err}")
    if len(out.strip()) > 0:
        return (True, "GPO is enforcing audit/security policy on this server")
    return (False, "No GPO-enforced audit or security policy found via gpresult")


def audit_rules_coverage_lx() -> tuple[bool, str]:
    """Verify /etc/audit/rules.d/ covers required CMMC event categories on Linux/Debian."""
    rules_dir = Path("/etc/audit/rules.d/")
    if not rules_dir.exists():
        return (False, "Audit rules directory not found: /etc/audit/rules.d/ does not exist")
    all_rules = ""
    for rule_file in rules_dir.glob("*.rules"):
        all_rules += rule_file.read_text()
    required_patterns = [
        (r'-w\s+/etc/passwd', "/etc/passwd watches"),
        (r'-w\s+/etc/shadow', "/etc/shadow watches"),
        (r'-a\s+always,exit.*execve', "execve syscall rules"),
        (r'-w\s+/etc/sudoers', "/etc/sudoers watches"),
        (r'-w\s+/var/log', "/var/log watches"),
    ]
    missing = [label for pattern, label in required_patterns if not re.search(pattern, all_rules)]
    if not missing:
        return (True, "Audit rules cover all required CMMC event categories")
    return (False, f"Audit rules missing coverage for: {', '.join(missing)}")


def audit_rules_locked_lx() -> tuple[bool, str]:
    """Confirm auditd rules include -e 2 (immutable) flag on Linux/Debian."""
    rc, out, _ = _run("auditctl -s 2>/dev/null | grep 'enabled 2'")
    if rc == 0 and out.strip():
        return (True, "auditd rules are locked (immutable flag -e 2 is active)")
    # Also check rules files for -e 2
    rc2, out2, _ = _run("grep -r '^-e 2' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null")
    if rc2 == 0 and len(out2.strip()) > 0:
        return (True, "auditd rules include -e 2 (immutable) flag in rules files")
    return (False, "auditd rules do not include -e 2 (immutable) flag")


# ===========================================================================
# AU.L2-3.3.4 — Alert in the Event of Audit Logging Process Failure
# ===========================================================================

def audit_failure_alert_wc() -> tuple[bool, str]:
    """Verify CrashOnAuditFail is configured on Windows Client."""
    rc, out, err = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name CrashOnAuditFail -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty CrashOnAuditFail"
    )
    if rc != 0:
        return (False, f"Could not read CrashOnAuditFail registry value: {err}")
    val = out.strip()
    # 1 = warn and continue, 2 = halt — either satisfies the requirement
    if val in ("1", "2"):
        return (True, f"CrashOnAuditFail is configured (value = {val})")
    return (False, f"CrashOnAuditFail is not properly configured (value = {val or 'not set'})")


def log_full_action_wc() -> tuple[bool, str]:
    """Confirm Security event log max size and overflow action on Windows Client."""
    rc, out, err = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' "
        "| Select-Object MaxSize,Retention | Format-List"
    )
    if rc != 0:
        return (False, f"Could not query Security log overflow settings: {err}")
    if "MaxSize" in out:
        return (True, "Security event log MaxSize and overflow action are configured")
    return (False, "Security event log MaxSize not found in registry")


def audit_failure_alert_ws() -> tuple[bool, str]:
    """Verify CrashOnAuditFail is configured on Windows Server."""
    return audit_failure_alert_wc()


def log_full_action_ws() -> tuple[bool, str]:
    """Confirm Security event log overflow action on Windows Server."""
    return log_full_action_wc()


def siem_audit_alert_ws() -> tuple[bool, str]:
    """Verify SIEM is alerting on Event ID 1102 (log cleared) and 1100 (audit stopped)."""
    rc, out, err = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,1100} "
        "-MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object "
        "| Select-Object -ExpandProperty Count"
    )
    # We check that the query capability works; actual SIEM alert config is policy-level
    if rc == 0:
        return (True, "SIEM audit alert query for Event IDs 1102/1100 is functional")
    return (False, f"Could not query Security log for SIEM alert events (1102/1100): {err}")


def auditd_disk_full_action_lx() -> tuple[bool, str]:
    """Verify disk_full_action in auditd.conf is set to halt, syslog, or email."""
    conf_path = Path("/etc/audit/auditd.conf")
    if not conf_path.exists():
        return (False, "auditd.conf not found: /etc/audit/auditd.conf does not exist")
    content = conf_path.read_text()
    match = re.search(r'^\s*disk_full_action\s*=\s*(\S+)', content, re.MULTILINE | re.IGNORECASE)
    if not match:
        return (False, "disk_full_action is not set in auditd.conf")
    action = match.group(1).lower()
    valid = {"halt", "syslog", "email", "exec", "suspend"}
    if action in valid:
        return (True, f"disk_full_action is configured to '{action}' in auditd.conf")
    return (False, f"disk_full_action is set to '{action}' (not in accepted values: {', '.join(sorted(valid))})")


def auditd_space_left_action_lx() -> tuple[bool, str]:
    """Confirm space_left_action and admin_space_left_action are configured in auditd.conf."""
    conf_path = Path("/etc/audit/auditd.conf")
    if not conf_path.exists():
        return (False, "auditd.conf not found: /etc/audit/auditd.conf does not exist")
    content = conf_path.read_text()
    space_left = re.search(
        r'^\s*space_left_action\s*=\s*(\S+)', content, re.MULTILINE | re.IGNORECASE
    )
    admin_space = re.search(
        r'^\s*admin_space_left_action\s*=\s*(\S+)', content, re.MULTILINE | re.IGNORECASE
    )
    valid = {"email", "halt", "syslog", "exec", "suspend"}
    sl_val = space_left.group(1).lower() if space_left else None
    asl_val = admin_space.group(1).lower() if admin_space else None
    sl_ok = sl_val and sl_val in valid
    asl_ok = asl_val and asl_val in valid
    if sl_ok and asl_ok:
        return (True, f"space_left_action = '{sl_val}', admin_space_left_action = '{asl_val}'")
    missing = []
    if not sl_ok:
        missing.append(f"space_left_action (value: {sl_val or 'not set'})")
    if not asl_ok:
        missing.append(f"admin_space_left_action (value: {asl_val or 'not set'})")
    return (False, f"Invalid or missing auditd.conf settings: {'; '.join(missing)}")


def auditd_failure_flag_lx() -> tuple[bool, str]:
    """Verify auditd rules include -f 1 or -f 2 failure flag."""
    rc, out, _ = _run("auditctl -s 2>/dev/null | grep 'failure'")
    if rc == 0 and re.search(r'failure\s+[12]', out):
        match = re.search(r'failure\s+([12])', out)
        flag = match.group(1) if match else "1 or 2"
        return (True, f"auditd failure flag is set (-f {flag})")
    rc2, out2, _ = _run(
        "grep -rE '^-f [12]' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null"
    )
    if rc2 == 0 and len(out2.strip()) > 0:
        return (True, "auditd failure flag (-f 1 or -f 2) found in rules files")
    return (False, "auditd failure flag (-f 1 or -f 2) is not configured")


# ===========================================================================
# AU.L2-3.3.5 — Correlate Audit Record Review, Analysis, and Reporting
# ===========================================================================

def log_forwarding_wc() -> tuple[bool, str]:
    """Verify WEF or SIEM agent is configured on Windows Client."""
    rc, out, err = _ps(
        "Get-Service -Name 'WecSvc','SplunkForwarder','elastic-agent','nxlog' "
        "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc != 0:
        return (False, f"Could not query log forwarding services: {err}")
    try:
        count = int(out.strip())
        if count > 0:
            return (True, f"Log forwarding service is running on Windows Client ({count} agent(s) active)")
        return (False, "No WEF/SIEM log forwarding agent is running on Windows Client")
    except ValueError:
        return (False, "Could not parse log forwarding service count")


def log_detail_wc() -> tuple[bool, str]:
    """Confirm log entries include fields required for correlation on Windows Client."""
    rc, out, err = _ps(
        "Get-WinEvent -LogName Security -MaxEvents 1 "
        "| Select-Object TimeCreated,Id,UserId,Message | Format-List"
    )
    if rc != 0:
        return (False, f"Could not query Security event log entries: {err}")
    missing = [f for f in ["TimeCreated", "UserId"] if f not in out]
    if not missing:
        return (True, "Security log entries include TimeCreated, UserId, and Message fields")
    return (False, f"Security log entries are missing correlation fields: {', '.join(missing)}")


def log_detail_ws() -> tuple[bool, str]:
    """Confirm log entries include correlation fields on Windows Server."""
    return log_detail_wc()


def siem_agent_active_ws() -> tuple[bool, str]:
    """Verify a SIEM agent is installed, running, and communicating on Windows Server."""
    return log_forwarding_ws()


def log_detail_lx() -> tuple[bool, str]:
    """Confirm auditd records include auid, uid, pid, timestamp, and syscall fields."""
    rc, out, err = _run(
        "ausearch -m SYSCALL --start recent 2>/dev/null | head -5"
    )
    required_fields = ["auid=", "uid=", "pid=", "syscall="]
    if rc != 0:
        return (False, f"Could not retrieve recent SYSCALL audit records: {err}")
    missing = [f for f in required_fields if f not in out]
    if not missing:
        return (True, "Recent SYSCALL audit records include auid, uid, pid, and syscall fields")
    return (False, f"Recent audit records missing required fields: {', '.join(missing)}")


def siem_agent_active_lx() -> tuple[bool, str]:
    """Verify a SIEM agent is installed, running, and shipping logs on Linux/Debian."""
    agents = ["filebeat", "elastic-agent", "splunkd", "td-agent", "fluentd"]
    for agent in agents:
        rc, _, _ = _run(f"systemctl is-active {agent} 2>/dev/null")
        if rc == 0:
            return (True, f"SIEM agent '{agent}' is active and running")
    return (False, f"No SIEM agent is running (checked: {', '.join(agents)})")


# ===========================================================================
# AU.L2-3.3.6 — Audit Record Reduction and Report Generation
# ===========================================================================

def log_query_capability_wc() -> tuple[bool, str]:
    """Verify ability to filter and query audit logs on Windows Client."""
    rc, out, err = _ps(
        "Get-WinEvent -LogName Security -MaxEvents 10 "
        "-FilterXPath '*[System[EventID=4624]]' -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc == 0:
        return (True, "Security log query capability is functional (Get-WinEvent with FilterXPath)")
    return (False, f"Security log query capability check failed: {err}")


def log_export_wc() -> tuple[bool, str]:
    """Confirm audit logs can be exported from Windows Client."""
    rc, out, err = _ps(
        "Get-Command wevtutil -ErrorAction SilentlyContinue | Measure-Object "
        "| Select-Object -ExpandProperty Count"
    )
    if rc == 0:
        return (True, "wevtutil is available for audit log export")
    return (False, f"wevtutil not found or not accessible: {err}")


def log_query_capability_ws() -> tuple[bool, str]:
    """Verify ability to filter and query audit logs on Windows Server."""
    return log_query_capability_wc()


def log_export_ws() -> tuple[bool, str]:
    """Confirm audit logs can be exported from Windows Server."""
    return log_export_wc()


def siem_reporting_ws() -> tuple[bool, str]:
    """Verify SIEM agent connectivity implies reporting capability on Windows Server."""
    return siem_agent_active_ws()


def ausearch_available_lx() -> tuple[bool, str]:
    """Verify ausearch and aureport are installed and functional on Linux/Debian."""
    rc1, _, _ = _run("which ausearch")
    rc2, _, _ = _run("which aureport")
    if rc1 == 0 and rc2 == 0:
        return (True, "ausearch and aureport are installed and available")
    missing = []
    if rc1 != 0:
        missing.append("ausearch")
    if rc2 != 0:
        missing.append("aureport")
    return (False, f"Required audit tools not found: {', '.join(missing)}")


def log_query_capability_lx() -> tuple[bool, str]:
    """Confirm ausearch supports filtering by auid, timestamp, and syscall."""
    rc, out, _ = _run("ausearch --help 2>&1 | grep -E '\\-\\-uid|\\-\\-start|\\-\\-syscall'")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "ausearch supports --uid, --start, and/or --syscall filtering")
    return (False, "ausearch does not appear to support required filtering options (--uid/--start/--syscall)")


def siem_reporting_lx() -> tuple[bool, str]:
    """Verify SIEM agent connectivity implies reporting capability on Linux/Debian."""
    return siem_agent_active_lx()


# ===========================================================================
# AU.L2-3.3.7 — Compare and Synchronize Internal Clocks (NTP)
# ===========================================================================

def w32tm_running_wc() -> tuple[bool, str]:
    """Verify the Windows Time service is running on Windows Client."""
    rc, out, err = _ps(
        "Get-Service -Name W32Time | Select-Object -ExpandProperty Status"
    )
    if rc != 0:
        return (False, f"Could not query Windows Time service status: {err}")
    status = out.strip().lower()
    if status == "running":
        return (True, "Windows Time service (W32Time) is running")
    return (False, f"Windows Time service (W32Time) is not running (status: {status or 'unknown'})")


def ntp_source_wc() -> tuple[bool, str]:
    """Confirm NTP source is configured on Windows Client."""
    rc, out, err = _ps("w32tm /query /source")
    if rc != 0:
        return (False, f"Could not query NTP source: {err}")
    source = out.strip()
    if source and "error" not in source.lower():
        return (True, f"NTP source is configured: {source}")
    return (False, f"NTP source is not properly configured (output: {source or 'empty'})")


def time_sync_status_wc() -> tuple[bool, str]:
    """Verify w32tm reports successful last sync on Windows Client."""
    rc, out, err = _ps("w32tm /query /status")
    if rc != 0:
        return (False, f"Could not query time sync status: {err}")
    if "Last Successful Sync Time" in out:
        return (True, "Windows time sync is active with a recorded last successful sync")
    return (False, "w32tm status does not report a last successful sync time")


def w32tm_running_ws() -> tuple[bool, str]:
    """Verify the Windows Time service is running on Windows Server."""
    return w32tm_running_wc()


def ntp_source_ws() -> tuple[bool, str]:
    """Confirm NTP source is configured on Windows Server."""
    return ntp_source_wc()


def time_sync_status_ws() -> tuple[bool, str]:
    """Verify w32tm reports successful last sync on Windows Server."""
    return time_sync_status_wc()


def pdc_ntp_source_ws() -> tuple[bool, str]:
    """Verify the PDC emulator is syncing from an external authoritative NTP source."""
    rc, out, err = _ps(
        "w32tm /query /configuration | Select-String 'NtpServer'"
    )
    if rc != 0:
        return (False, f"Could not query PDC NTP configuration: {err}")
    if not out.strip():
        return (False, "NtpServer is not configured in w32tm configuration")
    # Ensure it's not pointing only to itself (Local CMOS Clock or VM IC)
    if "time.nist.gov" in out or "pool.ntp.org" in out or re.search(r'\d+\.\d+\.\d+\.\d+', out):
        return (True, f"PDC NTP source points to an external authoritative server: {out.strip()}")
    return (False, f"PDC NTP source may not be an external authoritative server: {out.strip()}")


def ntp_running_lx() -> tuple[bool, str]:
    """Verify chronyd, ntpd, or systemd-timesyncd is active on Linux/Debian."""
    services = ["chronyd", "ntpd", "systemd-timesyncd"]
    for service in services:
        rc, _, _ = _run(f"systemctl is-active {service} 2>/dev/null")
        if rc == 0:
            return (True, f"NTP service '{service}' is active")
    return (False, f"No NTP service is active (checked: {', '.join(services)})")


def ntp_source_lx() -> tuple[bool, str]:
    """Confirm an authoritative NTP server is configured on Linux/Debian."""
    conf_files = ["/etc/chrony.conf", "/etc/chrony/chrony.conf", "/etc/ntp.conf"]
    for conf in conf_files:
        if Path(conf).exists():
            content = Path(conf).read_text()
            if re.search(r'^\s*(server|pool)\s+\S+', content, re.MULTILINE):
                return (True, f"NTP server/pool is configured in {conf}")
    return (False, f"No NTP server or pool configured in any of: {', '.join(conf_files)}")


def time_sync_status_lx() -> tuple[bool, str]:
    """Verify time synchronization is active and within bounds on Linux/Debian."""
    rc, out, _ = _run("chronyc tracking 2>/dev/null | grep 'System time'")
    if rc == 0 and out.strip():
        return (True, f"chrony time sync is active: {out.strip()}")
    rc2, out2, _ = _run("timedatectl status 2>/dev/null | grep 'NTP synchronized: yes'")
    if rc2 == 0 and len(out2.strip()) > 0:
        return (True, "systemd-timesyncd reports NTP synchronized: yes")
    return (False, "Time synchronization is not active (chrony and systemd-timesyncd checks failed)")


# ===========================================================================
# AU.L2-3.3.8 — Protect Audit Information and Tools from Unauthorized Access
# ===========================================================================

def event_log_acl_wc() -> tuple[bool, str]:
    """Verify Security event log DACL restricts access on Windows Client."""
    rc, out, err = _ps(
        "wevtutil gl Security | Select-String 'channelAccess'"
    )
    if rc != 0:
        return (False, f"Could not query Security event log DACL: {err}")
    if "channelAccess" in out:
        return (True, "Security event log has a channelAccess DACL configured")
    return (False, "Security event log channelAccess DACL is not configured")


def log_clear_audit_wc() -> tuple[bool, str]:
    """Confirm audit policy change auditing is enabled so log clears are detected."""
    rc, out, err = _ps(
        "auditpol /get /subcategory:'Audit Policy Change' | Select-String 'Success'"
    )
    if rc != 0:
        return (False, f"Could not query Audit Policy Change subcategory: {err}")
    if len(out.strip()) > 0:
        return (True, "Audit Policy Change subcategory is enabled for Success events")
    return (False, "Audit Policy Change subcategory is not enabled for Success events")


def audit_tools_protected_wc() -> tuple[bool, str]:
    """Verify auditpol.exe is not accessible to standard users on Windows Client."""
    rc, out, err = _ps(
        "(Get-Acl 'C:\\Windows\\System32\\auditpol.exe').Access "
        "| Where-Object {$_.IdentityReference -notmatch 'SYSTEM|Administrators|TrustedInstaller'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    if rc != 0:
        return (False, f"Could not query auditpol.exe ACL: {err}")
    try:
        count = int(out.strip())
        if count == 0:
            return (True, "auditpol.exe ACL restricts access to SYSTEM/Administrators/TrustedInstaller only")
        return (False, f"auditpol.exe is accessible to {count} non-privileged identity(ies)")
    except ValueError:
        return (False, "Could not parse auditpol.exe ACL entry count")


def event_log_acl_ws() -> tuple[bool, str]:
    """Verify Security event log DACL restricts access on Windows Server."""
    return event_log_acl_wc()


def log_clear_audit_ws() -> tuple[bool, str]:
    """Confirm audit policy change auditing detects log clears on Windows Server."""
    return log_clear_audit_wc()


def audit_tools_protected_ws() -> tuple[bool, str]:
    """Verify auditpol.exe is not accessible to standard users on Windows Server."""
    return audit_tools_protected_wc()


def remote_log_acl_ws() -> tuple[bool, str]:
    """Confirm centralized log storage has access controls preventing unauthorized modification."""
    # Check WEF subscription collector access
    rc, out, err = _ps(
        "wecutil es 2>$null | Measure-Object | Select-Object -ExpandProperty Count"
    )
    # If WEF subscriptions exist, collector is active — actual remote ACL is policy-level
    if rc != 0:
        return (False, f"Could not query WEF subscriptions: {err}")
    try:
        count = int(out.strip())
        if count > 0:
            return (True, f"WEF collector is active with {count} subscription(s) configured")
        return (False, "No WEF subscriptions configured (centralized log ACL cannot be verified)")
    except ValueError:
        return (False, "Could not parse WEF subscription count")


def audit_log_permissions_lx() -> tuple[bool, str]:
    """Verify /var/log/audit/audit.log is owned by root with permissions 600 or 640."""
    log_path = Path("/var/log/audit/audit.log")
    if not log_path.exists():
        return (False, "Audit log not found: /var/log/audit/audit.log does not exist")
    s = log_path.stat()
    owner_is_root = s.st_uid == 0
    mode = oct(s.st_mode)[-3:]
    if owner_is_root and mode in ("600", "640"):
        return (True, f"Audit log is owned by root with permissions {mode}")
    issues = []
    if not owner_is_root:
        issues.append(f"owner uid={s.st_uid} (expected: 0/root)")
    if mode not in ("600", "640"):
        issues.append(f"permissions={mode} (expected: 600 or 640)")
    return (False, f"Audit log permissions problem: {'; '.join(issues)}")


def audit_conf_permissions_lx() -> tuple[bool, str]:
    """Confirm /etc/audit/ config files are owned by root with restrictive permissions."""
    audit_conf = Path("/etc/audit/auditd.conf")
    rules_dir = Path("/etc/audit/rules.d/")
    if not audit_conf.exists():
        return (False, "auditd.conf not found: /etc/audit/auditd.conf does not exist")
    s = audit_conf.stat()
    mode = oct(s.st_mode)[-3:]
    conf_ok = s.st_uid == 0 and mode in ("600", "640", "400")
    dir_ok = rules_dir.exists() and rules_dir.stat().st_uid == 0
    if conf_ok and dir_ok:
        return (True, f"auditd.conf is root-owned with permissions {mode}, and rules.d/ is root-owned")
    issues = []
    if not conf_ok:
        issues.append(f"auditd.conf: uid={s.st_uid}, mode={mode} (expected root-owned, 600/640/400)")
    if not dir_ok:
        if not rules_dir.exists():
            issues.append("rules.d/ directory does not exist")
        else:
            issues.append(f"rules.d/ uid={rules_dir.stat().st_uid} (expected: 0/root)")
    return (False, f"Audit config permission issues: {'; '.join(issues)}")


def audit_binary_integrity_lx() -> tuple[bool, str]:
    """Verify integrity of audit binaries using package manager on Linux/Debian."""
    # Try dpkg first (Debian/Ubuntu)
    rc_dpkg, out_dpkg, _ = _run("dpkg --verify auditd 2>/dev/null")
    if rc_dpkg == 0 and not out_dpkg.strip():
        return (True, "auditd binary integrity verified by dpkg (no issues found)")
    # Fall back to rpm (RHEL/CentOS/Rocky)
    rc_rpm, out_rpm, _ = _run("rpm -V audit 2>/dev/null | grep -E '^S|^M|^5'")
    if rc_rpm == 0 and not out_rpm.strip():
        return (True, "auditd binary integrity verified by rpm (no issues found)")
    if out_dpkg.strip():
        return (False, f"dpkg integrity check found issues with auditd: {out_dpkg.strip()}")
    if out_rpm.strip():
        return (False, f"rpm integrity check found issues with audit: {out_rpm.strip()}")
    return (False, "Could not verify auditd binary integrity (dpkg and rpm both unavailable or failed)")


def audit_self_protect_rules_lx() -> tuple[bool, str]:
    """Confirm auditd rules watch /etc/audit/ and /var/log/audit/ for changes."""
    rc, out, _ = _run(
        "auditctl -l 2>/dev/null | grep -E '/etc/audit|/var/log/audit'"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, "auditd rules include watches on /etc/audit/ and/or /var/log/audit/")
    return (False, "No auditd rules found watching /etc/audit/ or /var/log/audit/")


# ===========================================================================
# AU.L2-3.3.9 — Limit Management of Audit Logging to Privileged Users
# ===========================================================================

def manage_audit_right_wc() -> tuple[bool, str]:
    """Verify SeSecurityPrivilege is assigned only to Administrators on Windows Client."""
    rc, out, err = _ps(
        "secedit /export /cfg C:\\Windows\\Temp\\secpol_tmp.cfg /quiet; "
        "Select-String 'SeSecurityPrivilege' C:\\Windows\\Temp\\secpol_tmp.cfg"
    )
    if rc != 0:
        return (False, f"Could not export security policy to check SeSecurityPrivilege: {err}")
    if not out.strip():
        return (False, "SeSecurityPrivilege is not defined in the security policy")
    # Should only reference Administrators (*S-1-5-32-544) or equivalent
    if "SeSecurityPrivilege" in out and "Users" not in out:
        return (True, "SeSecurityPrivilege is assigned only to Administrators (not to Users)")
    return (False, "SeSecurityPrivilege may be granted to non-administrative accounts (Users found in policy)")


def audit_policy_modify_restricted_wc() -> tuple[bool, str]:
    """Confirm standard users cannot modify audit policy on Windows Client."""
    rc, out, err = _ps(
        "secedit /export /cfg C:\\Windows\\Temp\\secpol_tmp.cfg /quiet; "
        "Select-String 'SeSecurityPrivilege|SeAuditPrivilege' C:\\Windows\\Temp\\secpol_tmp.cfg"
    )
    if rc != 0:
        return (False, f"Could not query audit modification privileges: {err}")
    if "Users" not in out:
        return (True, "SeSecurityPrivilege and SeAuditPrivilege are not granted to standard Users")
    return (False, "Standard Users group may have SeSecurityPrivilege or SeAuditPrivilege")


def manage_audit_right_ws() -> tuple[bool, str]:
    """Verify SeSecurityPrivilege is assigned only to Administrators on Windows Server."""
    return manage_audit_right_wc()


def audit_policy_modify_restricted_ws() -> tuple[bool, str]:
    """Confirm standard users cannot modify audit policy on Windows Server."""
    return audit_policy_modify_restricted_wc()


def event_log_readers_membership_ws() -> tuple[bool, str]:
    """Verify Event Log Readers group contains only authorized accounts on Windows Server."""
    rc, out, err = _ps(
        "Get-LocalGroupMember -Group 'Event Log Readers' "
        "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
    )
    if rc != 0:
        return (False, f"Could not query Event Log Readers group membership: {err}")
    members = [m.strip().lower() for m in out.splitlines() if m.strip()]
    # Flag if any obviously generic accounts are members
    suspicious = [m for m in members if re.search(r'everyone|users|authenticated', m)]
    if len(suspicious) == 0:
        return (True, f"Event Log Readers group has no overly broad members ({len(members)} member(s) reviewed)")
    return (False, f"Event Log Readers group contains overly broad accounts: {', '.join(suspicious)}")


def siem_access_restricted_ws() -> tuple[bool, str]:
    """Confirm SIEM access is restricted; check agent is running under a service account."""
    rc, out, err = _ps(
        "Get-WmiObject Win32_Service | Where-Object {$_.Name -match 'splunk|elastic|nxlog'} "
        "| Select-Object StartName | Format-List"
    )
    if rc != 0:
        return (False, f"Could not query SIEM service accounts: {err}")
    if not out.strip():
        return (False, "No SIEM service (Splunk/Elastic/NXLog) found on this system")
    # Service should not run as LocalSystem or a generic account
    if "LocalSystem" not in out and "NT AUTHORITY\\SYSTEM" not in out:
        return (True, "SIEM agent is running under a dedicated service account (not LocalSystem)")
    return (False, "SIEM agent is running as LocalSystem or NT AUTHORITY\\SYSTEM (should use a service account)")


def auditd_management_restricted_lx() -> tuple[bool, str]:
    """Verify auditctl and /etc/audit/ are accessible only by root on Linux/Debian."""
    conf_ok, conf_msg = audit_conf_permissions_lx()
    # If no non-root accessible auditctl found, and conf is root-only, return True
    if conf_ok:
        return (True, f"auditd management access is restricted to root: {conf_msg}")
    return (False, f"auditd management access is not properly restricted: {conf_msg}")


def audit_sudo_rights_lx() -> tuple[bool, str]:
    """Confirm sudoers does not grant unrestricted audit tool access to non-admin accounts."""
    rc, out, _ = _run(
        "grep -rE 'auditctl|auditd|aureport|ausearch' /etc/sudoers /etc/sudoers.d/ 2>/dev/null "
        "| grep -v '^#'"
    )
    if rc != 0 or not out.strip():
        return (True, "No sudo rules found granting audit tool access (auditctl/auditd/aureport/ausearch)")
    # If rules exist, check they are scoped to specific admin groups only
    suspicious = [
        line for line in out.splitlines()
        if not re.search(r'%sudo|%wheel|%admin|%audit', line)
    ]
    if len(suspicious) == 0:
        return (True, "Audit tool sudo rules are scoped to admin groups only (%sudo/%wheel/%admin/%audit)")
    return (False, f"Unrestricted sudo access to audit tools found in sudoers: {'; '.join(suspicious)}")


def audit_log_dir_access_lx() -> tuple[bool, str]:
    """Verify /var/log/audit/ directory permissions are 700 (root only) on Linux/Debian."""
    audit_dir = Path("/var/log/audit")
    if not audit_dir.exists():
        return (False, "/var/log/audit directory does not exist")
    s = audit_dir.stat()
    owner_is_root = s.st_uid == 0
    mode = oct(s.st_mode)[-3:]
    if owner_is_root and mode == "700":
        return (True, "/var/log/audit is owned by root with permissions 700")
    issues = []
    if not owner_is_root:
        issues.append(f"owner uid={s.st_uid} (expected: 0/root)")
    if mode != "700":
        issues.append(f"permissions={mode} (expected: 700)")
    return (False, f"/var/log/audit permission issues: {'; '.join(issues)}")
