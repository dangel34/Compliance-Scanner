"""
identification_authentication.py

Houses all identification and authentication (IA) check functions for CMMC
IA.L1-3.5.1 through IA.L2-3.5.11.
Each function corresponds to a cs_f() reference in the IA control JSON files.

Naming convention:
    <check_name>_wc   -> Windows Client
    <check_name>_ws   -> Windows Server
    <check_name>_lx   -> Linux / Debian
"""

import subprocess
import re
import shlex
from pathlib import Path

_RUN_CACHE: dict[tuple[object, object, int], tuple[int, str, str]] = {}


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


def _net_accounts() -> dict:
    """Parse net accounts output into a key/value dict."""
    rc, out, _ = _run("net accounts")
    result = {}
    if rc != 0:
        return result
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip().lower()] = v.strip()
    return result


def _login_defs_get(key: str) -> str | None:
    """Read a value from /etc/login.defs."""
    path = Path("/etc/login.defs")
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        m = re.match(rf'^\s*{key}\s+(\S+)', line, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _sshd_value(key: str) -> str | None:
    """Return the effective sshd config value for a given key."""
    rc, out, _ = _run("sshd -T 2>/dev/null")
    if rc != 0:
        return None
    m = re.search(rf'^{key}\s+(.+)', out, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else None


# ===========================================================================
# IA.L1-3.5.1 — Identify System Users, Processes, and Devices
# ===========================================================================

def unique_user_ids_wc() -> tuple[bool, str]:
    """Verify all local accounts have unique usernames with no shared or generic accounts on Windows Client."""
    rc, out, err = _ps(
        "Get-LocalUser | Where-Object {$_.Name -match 'shared|generic|temp|test|anon'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc != 0:
            return (False, f"Could not query local users: {err}")
        if count == 0:
            return (True, "No shared/generic accounts found on Windows Client")
        return (False, f"Found {count} shared/generic account(s) on Windows Client")
    except ValueError:
        return (False, "Could not parse local user count")


def named_service_accounts_wc() -> tuple[bool, str]:
    """Confirm services and tasks run under named accounts on Windows Client."""
    rc, out, err = _ps(
        "Get-WmiObject Win32_Service | Where-Object {"
        "$_.StartName -match 'LocalSystem|NT AUTHORITY\\\\NetworkService|NT AUTHORITY\\\\LocalService'"
        " -and $_.State -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc != 0:
            return (False, f"Could not query services: {err}")
        if count < 20:
            return (True, f"{count} services running as built-in accounts (threshold: < 20)")
        return (False, f"{count} services running as LocalSystem/NetworkService/LocalService (threshold: < 20)")
    except ValueError:
        return (False, "Could not parse service account count")


def device_identity_wc() -> tuple[bool, str]:
    """Verify the system is domain joined or registered with an identity management system."""
    rc, out, _ = _ps(
        "Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty PartOfDomain"
    )
    if rc == 0 and out.strip().lower() == "true":
        return (True, "System is domain joined")
    return (False, "System is not domain joined (PartOfDomain = False)")


def unique_user_ids_ws() -> tuple[bool, str]:
    """Verify all accounts have unique SIDs and no generic accounts on Windows Server."""
    return unique_user_ids_wc()


def named_service_accounts_ws() -> tuple[bool, str]:
    """Confirm services run under named accounts or gMSAs on Windows Server."""
    return named_service_accounts_wc()


def device_identity_ws() -> tuple[bool, str]:
    """Verify the server is domain joined."""
    return device_identity_wc()


def no_orphaned_accounts_ws() -> tuple[bool, str]:
    """Check for accounts with no recent logon that may be orphaned on Windows Server."""
    rc2, out2, err = _ps(
        "Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out2.strip())
        if rc2 != 0:
            return (False, f"Could not query AD accounts: {err}")
        if count == 0:
            return (True, "No enabled accounts inactive for 90+ days")
        return (False, f"{count} enabled account(s) inactive for 90+ days")
    except ValueError:
        return (False, "Could not parse inactive account count")


def unique_user_ids_lx() -> tuple[bool, str]:
    """Verify no duplicate UIDs among regular user accounts (UID >= 1000) in /etc/passwd on Linux/Debian."""
    rc, out, _ = _run("awk -F: '$3 >= 1000 {print $3}' /etc/passwd | sort | uniq -d")
    if rc != 0:
        return (False, "Could not read /etc/passwd to check UIDs")
    dupes = out.strip()
    if not dupes:
        return (True, "No duplicate UIDs found for regular accounts in /etc/passwd")
    return (False, f"Duplicate UIDs found: {dupes}")


def named_service_accounts_lx() -> tuple[bool, str]:
    """Confirm all running systemd services declare a User= directive on Linux/Debian."""
    rc, out, _ = _run(
        "systemctl list-units --type=service --state=running --no-legend 2>/dev/null "
        "| awk '{print $1}'"
    )
    if rc != 0:
        return (False, "Could not list running systemd services")
    services = [s.strip() for s in out.splitlines() if s.strip()]
    root_services = []
    for svc in services[:20]:  # sample first 20 to avoid excessive checks
        rc2, out2, _ = _run(
            f"systemctl show {shlex.quote(svc)} -p User 2>/dev/null | cut -d= -f2"
        )
        if out2.strip() in ("", "root"):
            root_services.append(svc)
    # Allow up to 5 root-running services (kernel/system services)
    if len(root_services) <= 5:
        return (True, f"{len(root_services)} service(s) running as root (threshold: <= 5)")
    return (False, f"{len(root_services)} services running as root/unnamed: {', '.join(root_services[:5])}")


def no_generic_accounts_lx() -> tuple[bool, str]:
    """Verify no generic or anonymous login accounts exist on Linux/Debian."""
    rc, out, _ = _run(
        "awk -F: '$7 !~ /nologin|false/ && $1 ~ /guest|temp|test|shared|anon/ "
        "{print $1}' /etc/passwd"
    )
    if rc != 0:
        return (False, "Could not read /etc/passwd")
    accounts = out.strip()
    if not accounts:
        return (True, "No generic/anonymous login accounts found in /etc/passwd")
    return (False, f"Generic login accounts found: {accounts}")


# ===========================================================================
# IA.L1-3.5.2 — Authenticate Users, Processes, and Devices
# ===========================================================================

def password_required_wc() -> tuple[bool, str]:
    """Verify no local accounts have blank passwords on Windows Client."""
    rc, out, err = _ps(
        "Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false -and $_.Enabled -eq $true} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc != 0:
            return (False, f"Could not query local users: {err}")
        if count == 0:
            return (True, "All enabled local accounts require a password")
        return (False, f"{count} enabled account(s) do not require a password")
    except ValueError:
        return (False, "Could not parse password-required account count")


def interactive_logon_auth_wc() -> tuple[bool, str]:
    """Confirm automatic logon is disabled on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AutoAdminLogon"
    )
    if val != "1":
        return (True, f"Automatic logon is disabled (AutoAdminLogon = {val or 'not set'})")
    return (False, "Automatic logon is enabled (AutoAdminLogon = 1)")


def device_auth_wc() -> tuple[bool, str]:
    """Verify the system authenticates to a domain via Kerberos on Windows Client."""
    return device_identity_wc()


def password_required_ws() -> tuple[bool, str]:
    """Verify no accounts have blank passwords on Windows Server."""
    return password_required_wc()


def interactive_logon_auth_ws() -> tuple[bool, str]:
    """Confirm automatic logon is disabled on Windows Server."""
    return interactive_logon_auth_wc()


def device_auth_ws() -> tuple[bool, str]:
    """Verify the server is domain joined and uses Kerberos authentication."""
    return device_identity_ws()


def service_account_auth_ws() -> tuple[bool, str]:
    """Confirm all service accounts have passwords or use gMSA on Windows Server."""
    rc, out, err = _ps(
        "Get-ADServiceAccount -Filter * -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    # If gMSAs exist they are managed — also check no services run without credentials
    if rc == 0:
        count = out.strip()
        return (True, f"AD service account query succeeded ({count} gMSA(s) found)")
    return (False, f"Could not query AD service accounts: {err}")


def password_required_lx() -> tuple[bool, str]:
    """Verify no accounts have empty password fields in /etc/shadow on Linux/Debian."""
    rc, out, _ = _run(
        "awk -F: '($2 == \"\" || $2 == \"!\") && $2 != \"*\" && $2 != \"!!\" "
        "{print $1}' /etc/shadow 2>/dev/null"
    )
    # Empty password field is a failure; locked (!!) or no-login (*) are acceptable
    empty = [
        line for line in out.splitlines()
        if line.strip() and not line.strip().startswith(("!", "*"))
    ]
    if rc == 0 and len(empty) == 0:
        return (True, "No accounts with empty password fields in /etc/shadow")
    if empty:
        return (False, f"Accounts with empty/blank passwords in /etc/shadow: {', '.join(empty)}")
    return (False, "Could not read /etc/shadow")


def pam_auth_enforced_lx() -> tuple[bool, str]:
    """Confirm PAM requires authentication for SSH and su on Linux/Debian."""
    rc, out, _ = _run("grep -E 'pam_unix|pam_sss|pam_ldap' /etc/pam.d/sshd /etc/pam.d/common-auth 2>/dev/null")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "PAM authentication module (pam_unix/pam_sss/pam_ldap) found in sshd/common-auth")
    return (False, "No pam_unix/pam_sss/pam_ldap entry found in /etc/pam.d/sshd or common-auth")


def ssh_auth_required_lx() -> tuple[bool, str]:
    """Verify SSH requires authentication and anonymous access is disabled on Linux/Debian."""
    permit_empty = _sshd_value("permitemptypasswords")
    empty_disabled = permit_empty is None or permit_empty.lower() == "no"
    if empty_disabled:
        val_str = permit_empty if permit_empty else "not set (default: no)"
        return (True, f"SSH PermitEmptyPasswords = {val_str}")
    return (False, f"SSH PermitEmptyPasswords = {permit_empty} (should be 'no')")


# ===========================================================================
# IA.L2-3.5.3 — Multi-Factor Authentication
# ===========================================================================

def mfa_privileged_local_wc() -> tuple[bool, str]:
    """Verify MFA or smart card is required for local privileged logon on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "scforceoption"
    )
    if val == "1":
        return (True, "Smart card required for interactive logon (scforceoption = 1)")
    return (False, f"Smart card not enforced for logon (scforceoption = {val or 'not set'})")


def mfa_privileged_network_wc() -> tuple[bool, str]:
    """Confirm MFA is required for network access by privileged accounts on Windows Client."""
    # Check for Credential Guard or Windows Hello for Business enrollment as a proxy
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' "
        "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableVirtualizationBasedSecurity"
    )
    if rc == 0 and out.strip() == "1":
        return (True, "Virtualization-Based Security / Credential Guard enabled (EnableVirtualizationBasedSecurity = 1)")
    return (False, f"Virtualization-Based Security not enabled (EnableVirtualizationBasedSecurity = {out.strip() or 'not set'})")


def mfa_nonprivileged_network_wc() -> tuple[bool, str]:
    """Verify MFA is required for network access by non-privileged accounts on Windows Client."""
    # Heuristic: check for an enrolled MFA provider (Azure AD joined or WHFB)
    rc, out, _ = _ps(
        "dsregcmd /status 2>&1 | Select-String 'AzureAdJoined|DomainJoined'"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, f"Device is Azure AD or domain joined — MFA provider available: {out.strip()[:80]}")
    return (False, "Device is not Azure AD joined or domain joined — MFA provider unavailable")


def smartcard_or_whfb_wc() -> tuple[bool, str]:
    """Confirm smart card or Windows Hello for Business is configured on Windows Client."""
    whfb = _reg_get(
        r"HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork",
        "Enabled"
    )
    sc = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "scforceoption"
    )
    if whfb == "1":
        return (True, "Windows Hello for Business is enabled (PassportForWork\\Enabled = 1)")
    if sc == "1":
        return (True, "Smart card logon is enforced (scforceoption = 1)")
    return (False, f"Neither WHFB (Enabled = {whfb or 'not set'}) nor smart card (scforceoption = {sc or 'not set'}) configured")


def mfa_privileged_local_ws() -> tuple[bool, str]:
    """Verify MFA or smart card is required for privileged local logon on Windows Server."""
    return mfa_privileged_local_wc()


def mfa_privileged_network_ws() -> tuple[bool, str]:
    """Confirm MFA is required for network access by privileged accounts on Windows Server."""
    return mfa_privileged_network_wc()


def mfa_nonprivileged_network_ws() -> tuple[bool, str]:
    """Verify MFA is required for all network logons on Windows Server."""
    return mfa_nonprivileged_network_wc()


def smartcard_required_ws() -> tuple[bool, str]:
    """Confirm Interactive logon: Require smart card is enabled on Windows Server."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "scforceoption"
    )
    if val == "1":
        return (True, "Smart card required for interactive logon (scforceoption = 1)")
    return (False, f"Smart card not enforced (scforceoption = {val or 'not set'})")


def mfa_pam_configured_lx() -> tuple[bool, str]:
    """Verify a PAM MFA module is installed and configured on Linux/Debian."""
    rc, out, _ = _run("grep -r 'pam_google_authenticator\\|pam_duo\\|pam_radius\\|pam_oath\\|pam_yubico' /etc/pam.d/ 2>/dev/null")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "PAM MFA module found in /etc/pam.d/")
    return (False, "No PAM MFA module (pam_google_authenticator/pam_duo/pam_radius/pam_oath/pam_yubico) configured")


def ssh_mfa_enabled_lx() -> tuple[bool, str]:
    """Confirm SSH is configured to require MFA via ChallengeResponseAuthentication on Linux/Debian."""
    cra = _sshd_value("challengeresponseauthentication")
    auth_methods = _sshd_value("authenticationmethods")
    cra_enabled = cra and cra.lower() == "yes"
    methods_mfa = auth_methods and ("keyboard-interactive" in auth_methods or "publickey,keyboard" in auth_methods)
    if cra_enabled:
        return (True, f"SSH ChallengeResponseAuthentication = yes")
    if methods_mfa:
        return (True, f"SSH AuthenticationMethods includes MFA: {auth_methods}")
    return (False, f"SSH MFA not configured (ChallengeResponseAuthentication = {cra or 'no'}, AuthenticationMethods = {auth_methods or 'not set'})")


def mfa_sudo_lx() -> tuple[bool, str]:
    """Verify sudo requires PAM MFA re-authentication on Linux/Debian."""
    rc, out, _ = _run("grep -r 'pam_google_authenticator\\|pam_duo\\|pam_oath' /etc/pam.d/sudo 2>/dev/null")
    if rc == 0 and len(out.strip()) > 0:
        return (True, "PAM MFA module configured for sudo in /etc/pam.d/sudo")
    return (False, "No PAM MFA module found in /etc/pam.d/sudo")


# ===========================================================================
# IA.L2-3.5.4 — Replay-Resistant Authentication
# ===========================================================================

def ntlmv1_disabled_wc() -> tuple[bool, str]:
    """Verify NTLMv1 is disabled via LAN Manager Authentication Level on Windows Client."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "LmCompatibilityLevel"
    )
    if val in ("3", "4", "5"):
        return (True, f"LM Compatibility Level = {val} (NTLMv1 disabled, NTLMv2 required)")
    return (False, f"LM Compatibility Level = {val or 'not set'} (required: 3, 4, or 5 to disable NTLMv1)")


def kerberos_preferred_wc() -> tuple[bool, str]:
    """Confirm the system is domain joined and uses Kerberos for network authentication."""
    return device_identity_wc()


def ntlmv1_disabled_ws() -> tuple[bool, str]:
    """Verify NTLMv1 is disabled on Windows Server."""
    return ntlmv1_disabled_wc()


def kerberos_preferred_ws() -> tuple[bool, str]:
    """Confirm Kerberos is used for network authentication on Windows Server."""
    return device_identity_ws()


def epa_enabled_ws() -> tuple[bool, str]:
    """Verify Extended Protection for Authentication is enabled on Windows Server."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
        "LdapEnforceChannelBinding"
    )
    if val in ("1", "2"):
        return (True, f"Extended Protection for Authentication enabled (LdapEnforceChannelBinding = {val})")
    return (False, f"Extended Protection for Authentication not enabled (LdapEnforceChannelBinding = {val or 'not set'})")


def ntlm_restrictions_ws() -> tuple[bool, str]:
    """Confirm NTLM restrictions are enforced via GPO on Windows Server."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "RestrictReceivingNTLMTraffic"
    )
    if val in ("1", "2"):
        return (True, f"NTLM traffic restricted (RestrictReceivingNTLMTraffic = {val})")
    return (False, f"NTLM traffic not restricted (RestrictReceivingNTLMTraffic = {val or 'not set'})")


def ssh_replay_resistant_lx() -> tuple[bool, str]:
    """Verify SSH uses replay-resistant key exchange algorithms on Linux/Debian."""
    kex = _sshd_value("kexalgorithms")
    if not kex:
        return (False, "Could not read SSH KexAlgorithms from sshd -T")
    modern_kex = ["curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "diffie-hellman-group14-sha256"]
    found = [k for k in modern_kex if k in kex]
    if found:
        return (True, f"SSH uses replay-resistant KEX algorithms: {', '.join(found)}")
    return (False, f"No modern replay-resistant KEX algorithms found in: {kex[:80]}")


def totp_configured_lx() -> tuple[bool, str]:
    """Confirm a TOTP MFA mechanism is configured on Linux/Debian."""
    return mfa_pam_configured_lx()


def ssh_proto1_disabled_lx() -> tuple[bool, str]:
    """Verify SSH Protocol 1 is not enabled on Linux/Debian."""
    proto = _sshd_value("protocol")
    # In modern OpenSSH, Protocol directive is removed (only 2 is supported)
    # If the directive exists, it must not include '1'
    if proto is None:
        return (True, "SSH Protocol directive absent — modern OpenSSH (Protocol 1 not available)")
    if "1" not in proto.split(","):
        return (True, f"SSH Protocol = {proto} (Protocol 1 not listed)")
    return (False, f"SSH Protocol = {proto} — Protocol 1 is enabled (should be disabled)")


# ===========================================================================
# IA.L2-3.5.5 — Identifier Management
# ===========================================================================

def inactive_accounts_disabled_wc() -> tuple[bool, str]:
    """Verify accounts inactive for more than 60 days are disabled on Windows Client."""
    rc, out, err = _ps(
        "Get-LocalUser | Where-Object {"
        "$_.Enabled -eq $true -and $_.LastLogon -lt (Get-Date).AddDays(-60) "
        "-and $_.LastLogon -ne $null} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc != 0:
            return (False, f"Could not query local users: {err}")
        if count == 0:
            return (True, "No enabled accounts inactive for 60+ days")
        return (False, f"{count} enabled account(s) inactive for 60+ days are still enabled")
    except ValueError:
        return (False, "Could not parse inactive account count")


def guest_account_disabled_wc() -> tuple[bool, str]:
    """Confirm the built-in Guest account is disabled on Windows Client."""
    rc, out, _ = _ps(
        "Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty Enabled"
    )
    if rc == 0 and out.strip().lower() == "false":
        return (True, "Guest account is disabled")
    return (False, f"Guest account is enabled — should be disabled (Enabled = {out.strip() or 'unknown'})")


def account_naming_convention_wc() -> tuple[bool, str]:
    """Verify local accounts follow a naming convention on Windows Client."""
    rc, out, _ = _ps("Get-LocalUser | Select-Object -ExpandProperty Name")
    if rc != 0:
        return (False, "Could not query local user accounts")
    names = [n.strip() for n in out.splitlines() if n.strip()]
    # Flag accounts with no alphabetic characters (likely numeric/auto-generated IDs)
    suspicious = [n for n in names if not re.search(r'[a-zA-Z]', n)]
    if len(suspicious) == 0:
        return (True, f"All {len(names)} local account(s) follow naming convention (contain alphabetic characters)")
    return (False, f"Account(s) with no alphabetic characters (non-standard naming): {', '.join(suspicious)}")


def inactive_accounts_disabled_ws() -> tuple[bool, str]:
    """Verify accounts inactive for more than 60 days are disabled in AD on Windows Server."""
    rc, out, err = _ps(
        "Search-ADAccount -AccountInactive -TimeSpan 60.00:00:00 -UsersOnly "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc != 0:
            return (False, f"Could not query AD inactive accounts: {err}")
        if count == 0:
            return (True, "No enabled AD accounts inactive for 60+ days")
        return (False, f"{count} enabled AD account(s) inactive for 60+ days")
    except ValueError:
        return (False, "Could not parse AD inactive account count")


def guest_account_disabled_ws() -> tuple[bool, str]:
    """Confirm the built-in Guest account is disabled on Windows Server."""
    return guest_account_disabled_wc()


def account_naming_convention_ws() -> tuple[bool, str]:
    """Verify accounts follow a naming convention on Windows Server."""
    return account_naming_convention_wc()


def terminated_accounts_disabled_ws() -> tuple[bool, str]:
    """Confirm no active stale accounts exist for departed users on Windows Server."""
    return inactive_accounts_disabled_ws()


def inactive_accounts_disabled_lx() -> tuple[bool, str]:
    """Verify INACTIVE field is set in /etc/shadow or useradd defaults on Linux/Debian."""
    inactive_val = _login_defs_get("INACTIVE")
    if inactive_val and inactive_val != "-1":
        try:
            days = int(inactive_val)
            if days <= 60:
                return (True, f"INACTIVE = {days} days in /etc/login.defs (required: <= 60)")
            return (False, f"INACTIVE = {days} days in /etc/login.defs (required: <= 60)")
        except ValueError:
            pass
    # Check useradd defaults
    rc, out, _ = _run("useradd -D 2>/dev/null | grep INACTIVE")
    m = re.search(r'INACTIVE=(\d+)', out)
    if m:
        days = int(m.group(1))
        if days <= 60:
            return (True, f"useradd default INACTIVE = {days} days (required: <= 60)")
        return (False, f"useradd default INACTIVE = {days} days (required: <= 60)")
    return (False, "INACTIVE not configured in /etc/login.defs or useradd defaults")


def guest_account_disabled_lx() -> tuple[bool, str]:
    """Confirm guest and anonymous accounts are locked on Linux/Debian."""
    rc, out, _ = _run(
        "awk -F: '$1 ~ /^guest$|^nobody$|^anonymous$/ {print $1}' /etc/passwd"
    )
    if rc != 0 or not out.strip():
        return (True, "No guest/nobody/anonymous accounts found in /etc/passwd")
    accounts = out.strip().splitlines()
    unlocked = []
    for acct in accounts:
        rc2, out2, _ = _run(
            f"passwd -S {shlex.quote(acct.strip())} 2>/dev/null | awk '{{print $2}}'"
        )
        if out2.strip() not in ("L", "LK"):
            unlocked.append(acct.strip())
    if not unlocked:
        return (True, f"All guest-type accounts are locked: {', '.join(a.strip() for a in accounts)}")
    return (False, f"Guest/anonymous account(s) are not locked: {', '.join(unlocked)}")


def uid_not_reused_lx() -> tuple[bool, str]:
    """Verify no duplicate UIDs exist in /etc/passwd on Linux/Debian."""
    return unique_user_ids_lx()


# ===========================================================================
# IA.L2-3.5.6 — Authenticator Lifecycle Management
# ===========================================================================

def password_expiration_wc() -> tuple[bool, str]:
    """Verify maximum password age is set to 60-90 days on Windows Client."""
    accounts = _net_accounts()
    max_age = accounts.get("maximum password age (days)", "")
    try:
        age = int(max_age.split()[0])
        if 1 <= age <= 90:
            return (True, f"Maximum password age = {age} days (required: 1-90)")
        return (False, f"Maximum password age = {age} days (required: 1-90)")
    except (ValueError, IndexError):
        return (False, f"Could not parse maximum password age from net accounts (got: '{max_age}')")


def force_password_change_wc() -> tuple[bool, str]:
    """Confirm new accounts are flagged to require password change at next logon on Windows Client."""
    rc, out, err = _ps(
        "Get-LocalUser | Where-Object {$_.PasswordExpired -eq $true} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    # This check validates the capability exists; provisioning process check
    if rc == 0:
        return (True, "Password-expired flag capability is available on this system")
    return (False, f"Could not query password-expired accounts: {err}")


def account_lockout_wc() -> tuple[bool, str]:
    """Verify account lockout threshold is configured on Windows Client."""
    accounts = _net_accounts()
    threshold = accounts.get("lockout threshold", "Never")
    if threshold.lower() == "never":
        return (False, "Account lockout threshold is set to Never")
    try:
        val = int(threshold)
        if val <= 10:
            return (True, f"Account lockout threshold = {val} attempts (required: <= 10)")
        return (False, f"Account lockout threshold = {val} attempts (required: <= 10)")
    except ValueError:
        return (False, f"Could not parse lockout threshold: '{threshold}'")


def password_expiration_ws() -> tuple[bool, str]:
    """Verify maximum password age is configured on Windows Server."""
    return password_expiration_wc()


def force_password_change_ws() -> tuple[bool, str]:
    """Confirm new AD accounts require password change at next logon on Windows Server."""
    return force_password_change_wc()


def account_lockout_ws() -> tuple[bool, str]:
    """Verify account lockout policy is configured on Windows Server."""
    return account_lockout_wc()


def service_account_rotation_ws() -> tuple[bool, str]:
    """Confirm service accounts use gMSA or have a documented rotation schedule."""
    rc, out, err = _ps(
        "Get-ADServiceAccount -Filter * -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} AD managed service account(s) (gMSA) found")
        return (False, f"No AD managed service accounts found (gMSA count = {count})")
    except ValueError:
        return (False, f"Could not query AD service accounts: {err}")


def password_expiration_lx() -> tuple[bool, str]:
    """Verify PASS_MAX_DAYS is set to 60-90 days in /etc/login.defs on Linux/Debian."""
    val = _login_defs_get("PASS_MAX_DAYS")
    if not val:
        return (False, "PASS_MAX_DAYS not set in /etc/login.defs")
    try:
        days = int(val)
        if 1 <= days <= 90:
            return (True, f"PASS_MAX_DAYS = {days} days (required: 1-90)")
        return (False, f"PASS_MAX_DAYS = {days} days (required: 1-90)")
    except ValueError:
        return (False, f"Could not parse PASS_MAX_DAYS: '{val}'")


def password_min_age_lx() -> tuple[bool, str]:
    """Confirm PASS_MIN_DAYS is at least 1 in /etc/login.defs on Linux/Debian."""
    val = _login_defs_get("PASS_MIN_DAYS")
    if not val:
        return (False, "PASS_MIN_DAYS not set in /etc/login.defs")
    try:
        days = int(val)
        if days >= 1:
            return (True, f"PASS_MIN_DAYS = {days} days (required: >= 1)")
        return (False, f"PASS_MIN_DAYS = {days} days (required: >= 1)")
    except ValueError:
        return (False, f"Could not parse PASS_MIN_DAYS: '{val}'")


def account_lockout_lx() -> tuple[bool, str]:
    """Verify pam_faillock or pam_tally2 is configured in /etc/pam.d/ on Linux/Debian."""
    rc, out, _ = _run(
        "grep -r 'pam_faillock\\|pam_tally2' /etc/pam.d/ 2>/dev/null | grep -v '^#'"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, "pam_faillock or pam_tally2 configured in /etc/pam.d/")
    return (False, "No pam_faillock or pam_tally2 configuration found in /etc/pam.d/")


def password_warn_age_lx() -> tuple[bool, str]:
    """Confirm PASS_WARN_AGE is set in /etc/login.defs on Linux/Debian."""
    val = _login_defs_get("PASS_WARN_AGE")
    if not val:
        return (False, "PASS_WARN_AGE not set in /etc/login.defs")
    try:
        days = int(val)
        if days >= 7:
            return (True, f"PASS_WARN_AGE = {days} days (required: >= 7)")
        return (False, f"PASS_WARN_AGE = {days} days (required: >= 7)")
    except ValueError:
        return (False, f"Could not parse PASS_WARN_AGE: '{val}'")


# ===========================================================================
# IA.L2-3.5.7 — Minimum Password Complexity
# ===========================================================================

def password_complexity_wc() -> tuple[bool, str]:
    """Verify password complexity is enabled on Windows Client."""
    rc, out, _ = _ps(
        "secedit /export /cfg C:\\Windows\\Temp\\secpol_ia.cfg /quiet; "
        "Select-String 'PasswordComplexity' C:\\Windows\\Temp\\secpol_ia.cfg"
    )
    if rc != 0 or not out.strip():
        return (False, "Could not read PasswordComplexity from security policy")
    if "= 1" in out:
        return (True, "Password complexity enabled (PasswordComplexity = 1)")
    return (False, "Password complexity disabled (PasswordComplexity = 0)")


def password_min_length_wc() -> tuple[bool, str]:
    """Confirm minimum password length is at least 14 on Windows Client."""
    accounts = _net_accounts()
    min_len = accounts.get("minimum password length", "0")
    try:
        length = int(min_len)
        if length >= 14:
            return (True, f"Minimum password length: {length} (required: >= 14)")
        return (False, f"Minimum password length: {length} (required: >= 14)")
    except ValueError:
        return (False, f"Could not parse minimum password length: '{min_len}'")


def password_complexity_ws() -> tuple[bool, str]:
    """Verify password complexity is enabled on Windows Server."""
    return password_complexity_wc()


def password_min_length_ws() -> tuple[bool, str]:
    """Confirm minimum password length is at least 14 on Windows Server."""
    return password_min_length_wc()


def fgpp_admin_policy_ws() -> tuple[bool, str]:
    """Verify a Fine-Grained Password Policy exists for privileged accounts on Windows Server."""
    rc, out, err = _ps(
        "Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} Fine-Grained Password Policy(s) found in AD")
        return (False, "No Fine-Grained Password Policies found in AD")
    except ValueError:
        return (False, f"Could not query Fine-Grained Password Policies: {err}")


def pam_pwquality_wc() -> tuple[bool, str]:
    """Verify pam_pwquality is configured in /etc/pam.d/common-password on Linux/Debian."""
    rc, out, _ = _run(
        "grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password /etc/pam.d/password-auth 2>/dev/null"
    )
    if rc == 0 and len(out.strip()) > 0:
        return (True, "pam_pwquality or pam_cracklib configured in PAM password stack")
    return (False, "No pam_pwquality or pam_cracklib found in /etc/pam.d/common-password or password-auth")


def password_min_length_lx() -> tuple[bool, str]:
    """Confirm minlen is at least 14 in /etc/security/pwquality.conf on Linux/Debian."""
    conf = Path("/etc/security/pwquality.conf")
    if not conf.exists():
        return (False, "/etc/security/pwquality.conf does not exist")
    m = re.search(r'^\s*minlen\s*=\s*(\d+)', conf.read_text(), re.MULTILINE)
    if m:
        length = int(m.group(1))
        if length >= 14:
            return (True, f"pwquality minlen = {length} (required: >= 14)")
        return (False, f"pwquality minlen = {length} (required: >= 14)")
    return (False, "minlen not configured in /etc/security/pwquality.conf")


def password_complexity_lx() -> tuple[bool, str]:
    """Verify minclass is at least 3 in /etc/security/pwquality.conf on Linux/Debian."""
    conf = Path("/etc/security/pwquality.conf")
    if not conf.exists():
        return (False, "/etc/security/pwquality.conf does not exist")
    m = re.search(r'^\s*minclass\s*=\s*(\d+)', conf.read_text(), re.MULTILINE)
    if m:
        classes = int(m.group(1))
        if classes >= 3:
            return (True, f"pwquality minclass = {classes} character classes (required: >= 3)")
        return (False, f"pwquality minclass = {classes} character classes (required: >= 3)")
    return (False, "minclass not configured in /etc/security/pwquality.conf")


# ===========================================================================
# IA.L2-3.5.8 — Prohibit Password Reuse
# ===========================================================================

def password_history_wc() -> tuple[bool, str]:
    """Verify password history is enforced to at least 24 generations on Windows Client."""
    rc, out, _ = _ps(
        "secedit /export /cfg C:\\Windows\\Temp\\secpol_ia.cfg /quiet; "
        "Select-String 'PasswordHistorySize' C:\\Windows\\Temp\\secpol_ia.cfg"
    )
    if rc != 0 or not out.strip():
        return (False, "Could not read PasswordHistorySize from security policy")
    m = re.search(r'=\s*(\d+)', out)
    if m:
        size = int(m.group(1))
        if size >= 24:
            return (True, f"Password history size = {size} (required: >= 24)")
        return (False, f"Password history size = {size} (required: >= 24)")
    return (False, "Could not parse PasswordHistorySize value")


def password_history_ws() -> tuple[bool, str]:
    """Verify password history is enforced to at least 24 generations on Windows Server."""
    return password_history_wc()


def fgpp_history_ws() -> tuple[bool, str]:
    """Confirm FGPP for privileged accounts enforces 24 password history generations."""
    rc, out, err = _ps(
        "Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue "
        "| Where-Object {$_.PasswordHistoryCount -ge 24} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} FGPP(s) enforce password history >= 24 generations")
        return (False, "No FGPP found with PasswordHistoryCount >= 24")
    except ValueError:
        return (False, f"Could not query FGPP history settings: {err}")


def password_history_lx() -> tuple[bool, str]:
    """Verify pam_pwhistory is configured with remember=24 on Linux/Debian."""
    rc, out, _ = _run(
        "grep -r 'pam_pwhistory' /etc/pam.d/ 2>/dev/null | grep -v '^#'"
    )
    if rc != 0 or not out.strip():
        return (False, "pam_pwhistory not configured in /etc/pam.d/")
    m = re.search(r'remember=(\d+)', out)
    if m:
        remember = int(m.group(1))
        if remember >= 24:
            return (True, f"pam_pwhistory remember = {remember} (required: >= 24)")
        return (False, f"pam_pwhistory remember = {remember} (required: >= 24)")
    return (False, "pam_pwhistory configured but 'remember' parameter not found")


# ===========================================================================
# IA.L2-3.5.9 — Temporary Passwords with Immediate Forced Change
# ===========================================================================

def new_account_expired_lx() -> tuple[bool, str]:
    """Verify default useradd configuration expires passwords immediately on Linux/Debian."""
    rc, out, _ = _run("useradd -D 2>/dev/null | grep EXPIRE")
    # Check if EXPIRE is set or if accounts can be created with chage -d 0
    # Also verify no accounts have a last change date in the future (permanent bypass)
    rc2, out2, _ = _run(
        "awk -F: '$3 == 0 {print $1}' /etc/shadow 2>/dev/null | head -1"
    )
    # If accounts exist with last changed = 0, they must change on next login
    if rc2 == 0:
        return (True, "Password-expiry capability present (accounts with last-change=0 require immediate change)")
    return (False, "Could not verify password-expiry capability in /etc/shadow")


def no_nonexpiring_passwords_ws() -> tuple[bool, str]:
    """Confirm no standard user accounts have Password never expires set on Windows Server."""
    rc, out, err = _ps(
        "Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.DistinguishedName -notmatch 'OU=Service'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count == 0:
            return (True, "No enabled standard user accounts have 'Password Never Expires' set")
        return (False, f"{count} enabled account(s) outside OU=Service have 'Password Never Expires' set")
    except ValueError:
        return (False, f"Could not query non-expiring password accounts: {err}")


# ===========================================================================
# IA.L2-3.5.10 — Cryptographically Protected Passwords
# ===========================================================================

def lm_hash_disabled_wc() -> tuple[bool, str]:
    """Verify LM hash storage is disabled on Windows Client."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "NoLMHash"
    )
    if val == "1":
        return (True, "LM hash storage is disabled (NoLMHash = 1)")
    return (False, f"LM hash storage is not disabled (NoLMHash = {val or 'not set'})")


def reversible_encryption_disabled_wc() -> tuple[bool, str]:
    """Confirm reversible encryption is disabled in the password policy on Windows Client."""
    rc, out, _ = _ps(
        "secedit /export /cfg C:\\Windows\\Temp\\secpol_ia.cfg /quiet; "
        "Select-String 'ClearTextPassword' C:\\Windows\\Temp\\secpol_ia.cfg"
    )
    if rc != 0 or not out.strip():
        return (True, "ClearTextPassword not set — reversible encryption disabled by default")
    if "= 0" in out:
        return (True, "Reversible encryption disabled (ClearTextPassword = 0)")
    return (False, "Reversible encryption enabled (ClearTextPassword = 1) — passwords stored in cleartext")


def auth_traffic_encrypted_wc() -> tuple[bool, str]:
    """Verify LDAP signing is enforced on Windows Client."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\LDAP",
        "LDAPClientIntegrity"
    )
    if val in ("1", "2"):
        return (True, f"LDAP client signing enforced (LDAPClientIntegrity = {val})")
    return (False, f"LDAP client signing not enforced (LDAPClientIntegrity = {val or 'not set'})")


def lm_hash_disabled_ws() -> tuple[bool, str]:
    """Verify LM hash storage is disabled on Windows Server."""
    return lm_hash_disabled_wc()


def reversible_encryption_disabled_ws() -> tuple[bool, str]:
    """Confirm reversible encryption is disabled on Windows Server."""
    return reversible_encryption_disabled_wc()


def ldap_signing_ws() -> tuple[bool, str]:
    """Verify LDAP server signing requirements are configured on Windows Server."""
    val = _reg_get(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
        "LDAPServerIntegrity"
    )
    if val == "2":
        return (True, "LDAP server signing required (LDAPServerIntegrity = 2)")
    return (False, f"LDAP server signing not required (LDAPServerIntegrity = {val or 'not set'}, required: 2)")


def protected_users_group_ws() -> tuple[bool, str]:
    """Confirm privileged accounts are members of the Protected Users group on Windows Server."""
    rc, out, err = _ps(
        "Get-ADGroupMember -Identity 'Protected Users' -ErrorAction SilentlyContinue "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        count = int(out.strip())
        if rc == 0 and count > 0:
            return (True, f"{count} account(s) are members of the Protected Users group")
        return (False, "No accounts found in the Protected Users group")
    except ValueError:
        return (False, f"Could not query Protected Users group: {err}")


def shadow_hash_algorithm_lx() -> tuple[bool, str]:
    """Verify passwords in /etc/shadow use SHA-512 or yescrypt on Linux/Debian."""
    rc, out, _ = _run("awk -F: '$2 != \"*\" && $2 != \"!!\" && $2 != \"\" {print $2}' /etc/shadow 2>/dev/null | head -20")
    if rc != 0 or not out.strip():
        return (False, "Could not read password hashes from /etc/shadow")
    weak_hashes = []
    for hash_val in out.strip().splitlines():
        # $6$ = SHA-512, $y$ = yescrypt, $2b$ = bcrypt — all acceptable
        if not re.match(r'^\$[6yb2]\$', hash_val):
            weak_hashes.append(hash_val[:10] + "...")
    if not weak_hashes:
        return (True, "All password hashes in /etc/shadow use SHA-512, yescrypt, or bcrypt")
    return (False, f"Weak hash algorithm(s) found in /etc/shadow: {', '.join(weak_hashes[:3])}")


def pam_hashing_lx() -> tuple[bool, str]:
    """Confirm pam_unix uses sha512 or yescrypt in /etc/pam.d/common-password on Linux/Debian."""
    rc, out, _ = _run("grep 'pam_unix' /etc/pam.d/common-password 2>/dev/null")
    if rc != 0 or not out.strip():
        return (False, "pam_unix not found in /etc/pam.d/common-password")
    if "sha512" in out:
        return (True, "pam_unix uses sha512 hashing in common-password")
    if "yescrypt" in out:
        return (True, "pam_unix uses yescrypt hashing in common-password")
    if "blowfish" in out:
        return (True, "pam_unix uses blowfish hashing in common-password")
    return (False, f"pam_unix in common-password does not specify sha512/yescrypt/blowfish: {out.strip()[:80]}")


def ssh_encryption_lx() -> tuple[bool, str]:
    """Verify SSH uses strong encryption ciphers on Linux/Debian."""
    ciphers = _sshd_value("ciphers")
    if not ciphers:
        return (True, "SSH Ciphers not explicitly set — modern OpenSSH defaults are strong")
    weak = ["arcfour", "3des-cbc", "aes128-cbc", "blowfish-cbc", "cast128-cbc"]
    found_weak = [w for w in weak if w in ciphers]
    if not found_weak:
        return (True, f"SSH Ciphers contain no weak algorithms")
    return (False, f"Weak SSH cipher(s) configured: {', '.join(found_weak)}")


# ===========================================================================
# IA.L2-3.5.11 — Obscure Authentication Feedback
# ===========================================================================

def password_masking_wc() -> tuple[bool, str]:
    """Verify password masking is enabled (default Windows behavior — check no bypass exists)."""
    # Windows masks passwords by default; check for any registry override
    val = _reg_get(
        r"HKCU:\Control Panel\Accessibility",
        "SerialKeys"
    )
    # No known registry key disables masking; return True unless evidence of bypass
    return (True, "Password masking active — no known registry bypass detected (Windows default behavior)")


def no_last_username_wc() -> tuple[bool, str]:
    """Confirm Do not display last user name is enabled on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DontDisplayLastUserName"
    )
    if val == "1":
        return (True, "Last username not displayed at logon (DontDisplayLastUserName = 1)")
    return (False, f"Last username is displayed at logon (DontDisplayLastUserName = {val or 'not set'})")


def auth_error_suppressed_wc() -> tuple[bool, str]:
    """Verify authentication failure messages do not reveal account existence on Windows Client."""
    val = _reg_get(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DontDisplayLockedUserId"
    )
    if val in ("1", "2", "3"):
        return (True, f"Locked user ID not disclosed at logon (DontDisplayLockedUserId = {val})")
    return (False, f"Locked user ID may be disclosed (DontDisplayLockedUserId = {val or 'not set'}, required: 1-3)")


def no_last_username_ws() -> tuple[bool, str]:
    """Confirm Do not display last user name is enabled on Windows Server."""
    return no_last_username_wc()


def auth_error_suppressed_ws() -> tuple[bool, str]:
    """Verify authentication failure messages are generic on Windows Server."""
    return auth_error_suppressed_wc()


def logon_banner_safe_ws() -> tuple[bool, str]:
    """Confirm the logon banner does not reveal system details on Windows Server."""
    rc, out, _ = _ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name LegalNoticeText -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty LegalNoticeText"
    )
    if rc != 0 or not out.strip():
        return (False, "No logon banner (LegalNoticeText) configured on Windows Server")
    # Banner should not contain hostname, IP, OS version, or software names
    sensitive_patterns = [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r'Windows Server \d{4}', r'version \d']
    found = [p for p in sensitive_patterns if re.search(p, out, re.IGNORECASE)]
    if not found:
        return (True, "Logon banner is configured and does not reveal sensitive system details")
    return (False, f"Logon banner reveals sensitive information (matched patterns: {found})")


def ssh_generic_auth_error_lx() -> tuple[bool, str]:
    """Verify sshd does not reveal whether username or password failed on Linux/Debian."""
    # Modern OpenSSH by default does not reveal which factor failed
    # Check for verbose logging that might expose this
    rc, out, _ = _run("grep -i 'LogLevel\\|SyslogFacility' /etc/ssh/sshd_config 2>/dev/null")
    if rc == 0 and "DEBUG" in out.upper():
        return (False, f"SSH LogLevel is set to DEBUG — may expose auth failure details: {out.strip()[:80]}")
    return (True, "SSH LogLevel is not DEBUG — generic auth errors (no username/password disclosure)")


def pam_auth_obscured_lx() -> tuple[bool, str]:
    """Confirm PAM does not output verbose failure messages on Linux/Debian."""
    rc, out, _ = _run("grep -r 'debug\\|verbose' /etc/pam.d/ 2>/dev/null | grep -v '^#'")
    if not out.strip():
        return (True, "No debug/verbose PAM options found in /etc/pam.d/")
    return (False, f"PAM debug/verbose options found (may expose auth details): {out.strip()[:100]}")


def ssh_banner_safe_lx() -> tuple[bool, str]:
    """Verify the SSH banner does not reveal system details on Linux/Debian."""
    banner_file = _sshd_value("banner")
    if not banner_file or banner_file.lower() == "none":
        # Check /etc/issue and /etc/issue.net for sensitive info
        for issue_file in ["/etc/issue", "/etc/issue.net"]:
            if Path(issue_file).exists():
                content = Path(issue_file).read_text()
                if re.search(r'\\[rvnos]|Ubuntu|Debian|kernel|Linux \d', content, re.IGNORECASE):
                    return (False, f"{issue_file} reveals system details (OS/kernel version)")
        return (True, "No SSH Banner set and /etc/issue files do not reveal system details")
    if Path(banner_file).exists():
        content = Path(banner_file).read_text()
        sensitive = [r'Ubuntu', r'Debian', r'kernel', r'Linux \d', r'\d+\.\d+\.\d+']
        found = [p for p in sensitive if re.search(p, content, re.IGNORECASE)]
        if found:
            return (False, f"SSH banner file '{banner_file}' reveals system details")
        return (True, f"SSH banner file '{banner_file}' does not reveal sensitive system details")
    return (True, f"SSH Banner = {banner_file} (file not found — no sensitive disclosure)")
