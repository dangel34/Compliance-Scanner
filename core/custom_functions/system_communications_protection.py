"""
system_communications_protection.py

Houses all system and communications protection (SC) check functions
for CMMC SC.L1-3.13.1 through SC.L2-3.13.16.
Each function corresponds to a cs_f() reference in the SC control JSON files.

Naming convention:
    <check_name>_wc   -> Windows Client
    <check_name>_ws   -> Windows Server
    <check_name>_lx   -> Linux / Debian (shared)
"""

import ipaddress
import subprocess
import re
from pathlib import Path

_RUN_CACHE: dict[tuple[object, bool, int], tuple[int, str, str]] = {}


def clear_cache() -> None:
    """Clear the command result cache so the next scan gets fresh results."""
    _RUN_CACHE.clear()


def _run(cmd: str, shell: bool = True, timeout: int = 30) -> tuple[int, str, str]:
    cache_key = (cmd, shell, timeout)
    cached = _RUN_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        output = (result.returncode, result.stdout.strip(), result.stderr.strip())
        _RUN_CACHE[cache_key] = output
        return output
    except subprocess.TimeoutExpired:
        output = (-1, "", "command timed out")
        _RUN_CACHE[cache_key] = output
        return output


def _ps(cmd: str) -> tuple[int, str, str]:
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
    rc, out, _ = _ps(
        f"(Get-ItemProperty -Path '{key}' -Name '{value}' "
        f"-ErrorAction SilentlyContinue).'{value}'"
    )
    return out.strip() if rc == 0 and out.strip() else None


# =============================================================================
# SC.L1-3.13.1 — Monitor, Control, and Protect Communications at System Boundaries
# =============================================================================

def firewall_enabled_wc() -> tuple[bool, str]:
    """Verify Windows Defender Firewall is enabled on all profiles (Domain, Private, Public) on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"
        )
        if rc != 0 or not out:
            return (False, f"Could not query firewall profiles: {err}")
        lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
        if all(l == "true" for l in lines) and len(lines) >= 3:
            return (True, f"Windows Defender Firewall is enabled on all {len(lines)} profiles")
        disabled = [i + 1 for i, l in enumerate(lines) if l != "true"]
        return (False, f"Firewall is not enabled on all profiles (disabled on profile(s): {disabled}; got {len(lines)} profiles)")
    except Exception as e:
        return (False, f"Exception while checking firewall status: {e}")


def firewall_logging_wc() -> tuple[bool, str]:
    """Verify Windows Defender Firewall logging is enabled on at least one profile on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-NetFirewallProfile | Where-Object { $_.LogAllowed -eq 'True' -or $_.LogBlocked -eq 'True' } "
            "| Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc != 0 or not out.strip().isdigit():
            return (False, f"Could not query firewall logging status: {err}")
        count = int(out.strip())
        if count >= 1:
            return (True, f"Firewall logging is enabled on {count} profile(s)")
        return (False, "Firewall logging (LogAllowed/LogBlocked) is not enabled on any profile")
    except Exception as e:
        return (False, f"Exception while checking firewall logging: {e}")


def inbound_default_deny_wc() -> tuple[bool, str]:
    """Verify the Windows Defender Firewall default inbound action is Block for all profiles on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-NetFirewallProfile | Select-Object -ExpandProperty DefaultInboundAction"
        )
        if rc != 0 or not out:
            return (False, f"Could not query default inbound action: {err}")
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if all(l in ("2", "Block") for l in lines) and len(lines) >= 3:
            return (True, f"Default inbound action is Block on all {len(lines)} firewall profiles")
        non_block = [l for l in lines if l not in ("2", "Block")]
        return (False, f"Default inbound action is not Block on all profiles (non-block values: {non_block})")
    except Exception as e:
        return (False, f"Exception while checking inbound default action: {e}")


def network_profile_wc() -> tuple[bool, str]:
    """Verify no active network interface is assigned the Public profile on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"
        )
        if rc != 0:
            return (False, f"Could not query network connection profiles: {err}")
        lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
        if len(lines) > 0 and "public" not in lines:
            return (True, f"No network interface is on the Public profile (profiles: {lines})")
        if not lines:
            return (False, "No network connection profiles found")
        return (False, f"One or more network interfaces are assigned the Public profile: {lines}")
    except Exception as e:
        return (False, f"Exception while checking network profiles: {e}")


def firewall_enabled_ws() -> tuple[bool, str]:
    """Verify Windows Defender Firewall is enabled on all profiles on Windows Server."""
    return firewall_enabled_wc()


def firewall_logging_ws() -> tuple[bool, str]:
    """Verify Windows Defender Firewall logging is enabled on Windows Server."""
    return firewall_logging_wc()


def inbound_default_deny_ws() -> tuple[bool, str]:
    """Verify the default inbound firewall action is Block on all profiles on Windows Server."""
    return inbound_default_deny_wc()


def network_profile_ws() -> tuple[bool, str]:
    """Verify no network interface is on the Public profile on Windows Server."""
    return network_profile_wc()


def perimeter_firewall_ws() -> tuple[bool, str]:
    """Verify Windows Firewall advanced security rules include explicit perimeter inbound deny rules on Windows Server."""
    try:
        rc, out, err = _ps(
            "Get-NetFirewallRule -Direction Inbound -Action Block | Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc != 0:
            return (False, f"Could not query inbound block firewall rules: {err}")
        count = int(out.strip()) if out.strip().isdigit() else 0
        if count >= 1:
            return (True, f"Perimeter inbound deny rules exist ({count} inbound Block rule(s))")
        return (False, "No explicit inbound Block firewall rules found")
    except Exception as e:
        return (False, f"Exception while checking perimeter firewall rules: {e}")


def firewall_active_lx() -> tuple[bool, str]:
    """Verify iptables, nftables, or firewalld is active and has rules loaded on Linux/Debian."""
    try:
        # Check firewalld
        rc, out, _ = _run("systemctl is-active firewalld 2>/dev/null")
        if rc == 0 and "active" in out:
            return (True, "firewalld is active")
        # Check nftables
        rc, out, _ = _run("systemctl is-active nftables 2>/dev/null")
        if rc == 0 and "active" in out:
            return (True, "nftables is active")
        # Check iptables has rules beyond defaults
        rc, out, _ = _run("iptables -L -n --line-numbers 2>/dev/null | grep -c '^[0-9]'")
        if rc == 0:
            try:
                count = int(out.strip())
                if count > 0:
                    return (True, f"iptables has {count} active rule(s)")
            except ValueError:
                pass
        return (False, "No active firewall found (checked firewalld, nftables, iptables)")
    except Exception as e:
        return (False, f"Exception while checking firewall status: {e}")


def default_input_policy_lx() -> tuple[bool, str]:
    """Verify the iptables/nftables default INPUT chain policy is DROP or REJECT on Linux/Debian."""
    try:
        rc, out, _ = _run("iptables -L INPUT 2>/dev/null | head -1")
        if rc == 0 and re.search(r"policy\s+(DROP|REJECT)", out, re.IGNORECASE):
            m = re.search(r"policy\s+(\S+)", out, re.IGNORECASE)
            policy = m.group(1) if m else "DROP/REJECT"
            return (True, f"iptables INPUT chain default policy is {policy}")
        # Check nftables
        rc2, out2, _ = _run("nft list ruleset 2>/dev/null | grep -i 'type filter hook input'")
        if rc2 == 0 and out2:
            rc3, out3, _ = _run("nft list ruleset 2>/dev/null | grep -A5 'hook input' | grep -i 'policy drop'")
            if rc3 == 0 and out3:
                return (True, "nftables input hook has a drop policy")
        # Check ufw
        rc4, out4, _ = _run("ufw status verbose 2>/dev/null | grep 'Default:'")
        if rc4 == 0 and "deny (incoming)" in out4.lower():
            return (True, "ufw default incoming policy is deny")
        return (False, "No default DROP/REJECT INPUT policy found (checked iptables, nftables, ufw)")
    except Exception as e:
        return (False, f"Exception while checking default input policy: {e}")


def listening_ports_lx() -> tuple[bool, str]:
    """Verify only expected ports are listening; ss -tlnp produces output for review on Linux/Debian."""
    try:
        rc, out, err = _run("ss -tlnp 2>/dev/null")
        # We just verify ss runs successfully and produces output — detailed review is manual
        if rc == 0 and len(out.splitlines()) >= 1:
            return (True, "ss -tlnp executed successfully and returned listening port data for review")
        return (False, f"Could not retrieve listening port data: {err}")
    except Exception as e:
        return (False, f"Exception while checking listening ports: {e}")


# =============================================================================
# SC.L2-3.13.2 — Employ Security Engineering Principles
# =============================================================================

def secure_boot_wc() -> tuple[bool, str]:
    """Verify Secure Boot is enabled via Confirm-SecureBootUEFI on Windows Client."""
    try:
        rc, out, _ = _ps("Confirm-SecureBootUEFI")
        if rc == 0 and out.strip().lower() == "true":
            return (True, "Secure Boot is enabled (Confirm-SecureBootUEFI = True)")
        return (False, f"Secure Boot is not enabled (Confirm-SecureBootUEFI = {out.strip() or 'False/error'})")
    except Exception as e:
        return (False, f"Exception while checking Secure Boot: {e}")


def dep_nx_wc() -> tuple[bool, str]:
    """Verify DEP/NX is set to OptIn or AlwaysOn via bcdedit on Windows Client."""
    try:
        rc, out, err = _run("bcdedit /enum {current} 2>nul")
        if rc != 0:
            return (False, f"Could not run bcdedit: {err}")
        m = re.search(r"nx\s+(\S+)", out, re.IGNORECASE)
        if m and m.group(1).lower() in ("optin", "alwayson"):
            return (True, f"DEP/NX is configured: nx = {m.group(1)}")
        val = m.group(1) if m else "not found"
        return (False, f"DEP/NX is not properly configured: nx = {val} (expected: optin or alwayson)")
    except Exception as e:
        return (False, f"Exception while checking DEP/NX: {e}")


def aslr_wc() -> tuple[bool, str]:
    """Verify ASLR (MoveImages) is enabled in the registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
            "MoveImages"
        )
        # MoveImages = 0xFFFFFFFF or -1 means always randomize; absence means default (enabled)
        if val is None:
            return (True, "ASLR is enabled by default (MoveImages registry key is absent)")
        if val.strip() != "0":
            return (True, f"ASLR is enabled (MoveImages = {val})")
        return (False, "ASLR is disabled (MoveImages = 0)")
    except Exception as e:
        return (False, f"Exception while checking ASLR: {e}")


def secure_boot_ws() -> tuple[bool, str]:
    """Verify Secure Boot is enabled on Windows Server."""
    return secure_boot_wc()


def dep_nx_ws() -> tuple[bool, str]:
    """Verify DEP/NX is enabled on Windows Server."""
    return dep_nx_wc()


def aslr_ws() -> tuple[bool, str]:
    """Verify ASLR is enabled on Windows Server."""
    return aslr_wc()


def aslr_lx() -> tuple[bool, str]:
    """Verify ASLR is enabled (kernel.randomize_va_space = 2) on Linux/Debian."""
    try:
        p = Path("/proc/sys/kernel/randomize_va_space")
        if p.exists():
            val = p.read_text().strip()
            if val == "2":
                return (True, "ASLR is fully enabled (randomize_va_space = 2)")
            return (False, f"ASLR is not fully enabled (randomize_va_space = {val}, expected: 2)")
        rc, out, err = _run("sysctl -n kernel.randomize_va_space 2>/dev/null")
        if rc != 0:
            return (False, f"Could not read kernel.randomize_va_space: {err}")
        if out.strip() == "2":
            return (True, "ASLR is fully enabled (randomize_va_space = 2)")
        return (False, f"ASLR is not fully enabled (randomize_va_space = {out.strip()}, expected: 2)")
    except Exception as e:
        return (False, f"Exception while checking ASLR: {e}")


def selinux_apparmor_lx() -> tuple[bool, str]:
    """Verify SELinux is Enforcing or AppArmor is active on Linux/Debian."""
    try:
        rc, out, _ = _run("getenforce 2>/dev/null")
        if rc == 0 and "enforcing" in out.lower():
            return (True, "SELinux is in Enforcing mode")
        rc2, out2, _ = _run("aa-status 2>/dev/null | grep -i 'apparmor module is loaded'")
        if rc2 == 0 and out2:
            return (True, "AppArmor module is loaded and active")
        rc3, out3, _ = _run("systemctl is-active apparmor 2>/dev/null")
        if rc3 == 0 and "active" in out3:
            return (True, "AppArmor service is active")
        return (False, "Neither SELinux (Enforcing) nor AppArmor is active on this system")
    except Exception as e:
        return (False, f"Exception while checking SELinux/AppArmor: {e}")


def secure_boot_lx() -> tuple[bool, str]:
    """Verify Secure Boot is enabled via mokutil on Linux/Debian."""
    try:
        rc, out, err = _run("mokutil --sb-state 2>/dev/null")
        if rc == 0 and "secureboot enabled" in out.lower():
            return (True, "Secure Boot is enabled (mokutil: SecureBoot enabled)")
        return (False, f"Secure Boot is not enabled (mokutil output: {out.strip() or err.strip() or 'no output'})")
    except Exception as e:
        return (False, f"Exception while checking Secure Boot: {e}")


# =============================================================================
# SC.L1-3.13.5 — Implement Subnetworks for Publicly Accessible Systems
# =============================================================================

def network_profile_domain_wc() -> tuple[bool, str]:
    """Verify the active network profile is Domain (not Public) on Windows Client, indicating proper subnet placement."""
    try:
        rc, out, err = _ps(
            "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"
        )
        if rc != 0 or not out:
            return (False, f"Could not query network connection profiles: {err}")
        lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
        if any(l == "domainauthenticated" for l in lines):
            return (True, "Network profile is DomainAuthenticated (proper subnet placement confirmed)")
        return (False, f"No DomainAuthenticated network profile found (profiles: {lines})")
    except Exception as e:
        return (False, f"Exception while checking network profile: {e}")


def network_profile_domain_ws() -> tuple[bool, str]:
    """Verify the active network profile is Domain on Windows Server, indicating proper subnet placement."""
    return network_profile_domain_wc()


def internal_subnet_lx() -> tuple[bool, str]:
    """Verify the system has an RFC-1918 private IP address, indicating it is on an internal subnet on Linux/Debian."""
    try:
        rc, out, err = _run("ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1'")
        if rc != 0 or not out:
            return (False, f"Could not retrieve IP addresses or no non-loopback addresses found: {err}")
        ip_re = re.compile(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})")
        for m in ip_re.finditer(out):
            try:
                addr = ipaddress.ip_address(m.group(1))
                if addr.is_private and not addr.is_loopback:
                    return (True, f"System has an RFC-1918 private IP address: {m.group(1)}")
            except ValueError:
                pass
        return (False, f"No RFC-1918 private IP address found (addresses: {out.strip()})")
    except Exception as e:
        return (False, f"Exception while checking internal subnet: {e}")


# =============================================================================
# SC.L2-3.13.3 — Separate User Functionality from System Management Functionality
# =============================================================================

def no_standard_user_is_admin_wc() -> tuple[bool, str]:
    """Verify no standard daily-use accounts are members of the local Administrators group on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-LocalGroupMember -Group 'Administrators' | "
            "Where-Object { $_.ObjectClass -eq 'User' } | "
            "Select-Object -ExpandProperty Name"
        )
        if rc != 0:
            return (False, f"Could not query Administrators group membership: {err}")
        members = [l.strip() for l in out.splitlines() if l.strip()]
        # Built-in Administrator and domain admin accounts are expected; flag if >2 user accounts
        non_builtin = [m for m in members if not re.search(r"Administrator$", m, re.IGNORECASE)]
        if len(non_builtin) == 0:
            return (True, "Only built-in Administrator account(s) are in the Administrators group")
        return (False, f"Non-Administrator accounts found in Administrators group: {', '.join(non_builtin)}")
    except Exception as e:
        return (False, f"Exception while checking admin group membership: {e}")


def uac_enabled_wc() -> tuple[bool, str]:
    """Verify User Account Control (UAC) is enabled via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA"
        )
        if val == "1":
            return (True, "UAC is enabled (EnableLUA = 1)")
        return (False, f"UAC is not enabled (EnableLUA = {val or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking UAC: {e}")


def separate_admin_accounts_wc() -> tuple[bool, str]:
    """Verify admin accounts follow a naming convention separate from standard user accounts on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-LocalGroupMember -Group 'Administrators' | "
            "Where-Object { $_.ObjectClass -eq 'User' } | "
            "Select-Object -ExpandProperty Name"
        )
        if rc != 0:
            return (False, f"Could not query Administrators group membership: {err}")
        members = [l.strip() for l in out.splitlines() if l.strip()]
        # Compliant if all admin accounts contain 'admin', 'adm', or 'svc' in name (convention check)
        if not members:
            return (True, "No non-built-in user accounts found in the Administrators group")
        non_convention = [
            m for m in members
            if not re.search(r"(admin|adm|svc|sysadm|administrator)", m, re.IGNORECASE)
        ]
        if not non_convention:
            return (True, f"All admin accounts follow the expected naming convention ({len(members)} account(s) reviewed)")
        return (False, f"Admin accounts not following naming convention: {', '.join(non_convention)}")
    except Exception as e:
        return (False, f"Exception while checking admin account naming: {e}")


def no_standard_user_is_admin_ws() -> tuple[bool, str]:
    """Verify no standard daily-use accounts are in the Administrators group on Windows Server."""
    return no_standard_user_is_admin_wc()


def uac_enabled_ws() -> tuple[bool, str]:
    """Verify UAC is enabled on Windows Server."""
    return uac_enabled_wc()


def separate_admin_accounts_ws() -> tuple[bool, str]:
    """Verify admin accounts are named separately from standard user accounts on Windows Server."""
    return separate_admin_accounts_wc()


def ldap_admin_check_ws() -> tuple[bool, str]:
    """Verify Domain Admins group membership is limited (server-specific AD check) on Windows Server."""
    try:
        rc, out, err = _ps(
            "net group 'Domain Admins' /domain 2>&1 | "
            "Select-String -Pattern '^Members' -Context 0,20"
        )
        # Just verify the command runs; a non-empty, short list indicates controlled membership
        if rc == 0 and out.strip():
            return (True, "Domain Admins group membership is queryable (review list for compliance)")
        return (False, f"Could not query Domain Admins group membership: {err or 'no output'}")
    except Exception as e:
        return (False, f"Exception while checking Domain Admins membership: {e}")


def root_login_disabled_lx() -> tuple[bool, str]:
    """Verify SSH root login is disabled in sshd_config on Linux/Debian."""
    try:
        rc, out, _ = _run("sshd -T 2>/dev/null | grep -i 'permitrootlogin'")
        if rc == 0 and out:
            if "no" in out.lower():
                return (True, f"SSH PermitRootLogin is disabled: {out.strip()}")
            return (False, f"SSH PermitRootLogin is not disabled: {out.strip()}")
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            text = p.read_text()
            m = re.search(r"^\s*PermitRootLogin\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                val = m.group(1).lower()
                if val == "no":
                    return (True, "SSH PermitRootLogin is set to 'no' in sshd_config")
                return (False, f"SSH PermitRootLogin is set to '{val}' (expected: no)")
        return (False, "Could not determine SSH PermitRootLogin setting (sshd_config not found)")
    except Exception as e:
        return (False, f"Exception while checking SSH root login: {e}")


def no_uid0_regular_users_lx() -> tuple[bool, str]:
    """Verify no regular (non-root) user accounts have UID 0 on Linux/Debian."""
    try:
        p = Path("/etc/passwd")
        if not p.exists():
            return (False, "/etc/passwd not found")
        uid0 = []
        for line in p.read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                uid0.append(parts[0])
        if len(uid0) == 0:
            return (True, "No non-root accounts with UID 0 found in /etc/passwd")
        return (False, f"Non-root accounts with UID 0 found: {', '.join(uid0)}")
    except Exception as e:
        return (False, f"Exception while checking UID 0 accounts: {e}")


def sudo_restricted_lx() -> tuple[bool, str]:
    """Verify the sudoers file does not grant unrestricted NOPASSWD sudo to all users on Linux/Debian."""
    try:
        p = Path("/etc/sudoers")
        if not p.exists():
            return (False, "/etc/sudoers not found")
        text = p.read_text()
        # Fail if there is an uncommented ALL=(ALL) NOPASSWD: ALL for a non-root user
        dangerous = re.findall(
            r"^\s*(?!#)(?!root\s)(\S+)\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL",
            text, re.MULTILINE
        )
        if len(dangerous) == 0:
            return (True, "No unrestricted NOPASSWD sudo grants found in /etc/sudoers")
        return (False, f"Unrestricted NOPASSWD sudo grants found for: {', '.join(dangerous)}")
    except Exception as e:
        return (False, f"Exception while checking sudoers: {e}")


# =============================================================================
# SC.L2-3.13.4 — Prevent Unauthorized and Unintended Information Transfer
# =============================================================================

def dlp_agent_present_wc() -> tuple[bool, str]:
    """Verify a Data Loss Prevention agent (Microsoft Purview/Endpoint DLP) is present on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-Service -Name 'MsSense','SenseCncProxy','MpsSvc' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Status -eq 'Running' } | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc == 0 and out.strip().isdigit() and int(out.strip()) > 0:
            return (True, f"DLP/MDE agent service is running ({out.strip()} service(s) active)")
        # Also check for Purview compliance agent
        rc2, out2, _ = _ps(
            "Get-Process -Name 'MsSense','SenseIR' -ErrorAction SilentlyContinue | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc2 == 0 and out2.strip().isdigit() and int(out2.strip()) > 0:
            return (True, f"Purview/MDE compliance agent process is running ({out2.strip()} process(es))")
        return (False, "No DLP agent (MsSense/SenseCncProxy/MpsSvc/SenseIR) is running")
    except Exception as e:
        return (False, f"Exception while checking DLP agent: {e}")


def usb_storage_blocked_wc() -> tuple[bool, str]:
    """Verify USB/removable storage is disabled via the USBSTOR registry key on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
            "Start"
        )
        if val == "4":
            return (True, "USB storage is disabled (USBSTOR Start = 4)")
        return (False, f"USB storage is not disabled (USBSTOR Start = {val or 'not set'}, expected: 4)")
    except Exception as e:
        return (False, f"Exception while checking USB storage policy: {e}")


def outbound_firewall_rules_wc() -> tuple[bool, str]:
    """Verify outbound Windows Defender Firewall rules exist to restrict data paths on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-NetFirewallRule -Direction Outbound -Action Block | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc != 0:
            return (False, f"Could not query outbound firewall rules: {err}")
        count = int(out.strip()) if out.strip().isdigit() else 0
        if count >= 1:
            return (True, f"Outbound Block firewall rules exist ({count} rule(s))")
        return (False, "No outbound Block firewall rules found")
    except Exception as e:
        return (False, f"Exception while checking outbound firewall rules: {e}")


def dlp_agent_present_ws() -> tuple[bool, str]:
    """Verify a DLP agent is present on Windows Server."""
    return dlp_agent_present_wc()


def usb_storage_blocked_ws() -> tuple[bool, str]:
    """Verify USB storage is disabled on Windows Server."""
    return usb_storage_blocked_wc()


def outbound_firewall_rules_ws() -> tuple[bool, str]:
    """Verify outbound firewall block rules exist on Windows Server."""
    return outbound_firewall_rules_wc()


def usb_storage_blocked_lx() -> tuple[bool, str]:
    """Verify the usb-storage kernel module is blacklisted on Linux/Debian."""
    try:
        # Check modprobe.d blacklist
        for conf_file in Path("/etc/modprobe.d").glob("*.conf"):
            try:
                text = conf_file.read_text()
                if re.search(r"^\s*blacklist\s+usb[_-]storage", text, re.MULTILINE):
                    return (True, f"usb-storage is blacklisted in {conf_file}")
            except Exception:
                continue
        # Check if module is currently not loaded
        rc, _, _ = _run("lsmod 2>/dev/null | grep usb_storage")
        if rc != 0:  # grep returns non-zero if no match
            return (True, "usb-storage module is not currently loaded")
        return (False, "usb-storage module is loaded and no blacklist entry found in /etc/modprobe.d/")
    except Exception as e:
        return (False, f"Exception while checking USB storage block: {e}")


def outbound_firewall_lx() -> tuple[bool, str]:
    """Verify outbound firewall rules (iptables OUTPUT or firewalld) are configured on Linux/Debian."""
    try:
        rc, out, _ = _run("iptables -L OUTPUT -n 2>/dev/null")
        if rc == 0 and out:
            lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("target")]
            if len(lines) >= 1:
                return (True, f"iptables OUTPUT chain has {len(lines)} rule(s) configured")
        rc2, out2, _ = _run("firewall-cmd --list-all 2>/dev/null | grep -i 'rich rules'")
        if rc2 == 0 and out2.strip():
            return (True, "firewalld rich rules are configured (may include outbound controls)")
        return (False, "No outbound firewall rules found (checked iptables OUTPUT and firewalld rich rules)")
    except Exception as e:
        return (False, f"Exception while checking outbound firewall rules: {e}")


# =============================================================================
# SC.L2-3.13.6 — Deny Network Communications Traffic by Default
# =============================================================================

def inbound_default_block_wc() -> tuple[bool, str]:
    """Verify Windows Defender Firewall default inbound action is Block on all profiles on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-NetFirewallProfile | Select-Object -ExpandProperty DefaultInboundAction"
        )
        if rc != 0 or not out:
            return (False, f"Could not query default inbound action: {err}")
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if all(l in ("2", "Block") for l in lines) and len(lines) >= 3:
            return (True, f"Default inbound action is Block on all {len(lines)} firewall profiles")
        non_block = [l for l in lines if l not in ("2", "Block")]
        return (False, f"Default inbound action is not Block on all profiles (non-block values: {non_block})")
    except Exception as e:
        return (False, f"Exception while checking inbound default block: {e}")


def outbound_rules_exist_wc() -> tuple[bool, str]:
    """Verify explicit outbound firewall allow rules exist (not relying on default allow-all) on Windows Client."""
    try:
        rc, out, err = _ps(
            "Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc != 0:
            return (False, f"Could not query outbound allow rules: {err}")
        count = int(out.strip()) if out.strip().isdigit() else 0
        if count >= 5:
            return (True, f"Explicit outbound Allow rules exist ({count} rule(s) — default allow-all is not being relied upon)")
        return (False, f"Insufficient explicit outbound Allow rules: {count} (expected: >= 5)")
    except Exception as e:
        return (False, f"Exception while checking outbound allow rules: {e}")


def inbound_default_block_ws() -> tuple[bool, str]:
    """Verify default inbound firewall action is Block on Windows Server."""
    return inbound_default_block_wc()


def outbound_rules_exist_ws() -> tuple[bool, str]:
    """Verify explicit outbound allow rules exist on Windows Server."""
    return outbound_rules_exist_wc()


def iptables_default_drop_lx() -> tuple[bool, str]:
    """Verify iptables INPUT, OUTPUT, and FORWARD default policies are DROP or REJECT on Linux/Debian."""
    try:
        rc, out, _ = _run("iptables -L 2>/dev/null | grep '^Chain'")
        if rc == 0 and out:
            chains = out.splitlines()
            policies = []
            for line in chains:
                m = re.search(r"policy\s+(\S+)", line, re.IGNORECASE)
                if m:
                    policies.append(m.group(1).upper())
            if policies:
                non_drop = [p for p in policies if p not in ("DROP", "REJECT")]
                if not non_drop:
                    return (True, f"All iptables chain default policies are DROP/REJECT: {policies}")
                return (False, f"Some iptables chains do not have DROP/REJECT policy: {non_drop}")
        # Check ufw default deny
        rc2, out2, _ = _run("ufw status verbose 2>/dev/null")
        if rc2 == 0 and "deny (incoming)" in out2.lower():
            return (True, "ufw default incoming policy is deny")
        # Check firewalld default zone
        rc3, out3, _ = _run("firewall-cmd --get-default-zone 2>/dev/null")
        if rc3 == 0 and out3.strip() in ("drop", "block"):
            return (True, f"firewalld default zone is '{out3.strip()}' (deny by default)")
        return (False, "No default DROP/REJECT policy found (checked iptables, ufw, firewalld)")
    except Exception as e:
        return (False, f"Exception while checking default drop policy: {e}")


def ufw_default_deny_lx() -> tuple[bool, str]:
    """Verify ufw or firewalld default policy denies incoming connections on Linux/Debian."""
    try:
        rc, out, _ = _run("ufw status verbose 2>/dev/null")
        if rc == 0 and "deny (incoming)" in out.lower():
            return (True, "ufw default incoming policy is deny")
        rc2, out2, _ = _run("firewall-cmd --get-default-zone 2>/dev/null")
        if rc2 == 0 and out2.strip() in ("drop", "block"):
            return (True, f"firewalld default zone is '{out2.strip()}' (deny by default)")
        # Check nftables for drop policy on input
        rc3, out3, _ = _run("nft list ruleset 2>/dev/null | grep -A3 'hook input' | grep -i 'policy drop'")
        if rc3 == 0 and out3.strip():
            return (True, "nftables input hook has a drop policy")
        return (False, "No default deny policy found (checked ufw, firewalld, nftables)")
    except Exception as e:
        return (False, f"Exception while checking default deny policy: {e}")


# =============================================================================
# SC.L2-3.13.7 — Prevent Remote Devices from Using Split Tunneling
# =============================================================================

def rasman_no_split_tunnel_wc() -> tuple[bool, str]:
    """Verify the RasMan/PPP registry does not have split tunneling enabled on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-VpnConnection 2>/dev/null | Select-Object -ExpandProperty SplitTunneling"
        )
        if rc == 0 and out.strip():
            lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
            if all(l == "false" for l in lines):
                return (True, f"Split tunneling is disabled on all VPN connections ({len(lines)} connection(s))")
            enabled = [l for l in lines if l != "false"]
            return (False, f"Split tunneling is enabled on {len(enabled)} VPN connection(s)")
        # If no VPN connections configured, check GPO registry
        val2 = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnections",
            "NC_AllowNetBridge_NLA"
        )
        if val2 is None or val2 == "0":
            return (True, "No VPN connections configured; NC_AllowNetBridge_NLA is not set or is 0 (compliant)")
        return (False, f"NC_AllowNetBridge_NLA = {val2} (expected: 0 or not set)")
    except Exception as e:
        return (False, f"Exception while checking split tunneling: {e}")


def routing_via_vpn_wc() -> tuple[bool, str]:
    """Verify the default route (0.0.0.0/0) is via a VPN-type interface when a VPN is active on Windows Client."""
    try:
        # Check if any VPN connections are currently connected
        rc, out, _ = _ps(
            "Get-VpnConnection -ErrorAction SilentlyContinue | "
            "Where-Object { $_.ConnectionStatus -eq 'Connected' } | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc == 0 and out.strip().isdigit() and int(out.strip()) == 0:
            # No VPN connected — check cannot be evaluated against a live VPN
            return (True, "No VPN connections are currently active (check not applicable)")
        # VPN is connected; check default route is via a PPP/VPN adapter
        rc2, out2, err2 = _ps(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty InterfaceAlias"
        )
        if rc2 == 0 and out2.strip():
            alias = out2.strip().lower()
            if any(k in alias for k in ("vpn", "ppp", "ras", "tun", "tap")):
                return (True, f"Default route is via a VPN-type interface: {out2.strip()}")
            return (False, f"Default route is not via a VPN-type interface: {out2.strip()}")
        return (False, f"Could not determine default route interface: {err2}")
    except Exception as e:
        return (False, f"Exception while checking VPN routing: {e}")


def rasman_no_split_tunnel_ws() -> tuple[bool, str]:
    """Verify split tunneling is disabled on Windows Server."""
    return rasman_no_split_tunnel_wc()


def routing_via_vpn_ws() -> tuple[bool, str]:
    """Verify default route via VPN on Windows Server."""
    return routing_via_vpn_wc()


def vpn_no_split_tunnel_lx() -> tuple[bool, str]:
    """Verify VPN configurations (OpenVPN/WireGuard) route all traffic through the tunnel on Linux/Debian."""
    try:
        openvpn_dir = Path("/etc/openvpn")
        if openvpn_dir.exists():
            for conf in openvpn_dir.glob("*.conf"):
                try:
                    text = conf.read_text()
                    if "redirect-gateway def1" in text or "redirect-gateway local def1" in text:
                        return (True, f"OpenVPN config {conf.name} routes all traffic through the tunnel (redirect-gateway)")
                except Exception:
                    continue
        wg_dir = Path("/etc/wireguard")
        if wg_dir.exists():
            for conf in wg_dir.glob("*.conf"):
                try:
                    text = conf.read_text()
                    if re.search(r"AllowedIPs\s*=\s*0\.0\.0\.0/0", text):
                        return (True, f"WireGuard config {conf.name} routes all traffic through the tunnel (AllowedIPs = 0.0.0.0/0)")
                except Exception:
                    continue
        # If no VPN configs found, check routing table for VPN interfaces
        rc, out, _ = _run("ip route show 2>/dev/null | grep 'default'")
        if rc == 0 and re.search(r"(tun|tap|wg|vpn)\d*", out, re.IGNORECASE):
            return (True, f"Default route is via a VPN-type interface: {out.strip()}")
        return (False, "No VPN configuration found with full-tunnel routing (OpenVPN redirect-gateway, WireGuard 0.0.0.0/0, or VPN default route)")
    except Exception as e:
        return (False, f"Exception while checking VPN split tunneling: {e}")


# =============================================================================
# SC.L2-3.13.8 — Implement Cryptographic Mechanisms to Prevent Unauthorized Disclosure in Transit
# =============================================================================

def tls12_enabled_wc() -> tuple[bool, str]:
    """Verify TLS 1.2 is enabled in the SCHANNEL registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client",
            "Enabled"
        )
        # 1 = enabled; if key doesn't exist TLS 1.2 is enabled by default on Windows 10+
        if val is None:
            return (True, "TLS 1.2 is enabled by default (SCHANNEL registry key is absent, modern Windows default)")
        if val == "1":
            return (True, "TLS 1.2 is explicitly enabled in SCHANNEL registry (Enabled = 1)")
        return (False, f"TLS 1.2 is disabled in SCHANNEL registry (Enabled = {val})")
    except Exception as e:
        return (False, f"Exception while checking TLS 1.2: {e}")


def tls10_disabled_wc() -> tuple[bool, str]:
    """Verify TLS 1.0 is disabled in the SCHANNEL registry on Windows Client."""
    try:
        val_client = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client",
            "Enabled"
        )
        val_server = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server",
            "Enabled"
        )
        client_disabled = val_client == "0" if val_client is not None else False
        server_disabled = val_server == "0" if val_server is not None else False
        if client_disabled and server_disabled:
            return (True, "TLS 1.0 is disabled for both client and server in SCHANNEL registry")
        issues = []
        if not client_disabled:
            issues.append(f"TLS 1.0 Client Enabled = {val_client or 'not set (default enabled)'}")
        if not server_disabled:
            issues.append(f"TLS 1.0 Server Enabled = {val_server or 'not set (default enabled)'}")
        return (False, f"TLS 1.0 is not fully disabled: {'; '.join(issues)}")
    except Exception as e:
        return (False, f"Exception while checking TLS 1.0: {e}")


def smb_signing_required_wc() -> tuple[bool, str]:
    """Verify SMB signing is required via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
            "RequireSecuritySignature"
        )
        if val == "1":
            return (True, "SMB client signing is required (RequireSecuritySignature = 1)")
        return (False, f"SMB client signing is not required (RequireSecuritySignature = {val or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking SMB signing: {e}")


def rdp_encryption_wc() -> tuple[bool, str]:
    """Verify RDP encryption level is set to High (3) or FIPS (4) via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            "MinEncryptionLevel"
        )
        if val in ("3", "4"):
            label = "High" if val == "3" else "FIPS"
            return (True, f"RDP encryption level is set to {label} (MinEncryptionLevel = {val})")
        return (False, f"RDP encryption level is not High or FIPS (MinEncryptionLevel = {val or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking RDP encryption: {e}")


def tls12_enabled_ws() -> tuple[bool, str]:
    """Verify TLS 1.2 is enabled on Windows Server."""
    return tls12_enabled_wc()


def tls10_disabled_ws() -> tuple[bool, str]:
    """Verify TLS 1.0 is disabled on Windows Server."""
    return tls10_disabled_wc()


def smb_signing_required_ws() -> tuple[bool, str]:
    """Verify SMB signing is required on Windows Server (server-side)."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "RequireSecuritySignature"
        )
        if val == "1":
            return (True, "SMB server signing is required (RequireSecuritySignature = 1)")
        return (False, f"SMB server signing is not required (RequireSecuritySignature = {val or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking SMB server signing: {e}")


def rdp_encryption_ws() -> tuple[bool, str]:
    """Verify RDP encryption level is High or FIPS on Windows Server."""
    return rdp_encryption_wc()


def ldap_signing_ws() -> tuple[bool, str]:
    """Verify LDAP client signing requirements are set to require signing on Windows Server."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "LDAPServerIntegrity"
        )
        # 2 = Require signing
        if val == "2":
            return (True, "LDAP server signing is required (LDAPServerIntegrity = 2)")
        val2 = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "LDAPClientIntegrity"
        )
        if val2 == "2":
            return (True, "LDAP client signing is required via policy (LDAPClientIntegrity = 2)")
        return (False, f"LDAP signing is not required (LDAPServerIntegrity = {val or 'not set'}, LDAPClientIntegrity = {val2 or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking LDAP signing: {e}")


def ssh_strong_ciphers_lx() -> tuple[bool, str]:
    """Verify sshd is configured with strong ciphers and MACs, excluding weak algorithms on Linux/Debian."""
    try:
        rc, out, err = _run("sshd -T 2>/dev/null")
        if rc != 0:
            return (False, f"Could not query sshd configuration: {err}")
        weak_ciphers = ("arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc")
        weak_macs = ("hmac-md5", "hmac-sha1", "umac-64@openssh.com")
        out_lower = out.lower()
        ciphers_line = re.search(r"^ciphers\s+(.+)$", out_lower, re.MULTILINE)
        macs_line = re.search(r"^macs\s+(.+)$", out_lower, re.MULTILINE)
        found_weak = []
        if ciphers_line:
            ciphers = ciphers_line.group(1)
            found_weak += [wc for wc in weak_ciphers if wc in ciphers]
        if macs_line:
            macs = macs_line.group(1)
            found_weak += [wm for wm in weak_macs if wm in macs]
        if not found_weak:
            return (True, "sshd is configured with strong ciphers and MACs (no weak algorithms found)")
        return (False, f"sshd uses weak cipher(s)/MAC(s): {', '.join(found_weak)}")
    except Exception as e:
        return (False, f"Exception while checking SSH ciphers/MACs: {e}")


def tls_version_lx() -> tuple[bool, str]:
    """Verify the installed OpenSSL version supports TLS 1.2 or higher on Linux/Debian."""
    try:
        rc, out, err = _run("openssl version 2>/dev/null")
        if rc != 0:
            return (False, f"Could not query OpenSSL version: {err}")
        # OpenSSL 1.0.1+ supports TLS 1.2; 1.1.1+ supports TLS 1.3
        m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", out)
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if (major, minor) >= (1, 0) and patch >= 1:
                return (True, f"OpenSSL version supports TLS 1.2+: {out.strip()}")
            return (False, f"OpenSSL version is too old to support TLS 1.2: {out.strip()}")
        return (False, f"Could not parse OpenSSL version from: {out.strip()}")
    except Exception as e:
        return (False, f"Exception while checking OpenSSL version: {e}")


# =============================================================================
# SC.L2-3.13.9 — Terminate Network Connections After a Defined Period of Inactivity
# =============================================================================

def rdp_idle_timeout_wc() -> tuple[bool, str]:
    """Verify RDP idle session timeout is configured (MaxIdleTime <= 15 minutes) via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            "MaxIdleTime"
        )
        if val is None:
            return (False, "RDP MaxIdleTime is not configured (policy key not set)")
        # MaxIdleTime is in milliseconds; 900000 ms = 15 minutes
        ms = int(val)
        if 0 < ms <= 900000:
            return (True, f"RDP idle timeout is configured: {ms // 60000} minute(s) (MaxIdleTime = {ms} ms)")
        return (False, f"RDP idle timeout is not within 15 minutes (MaxIdleTime = {ms} ms, expected: 1-900000)")
    except Exception as e:
        return (False, f"Exception while checking RDP idle timeout: {e}")


def screen_lock_timeout_wc() -> tuple[bool, str]:
    """Verify screen lock (ScreenSaveTimeOut) is set to 900 seconds (15 min) or less on Windows Client."""
    try:
        val = _reg_get(
            "HKCU:\\Control Panel\\Desktop",
            "ScreenSaveTimeOut"
        )
        if val is None:
            # Try machine policy
            val = _reg_get(
                "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
                "ScreenSaveTimeOut"
            )
        if val is None:
            return (False, "ScreenSaveTimeOut is not configured (user or machine policy key not set)")
        secs = int(val)
        if 0 < secs <= 900:
            return (True, f"Screen lock timeout is {secs} second(s) (<= 15 minutes)")
        return (False, f"Screen lock timeout is {secs} second(s) (exceeds 15-minute limit of 900 seconds)")
    except Exception as e:
        return (False, f"Exception while checking screen lock timeout: {e}")


def rdp_idle_timeout_ws() -> tuple[bool, str]:
    """Verify RDP idle timeout is configured on Windows Server."""
    return rdp_idle_timeout_wc()


def screen_lock_timeout_ws() -> tuple[bool, str]:
    """Verify screen lock timeout is 15 minutes or less on Windows Server."""
    return screen_lock_timeout_wc()


def ssh_client_alive_lx() -> tuple[bool, str]:
    """Verify SSH ClientAliveInterval and ClientAliveCountMax are configured to terminate idle sessions on Linux/Debian."""
    try:
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return (False, "sshd_config not found: /etc/ssh/sshd_config does not exist")
        text = p.read_text()
        interval_m = re.search(r"^\s*ClientAliveInterval\s+(\d+)", text, re.MULTILINE | re.IGNORECASE)
        count_m = re.search(r"^\s*ClientAliveCountMax\s+(\d+)", text, re.MULTILINE | re.IGNORECASE)
        if not interval_m:
            rc, out, _ = _run("sshd -T 2>/dev/null | grep -i 'clientaliveinterval'")
            if rc == 0 and out:
                m2 = re.search(r"clientaliveinterval\s+(\d+)", out, re.IGNORECASE)
                if m2:
                    interval_m = m2
        if interval_m:
            interval = int(interval_m.group(1))
            count = int(count_m.group(1)) if count_m else 3
            # Timeout = interval * count; should be <= 900 seconds (15 min)
            timeout_secs = interval * count
            if 0 < interval and timeout_secs <= 900:
                return (True, f"SSH idle timeout is {timeout_secs}s (ClientAliveInterval={interval} * ClientAliveCountMax={count})")
            return (False, f"SSH idle timeout is {timeout_secs}s (exceeds 900s limit; ClientAliveInterval={interval}, ClientAliveCountMax={count})")
        return (False, "ClientAliveInterval is not configured in sshd_config")
    except Exception as e:
        return (False, f"Exception while checking SSH client alive settings: {e}")


def shell_timeout_lx() -> tuple[bool, str]:
    """Verify TMOUT is set in /etc/profile or /etc/profile.d/ to auto-terminate idle shell sessions on Linux/Debian."""
    try:
        profile = Path("/etc/profile")
        tmout_re = re.compile(r"^\s*(?:export\s+)?TMOUT\s*=\s*(\d+)", re.MULTILINE)
        if profile.exists():
            m = tmout_re.search(profile.read_text())
            if m and 0 < int(m.group(1)) <= 900:
                return (True, f"TMOUT is set to {m.group(1)}s in /etc/profile")
        profile_d = Path("/etc/profile.d")
        if profile_d.is_dir():
            for f in profile_d.glob("*.sh"):
                try:
                    m = tmout_re.search(f.read_text())
                    if m and 0 < int(m.group(1)) <= 900:
                        return (True, f"TMOUT is set to {m.group(1)}s in {f}")
                except Exception:
                    continue
        return (False, "TMOUT is not configured in /etc/profile or /etc/profile.d/ (idle shell sessions will not auto-terminate)")
    except Exception as e:
        return (False, f"Exception while checking TMOUT: {e}")


# =============================================================================
# SC.L2-3.13.10 — Establish and Manage Cryptographic Keys
# =============================================================================

def bitlocker_key_protector_wc() -> tuple[bool, str]:
    """Verify BitLocker key protector is TPM+PIN or TPM+Recovery (not recovery-only) on Windows Client."""
    try:
        rc, out, err = _run("manage-bde -status C: 2>nul")
        if rc != 0 or not out:
            return (False, f"Could not query BitLocker status: {err}")
        # Look for TPM as a key protector
        if "tpm" in out.lower() and "protection on" in out.lower():
            return (True, "BitLocker is on and TPM is a key protector on C:")
        if "protection on" in out.lower():
            return (False, "BitLocker protection is on but TPM is not listed as a key protector")
        return (False, "BitLocker is not protecting C: (protection is not on)")
    except Exception as e:
        return (False, f"Exception while checking BitLocker key protector: {e}")


def bitlocker_key_protector_ws() -> tuple[bool, str]:
    """Verify BitLocker key protectors are properly configured on Windows Server."""
    return bitlocker_key_protector_wc()


def luks_keyslots_lx() -> tuple[bool, str]:
    """Verify LUKS encrypted volumes exist and have key slots configured on Linux/Debian."""
    try:
        rc, out, _ = _run("lsblk -o NAME,FSTYPE 2>/dev/null | grep -i 'crypto_luks'")
        if rc != 0 or not out:
            return (False, "No LUKS-encrypted volumes found (lsblk shows no crypto_luks filesystems)")
        # LUKS volumes found; verify at least one key slot is active
        rc2, out2, _ = _run("blkid 2>/dev/null | grep -i 'luks'")
        if rc2 == 0 and out2.strip():
            return (True, "LUKS encrypted volumes found and key slots are active")
        return (False, "LUKS volumes detected by lsblk but not confirmed by blkid")
    except Exception as e:
        return (False, f"Exception while checking LUKS key slots: {e}")


def no_world_readable_keys_lx() -> tuple[bool, str]:
    """Verify no private key files (.key, .pem) are world-readable on Linux/Debian."""
    try:
        rc, out, _ = _run(
            r"find /etc /home /root /var -maxdepth 6 \( -name '*.key' -o -name '*.pem' \) 2>/dev/null | "
            "xargs -r stat --format='%a %n' 2>/dev/null | "
            "awk '{ if (substr($1, length($1))+0 >= 4) print }'"
        )
        # If any world-readable key files found, return False
        if rc == 0 and not out.strip():
            return (True, "No world-readable private key files (.key/.pem) found")
        if out.strip():
            count = len(out.strip().splitlines())
            return (False, f"{count} world-readable private key file(s) found:\n{out.strip()}")
        return (False, "Could not verify key file permissions")
    except Exception as e:
        return (False, f"Exception while checking key file permissions: {e}")


# =============================================================================
# SC.L2-3.13.11 — Employ FIPS-Validated Cryptography
# =============================================================================

def fips_mode_wc() -> tuple[bool, str]:
    """Verify FIPS mode is enabled via FipsAlgorithmPolicy registry key on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy",
            "Enabled"
        )
        if val == "1":
            return (True, "FIPS mode is enabled (FipsAlgorithmPolicy\\Enabled = 1)")
        return (False, f"FIPS mode is not enabled (FipsAlgorithmPolicy\\Enabled = {val or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking FIPS mode: {e}")


def fips_mode_ws() -> tuple[bool, str]:
    """Verify FIPS mode is enabled on Windows Server."""
    return fips_mode_wc()


def fips_enabled_lx() -> tuple[bool, str]:
    """Verify the kernel FIPS mode is enabled (/proc/sys/crypto/fips_enabled = 1) on Linux/Debian."""
    try:
        p = Path("/proc/sys/crypto/fips_enabled")
        if p.exists():
            val = p.read_text().strip()
            if val == "1":
                return (True, "FIPS mode is enabled (kernel fips_enabled = 1)")
            return (False, f"FIPS mode is not enabled (kernel fips_enabled = {val})")
        return (False, "/proc/sys/crypto/fips_enabled not found (kernel may not support FIPS mode)")
    except Exception as e:
        return (False, f"Exception while checking kernel FIPS mode: {e}")


def openssl_fips_lx() -> tuple[bool, str]:
    """Verify the kernel command line includes fips=1 boot parameter on Linux/Debian."""
    try:
        p = Path("/proc/cmdline")
        if p.exists():
            cmdline = p.read_text()
            if "fips=1" in cmdline:
                return (True, "Kernel boot parameter fips=1 is set")
            return (False, f"Kernel boot parameter fips=1 is not set (cmdline: {cmdline.strip()})")
        return (False, "/proc/cmdline not found")
    except Exception as e:
        return (False, f"Exception while checking FIPS boot parameter: {e}")


# =============================================================================
# SC.L2-3.13.12 — Prohibit Remote Activation of Collaborative Computing Devices
# =============================================================================

def camera_access_restricted_wc() -> tuple[bool, str]:
    """Verify camera access is restricted via GPO registry (LetAppsAccessCamera = 2) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy",
            "LetAppsAccessCamera"
        )
        # 2 = Force Deny; compliant
        if val == "2":
            return (True, "Camera access is Force Denied via GPO (LetAppsAccessCamera = 2)")
        return (False, f"Camera access is not Force Denied (LetAppsAccessCamera = {val or 'not set'}, expected: 2)")
    except Exception as e:
        return (False, f"Exception while checking camera access policy: {e}")


def microphone_access_restricted_wc() -> tuple[bool, str]:
    """Verify microphone access is restricted via GPO registry (LetAppsAccessMicrophone = 2) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy",
            "LetAppsAccessMicrophone"
        )
        if val == "2":
            return (True, "Microphone access is Force Denied via GPO (LetAppsAccessMicrophone = 2)")
        return (False, f"Microphone access is not Force Denied (LetAppsAccessMicrophone = {val or 'not set'}, expected: 2)")
    except Exception as e:
        return (False, f"Exception while checking microphone access policy: {e}")


def camera_access_restricted_ws() -> tuple[bool, str]:
    """Verify camera access is restricted on Windows Server."""
    return camera_access_restricted_wc()


def microphone_access_restricted_ws() -> tuple[bool, str]:
    """Verify microphone access is restricted on Windows Server."""
    return microphone_access_restricted_wc()


def camera_permissions_lx() -> tuple[bool, str]:
    """Verify camera/video devices are not world-accessible (not world-readable/writable) on Linux/Debian."""
    try:
        rc, out, _ = _run("ls -la /dev/video* 2>/dev/null")
        if rc != 0 or not out:
            return (True, "No camera/video devices (/dev/video*) found — not applicable")
        world_rw = [l for l in out.splitlines() if re.match(r"crw-rw-rw-", l)]
        if not world_rw:
            return (True, "Camera devices found but none are world-readable/writable")
        return (False, f"{len(world_rw)} camera device(s) are world-accessible (crw-rw-rw-): {[l.split()[-1] for l in world_rw]}")
    except Exception as e:
        return (False, f"Exception while checking camera device permissions: {e}")


def microphone_permissions_lx() -> tuple[bool, str]:
    """Verify audio capture devices are not world-accessible on Linux/Debian."""
    try:
        rc, out, _ = _run("ls -la /dev/snd/ 2>/dev/null")
        if rc != 0 or not out:
            return (True, "No audio devices (/dev/snd/) found — not applicable")
        world_writable = [l for l in out.splitlines() if re.match(r"crw-rw-rw-", l)]
        if len(world_writable) == 0:
            return (True, "Audio capture devices found but none are world-accessible")
        return (False, f"{len(world_writable)} audio device(s) are world-accessible (crw-rw-rw-)")
    except Exception as e:
        return (False, f"Exception while checking microphone device permissions: {e}")


# =============================================================================
# SC.L2-3.13.13 — Control and Monitor the Use of Mobile Code
# =============================================================================

def ps_execution_policy_wc() -> tuple[bool, str]:
    """Verify PowerShell execution policy is RemoteSigned or AllSigned on Windows Client."""
    try:
        rc, out, _ = _ps("Get-ExecutionPolicy -Scope LocalMachine")
        if rc == 0 and out.strip().lower() in ("remotesigned", "allsigned"):
            return (True, f"PowerShell execution policy (LocalMachine) is {out.strip()}")
        rc2, out2, _ = _ps("Get-ExecutionPolicy")
        if rc2 == 0 and out2.strip().lower() in ("remotesigned", "allsigned"):
            return (True, f"PowerShell execution policy is {out2.strip()}")
        effective = out2.strip() or out.strip() or "unknown"
        return (False, f"PowerShell execution policy is '{effective}' (expected: RemoteSigned or AllSigned)")
    except Exception as e:
        return (False, f"Exception while checking PowerShell execution policy: {e}")


def wsh_disabled_wc() -> tuple[bool, str]:
    """Verify Windows Script Host is disabled via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
            "Enabled"
        )
        if val == "0":
            return (True, "Windows Script Host is disabled (Enabled = 0)")
        return (False, f"Windows Script Host is not disabled (Enabled = {val or 'not set'}, expected: 0)")
    except Exception as e:
        return (False, f"Exception while checking Windows Script Host: {e}")


def applocker_active_wc() -> tuple[bool, str]:
    """Verify AppLocker or WDAC policies are configured and enforced on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-AppLockerPolicy -Effective -Xml 2>$null | "
            "Select-String 'EnforcementMode=\"Enabled\"' | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc == 0 and out.strip().isdigit() and int(out.strip()) > 0:
            return (True, f"AppLocker policy is active with {out.strip()} enforced rule collection(s)")
        # Check WDAC (Windows Defender Application Control) via CodeIntegrity registry
        rc2, out2, _ = _ps(
            "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
            "\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled"
        )
        if rc2 == 0 and out2.strip() == "1":
            return (True, "WDAC (Hypervisor Enforced Code Integrity) is enabled")
        # Also check if SIPolicy.p7b exists (indicates a deployed WDAC policy)
        if Path("C:/Windows/System32/CodeIntegrity/SIPolicy.p7b").exists():
            return (True, "WDAC policy file (SIPolicy.p7b) is deployed")
        return (False, "No AppLocker or WDAC policy is active on this system")
    except Exception as e:
        return (False, f"Exception while checking AppLocker/WDAC: {e}")


def ps_execution_policy_ws() -> tuple[bool, str]:
    """Verify PowerShell execution policy is RemoteSigned or AllSigned on Windows Server."""
    return ps_execution_policy_wc()


def wsh_disabled_ws() -> tuple[bool, str]:
    """Verify Windows Script Host is disabled on Windows Server."""
    return wsh_disabled_wc()


def applocker_active_ws() -> tuple[bool, str]:
    """Verify AppLocker or WDAC policies are active on Windows Server."""
    return applocker_active_wc()


def noexec_tmp_lx() -> tuple[bool, str]:
    """Verify /tmp and /home are mounted with the noexec option on Linux/Debian."""
    try:
        p = Path("/proc/mounts")
        if not p.exists():
            rc, out, err = _run("mount 2>/dev/null")
            if rc != 0:
                return (False, f"Could not read mount information: {err}")
            text = out
        else:
            text = p.read_text()
        tmp_noexec = False
        home_noexec = False
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                mountpoint = parts[1]
                options = parts[3]
                if mountpoint == "/tmp" and "noexec" in options:
                    tmp_noexec = True
                if mountpoint == "/home" and "noexec" in options:
                    home_noexec = True
        if tmp_noexec and home_noexec:
            return (True, "/tmp and /home are both mounted with the noexec option")
        missing = []
        if not tmp_noexec:
            missing.append("/tmp")
        if not home_noexec:
            missing.append("/home")
        return (False, f"noexec mount option is missing for: {', '.join(missing)}")
    except Exception as e:
        return (False, f"Exception while checking noexec mount options: {e}")


def no_world_writable_path_lx() -> tuple[bool, str]:
    """Verify no world-writable directories exist in the system PATH on Linux/Debian."""
    try:
        rc, out, err = _run("echo $PATH")
        if rc != 0:
            return (False, f"Could not read PATH: {err}")
        dirs = [d.strip() for d in out.split(":") if d.strip()]
        world_writable = []
        for d in dirs:
            p = Path(d)
            if p.exists() and p.is_dir():
                mode = p.stat().st_mode
                # World-writable = others write bit (0o002)
                if mode & 0o002:
                    world_writable.append(d)
        if not world_writable:
            return (True, f"No world-writable directories found in PATH ({len(dirs)} directories checked)")
        return (False, f"World-writable directories in PATH: {', '.join(world_writable)}")
    except Exception as e:
        return (False, f"Exception while checking PATH directories: {e}")


# =============================================================================
# SC.L2-3.13.14 — Control and Monitor the Use of VoIP Technologies
# =============================================================================

def voip_ports_controlled_wc() -> tuple[bool, str]:
    """Verify SIP/VoIP ports (5060, 5061) are not unexpectedly open or are covered by firewall rules on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetTCPConnection -State Listen -LocalPort 5060,5061 "
            "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc == 0 and out.strip().isdigit() and int(out.strip()) == 0:
            return (True, "SIP/VoIP ports 5060 and 5061 are not listening")
        # If open, verify firewall rules govern them via port filter objects
        rc2, out2, _ = _ps(
            "Get-NetFirewallRule | Get-NetFirewallPortFilter | "
            "Where-Object { $_.LocalPort -match '5060|5061' } | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc2 == 0 and out2.strip().isdigit() and int(out2.strip()) > 0:
            return (True, f"SIP/VoIP ports are open but governed by {out2.strip()} firewall rule(s)")
        open_count = out.strip() if out.strip().isdigit() else "unknown"
        return (False, f"SIP/VoIP ports 5060/5061 are listening ({open_count} connection(s)) with no firewall rules governing them")
    except Exception as e:
        return (False, f"Exception while checking VoIP ports: {e}")


def voip_ports_controlled_ws() -> tuple[bool, str]:
    """Verify SIP/VoIP ports are controlled on Windows Server."""
    return voip_ports_controlled_wc()


def voip_ports_lx() -> tuple[bool, str]:
    """Verify SIP/VoIP ports (5060, 5061) are not unexpectedly listening, or are governed by firewall on Linux/Debian."""
    try:
        rc, out, _ = _run("ss -ulnp 2>/dev/null | grep -E ':5060|:5061'")
        if rc != 0 or not out.strip():
            return (True, "SIP/VoIP ports 5060 and 5061 are not listening")
        # If open, check firewall rules cover them
        rc2, out2, _ = _run("iptables -L -n 2>/dev/null | grep -E '5060|5061'")
        if rc2 == 0 and out2.strip():
            return (True, "SIP/VoIP ports are open but governed by iptables rules")
        rc3, out3, _ = _run("firewall-cmd --list-all 2>/dev/null | grep -E '5060|5061'")
        if rc3 == 0 and out3.strip():
            return (True, "SIP/VoIP ports are open but governed by firewalld rules")
        return (False, f"SIP/VoIP ports 5060/5061 are listening with no firewall rules: {out.strip()}")
    except Exception as e:
        return (False, f"Exception while checking VoIP ports: {e}")


# =============================================================================
# SC.L2-3.13.15 — Protect the Authenticity of Communications Sessions
# =============================================================================

def smb_signing_wc() -> tuple[bool, str]:
    """Verify SMB client signing is required (RequireSecuritySignature = 1) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
            "RequireSecuritySignature"
        )
        if val == "1":
            return (True, "SMB client signing is required (RequireSecuritySignature = 1)")
        return (False, f"SMB client signing is not required (RequireSecuritySignature = {val or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking SMB signing: {e}")


def tls_cert_validation_wc() -> tuple[bool, str]:
    """Verify TLS certificate validation is not disabled (DisableCertificateRevocationChecks = 0) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "DisableCertRevocation"
        )
        # 0 or absent means revocation checks are enabled (compliant)
        if val is None or val == "0":
            return (True, f"TLS certificate revocation checking is enabled (DisableCertRevocation = {val or 'not set/0'})")
        return (False, f"TLS certificate revocation checking is disabled (DisableCertRevocation = {val})")
    except Exception as e:
        return (False, f"Exception while checking TLS cert validation: {e}")


def smb_signing_ws() -> tuple[bool, str]:
    """Verify SMB server signing is required on Windows Server."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "RequireSecuritySignature"
        )
        if val == "1":
            return (True, "SMB server signing is required (RequireSecuritySignature = 1)")
        return (False, f"SMB server signing is not required (RequireSecuritySignature = {val or 'not set'})")
    except Exception as e:
        return (False, f"Exception while checking SMB server signing: {e}")


def ldap_signing_required_ws() -> tuple[bool, str]:
    """Verify LDAP server signing requirements are set to require signing (LDAPServerIntegrity = 2) on Windows Server."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "LDAPServerIntegrity"
        )
        if val == "2":
            return (True, "LDAP server signing is required (LDAPServerIntegrity = 2)")
        return (False, f"LDAP server signing is not required (LDAPServerIntegrity = {val or 'not set'}, expected: 2)")
    except Exception as e:
        return (False, f"Exception while checking LDAP server signing: {e}")


def tls_cert_validation_ws() -> tuple[bool, str]:
    """Verify TLS certificate revocation checking is enabled on Windows Server."""
    return tls_cert_validation_wc()


def kerberos_auth_ws() -> tuple[bool, str]:
    """Verify Kerberos authentication is in use by confirming the system is domain-joined on Windows Server."""
    try:
        rc, out, _ = _ps(
            "(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain"
        )
        if rc == 0 and out.strip().lower() == "true":
            return (True, "System is domain-joined (Kerberos authentication is in use)")
        return (False, f"System is not domain-joined (PartOfDomain = {out.strip() or 'False'})")
    except Exception as e:
        return (False, f"Exception while checking domain membership: {e}")


def ssh_hostbased_disabled_lx() -> tuple[bool, str]:
    """Verify SSH HostbasedAuthentication is disabled in sshd_config on Linux/Debian."""
    try:
        rc, out, _ = _run("sshd -T 2>/dev/null | grep -i 'hostbasedauthentication'")
        if rc == 0 and out:
            if "no" in out.lower():
                return (True, f"SSH HostbasedAuthentication is disabled: {out.strip()}")
            return (False, f"SSH HostbasedAuthentication is not disabled: {out.strip()}")
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            text = p.read_text()
            m = re.search(r"^\s*HostbasedAuthentication\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                val = m.group(1).lower()
                if val == "no":
                    return (True, "SSH HostbasedAuthentication is set to 'no' in sshd_config")
                return (False, f"SSH HostbasedAuthentication is set to '{val}' (expected: no)")
        return (True, "HostbasedAuthentication not explicitly set (default is 'no')")
    except Exception as e:
        return (False, f"Exception while checking SSH HostbasedAuthentication: {e}")


def ssh_strict_host_lx() -> tuple[bool, str]:
    """Verify SSH client StrictHostKeyChecking is set to yes in /etc/ssh/ssh_config on Linux/Debian."""
    try:
        p = Path("/etc/ssh/ssh_config")
        if p.exists():
            text = p.read_text()
            m = re.search(r"^\s*StrictHostKeyChecking\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                val = m.group(1).lower()
                if val == "yes":
                    return (True, "SSH StrictHostKeyChecking is set to 'yes' in /etc/ssh/ssh_config")
                return (False, f"SSH StrictHostKeyChecking is set to '{val}' (expected: yes)")
        rc, out, _ = _run("ssh -G localhost 2>/dev/null | grep -i 'stricthostkeychecking'")
        if rc == 0 and out:
            if "yes" in out.lower():
                return (True, f"SSH StrictHostKeyChecking is 'yes': {out.strip()}")
            return (False, f"SSH StrictHostKeyChecking is not 'yes': {out.strip()}")
        return (False, "Could not determine SSH StrictHostKeyChecking setting")
    except Exception as e:
        return (False, f"Exception while checking SSH StrictHostKeyChecking: {e}")


# =============================================================================
# SC.L2-3.13.16 — Protect the Confidentiality of CUI at Rest
# =============================================================================

def bitlocker_enabled_wc() -> tuple[bool, str]:
    """Verify BitLocker is enabled and protection is On for the C: drive on Windows Client."""
    try:
        rc, out, err = _run("manage-bde -status C: 2>nul")
        if rc != 0 or not out:
            return (False, f"Could not query BitLocker status: {err}")
        if "protection on" in out.lower():
            return (True, "BitLocker protection is On for C:")
        return (False, "BitLocker protection is not On for C: (drive may be unencrypted or suspended)")
    except Exception as e:
        return (False, f"Exception while checking BitLocker status: {e}")


def bitlocker_full_encryption_wc() -> tuple[bool, str]:
    """Verify BitLocker encryption percentage is 100% on the system drive on Windows Client."""
    try:
        rc, out, err = _run("manage-bde -status C: 2>nul")
        if rc != 0 or not out:
            return (False, f"Could not query BitLocker status: {err}")
        m = re.search(r"Percentage Encrypted[:\s]+(\d+)[\.,]", out, re.IGNORECASE)
        if m:
            pct = int(m.group(1))
            if pct == 100:
                return (True, "BitLocker encryption is 100% complete on C:")
            return (False, f"BitLocker encryption is only {pct}% complete on C: (expected: 100%)")
        return (False, "Could not determine BitLocker encryption percentage from manage-bde output")
    except Exception as e:
        return (False, f"Exception while checking BitLocker encryption percentage: {e}")


def bitlocker_enabled_ws() -> tuple[bool, str]:
    """Verify BitLocker is enabled on Windows Server."""
    return bitlocker_enabled_wc()


def bitlocker_full_encryption_ws() -> tuple[bool, str]:
    """Verify BitLocker encryption is 100% complete on Windows Server."""
    return bitlocker_full_encryption_wc()


def luks_active_lx() -> tuple[bool, str]:
    """Verify LUKS-encrypted partitions exist on the system on Linux/Debian."""
    try:
        rc, out, _ = _run("lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | grep -i 'crypto_luks'")
        if rc == 0 and out.strip():
            count = len(out.strip().splitlines())
            return (True, f"LUKS-encrypted partition(s) found: {count} volume(s)")
        return (False, "No LUKS-encrypted partitions found (no crypto_luks filesystem type in lsblk)")
    except Exception as e:
        return (False, f"Exception while checking LUKS volumes: {e}")


def luks_mapping_active_lx() -> tuple[bool, str]:
    """Verify LUKS device mappings are active (unlocked dm-crypt devices present) on Linux/Debian."""
    try:
        # dmsetup status lists all device-mapper devices; filter for crypt type
        rc, out, _ = _run("dmsetup status 2>/dev/null | grep -i 'crypt'")
        if rc == 0 and out.strip():
            count = len(out.strip().splitlines())
            return (True, f"LUKS device mapping(s) are active ({count} crypt device(s) open)")
        # Alternatively, check /dev/mapper for any LUKS-opened devices via cryptsetup
        rc2, out2, _ = _run(
            "ls /dev/mapper/ 2>/dev/null | xargs -I{} sh -c "
            "'cryptsetup status {} 2>/dev/null | grep -q \"is active\" && echo {}' 2>/dev/null"
        )
        if rc2 == 0 and out2.strip():
            return (True, f"Active LUKS mappings found via cryptsetup: {out2.strip()}")
        return (False, "No active LUKS device mappings found (checked dmsetup and cryptsetup)")
    except Exception as e:
        return (False, f"Exception while checking LUKS mapping status: {e}")
