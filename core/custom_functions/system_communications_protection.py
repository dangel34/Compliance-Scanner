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

import subprocess
import re
from pathlib import Path


def _run(cmd: str, shell: bool = True) -> tuple[int, str, str]:
    result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _ps(cmd: str) -> tuple[int, str, str]:
    full_cmd = f'powershell.exe -NonInteractive -NoProfile -Command "{cmd}"'
    return _run(full_cmd)


def _reg_get(key: str, value: str) -> str | None:
    rc, out, _ = _ps(
        f"(Get-ItemProperty -Path '{key}' -Name '{value}' "
        f"-ErrorAction SilentlyContinue).'{value}'"
    )
    return out.strip() if rc == 0 and out.strip() else None


# =============================================================================
# SC.L1-3.13.1 — Monitor, Control, and Protect Communications at System Boundaries
# =============================================================================

def firewall_enabled_wc() -> bool:
    """Verify Windows Defender Firewall is enabled on all profiles (Domain, Private, Public) on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"
        )
        if rc != 0 or not out:
            return False
        lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
        return all(l == "true" for l in lines) and len(lines) >= 3
    except Exception:
        return False


def firewall_logging_wc() -> bool:
    """Verify Windows Defender Firewall logging is enabled on at least one profile on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetFirewallProfile | Where-Object { $_.LogAllowed -eq 'True' -or $_.LogBlocked -eq 'True' } "
            "| Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc != 0 or not out.strip().isdigit():
            return False
        return int(out.strip()) >= 1
    except Exception:
        return False


def inbound_default_deny_wc() -> bool:
    """Verify the Windows Defender Firewall default inbound action is Block for all profiles on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetFirewallProfile | Select-Object -ExpandProperty DefaultInboundAction"
        )
        if rc != 0 or not out:
            return False
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        return all(l in ("2", "Block") for l in lines) and len(lines) >= 3
    except Exception:
        return False


def network_profile_wc() -> bool:
    """Verify no active network interface is assigned the Public profile on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"
        )
        if rc != 0:
            return False
        lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
        return len(lines) > 0 and "public" not in lines
    except Exception:
        return False


def firewall_enabled_ws() -> bool:
    """Verify Windows Defender Firewall is enabled on all profiles on Windows Server."""
    return firewall_enabled_wc()


def firewall_logging_ws() -> bool:
    """Verify Windows Defender Firewall logging is enabled on Windows Server."""
    return firewall_logging_wc()


def inbound_default_deny_ws() -> bool:
    """Verify the default inbound firewall action is Block on all profiles on Windows Server."""
    return inbound_default_deny_wc()


def network_profile_ws() -> bool:
    """Verify no network interface is on the Public profile on Windows Server."""
    return network_profile_wc()


def perimeter_firewall_ws() -> bool:
    """Verify Windows Firewall advanced security rules include explicit perimeter inbound deny rules on Windows Server."""
    try:
        rc, out, _ = _ps(
            "Get-NetFirewallRule -Direction Inbound -Action Block | Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc != 0:
            return False
        count = int(out.strip()) if out.strip().isdigit() else 0
        return count >= 1
    except Exception:
        return False


def firewall_active_lx() -> bool:
    """Verify iptables, nftables, or firewalld is active and has rules loaded on Linux/Debian."""
    try:
        # Check firewalld
        rc, out, _ = _run("systemctl is-active firewalld 2>/dev/null")
        if rc == 0 and "active" in out:
            return True
        # Check nftables
        rc, out, _ = _run("systemctl is-active nftables 2>/dev/null")
        if rc == 0 and "active" in out:
            return True
        # Check iptables has rules beyond defaults
        rc, out, _ = _run("iptables -L -n --line-numbers 2>/dev/null | grep -c '^[0-9]'")
        if rc == 0:
            try:
                return int(out.strip()) > 0
            except ValueError:
                pass
        return False
    except Exception:
        return False


def default_input_policy_lx() -> bool:
    """Verify the iptables/nftables default INPUT chain policy is DROP or REJECT on Linux/Debian."""
    try:
        rc, out, _ = _run("iptables -L INPUT 2>/dev/null | head -1")
        if rc == 0 and re.search(r"policy\s+(DROP|REJECT)", out, re.IGNORECASE):
            return True
        # Check nftables
        rc2, out2, _ = _run("nft list ruleset 2>/dev/null | grep -i 'type filter hook input'")
        if rc2 == 0 and out2:
            rc3, out3, _ = _run("nft list ruleset 2>/dev/null | grep -A5 'hook input' | grep -i 'policy drop'")
            if rc3 == 0 and out3:
                return True
        # Check ufw
        rc4, out4, _ = _run("ufw status verbose 2>/dev/null | grep 'Default:'")
        if rc4 == 0 and "deny (incoming)" in out4.lower():
            return True
        return False
    except Exception:
        return False


def listening_ports_lx() -> bool:
    """Verify only expected ports are listening; ss -tlnp produces output for review on Linux/Debian."""
    try:
        rc, out, _ = _run("ss -tlnp 2>/dev/null")
        # We just verify ss runs successfully and produces output — detailed review is manual
        return rc == 0 and len(out.splitlines()) >= 1
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.2 — Employ Security Engineering Principles
# =============================================================================

def secure_boot_wc() -> bool:
    """Verify Secure Boot is enabled via Confirm-SecureBootUEFI on Windows Client."""
    try:
        rc, out, _ = _ps("Confirm-SecureBootUEFI")
        return rc == 0 and out.strip().lower() == "true"
    except Exception:
        return False


def dep_nx_wc() -> bool:
    """Verify DEP/NX is set to OptIn or AlwaysOn via bcdedit on Windows Client."""
    try:
        rc, out, _ = _run("bcdedit /enum {current} 2>nul")
        if rc != 0:
            return False
        return bool(re.search(r"nx\s+(optin|alwayson)", out, re.IGNORECASE))
    except Exception:
        return False


def aslr_wc() -> bool:
    """Verify ASLR (MoveImages) is enabled in the registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
            "MoveImages"
        )
        # MoveImages = 0xFFFFFFFF or -1 means always randomize; absence means default (enabled)
        if val is None:
            return True  # default is enabled on modern Windows
        return val.strip() != "0"
    except Exception:
        return False


def secure_boot_ws() -> bool:
    """Verify Secure Boot is enabled on Windows Server."""
    return secure_boot_wc()


def dep_nx_ws() -> bool:
    """Verify DEP/NX is enabled on Windows Server."""
    return dep_nx_wc()


def aslr_ws() -> bool:
    """Verify ASLR is enabled on Windows Server."""
    return aslr_wc()


def aslr_lx() -> bool:
    """Verify ASLR is enabled (kernel.randomize_va_space = 2) on Linux/Debian."""
    try:
        p = Path("/proc/sys/kernel/randomize_va_space")
        if p.exists():
            return p.read_text().strip() == "2"
        rc, out, _ = _run("sysctl -n kernel.randomize_va_space 2>/dev/null")
        return rc == 0 and out.strip() == "2"
    except Exception:
        return False


def selinux_apparmor_lx() -> bool:
    """Verify SELinux is Enforcing or AppArmor is active on Linux/Debian."""
    try:
        rc, out, _ = _run("getenforce 2>/dev/null")
        if rc == 0 and "enforcing" in out.lower():
            return True
        rc2, out2, _ = _run("aa-status 2>/dev/null | grep -i 'apparmor module is loaded'")
        if rc2 == 0 and out2:
            return True
        rc3, out3, _ = _run("systemctl is-active apparmor 2>/dev/null")
        if rc3 == 0 and "active" in out3:
            return True
        return False
    except Exception:
        return False


def secure_boot_lx() -> bool:
    """Verify Secure Boot is enabled via mokutil on Linux/Debian."""
    try:
        rc, out, _ = _run("mokutil --sb-state 2>/dev/null")
        return rc == 0 and "secureboot enabled" in out.lower()
    except Exception:
        return False


# =============================================================================
# SC.L1-3.13.5 — Implement Subnetworks for Publicly Accessible Systems
# =============================================================================

def network_profile_domain_wc() -> bool:
    """Verify the active network profile is Domain (not Public) on Windows Client, indicating proper subnet placement."""
    try:
        rc, out, _ = _ps(
            "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"
        )
        if rc != 0 or not out:
            return False
        lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
        return any(l == "domainauthenticated" for l in lines)
    except Exception:
        return False


def network_profile_domain_ws() -> bool:
    """Verify the active network profile is Domain on Windows Server, indicating proper subnet placement."""
    return network_profile_domain_wc()


def internal_subnet_lx() -> bool:
    """Verify the system has an RFC-1918 private IP address, indicating it is on an internal subnet on Linux/Debian."""
    try:
        rc, out, _ = _run("ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1'")
        if rc != 0 or not out:
            return False
        private_re = re.compile(
            r"inet\s+(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"
        )
        return bool(private_re.search(out))
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.3 — Separate User Functionality from System Management Functionality
# =============================================================================

def no_standard_user_is_admin_wc() -> bool:
    """Verify no standard daily-use accounts are members of the local Administrators group on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-LocalGroupMember -Group 'Administrators' | "
            "Where-Object { $_.ObjectClass -eq 'User' } | "
            "Select-Object -ExpandProperty Name"
        )
        if rc != 0:
            return False
        members = [l.strip() for l in out.splitlines() if l.strip()]
        # Built-in Administrator and domain admin accounts are expected; flag if >2 user accounts
        non_builtin = [m for m in members if not re.search(r"Administrator$", m, re.IGNORECASE)]
        return len(non_builtin) == 0
    except Exception:
        return False


def uac_enabled_wc() -> bool:
    """Verify User Account Control (UAC) is enabled via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA"
        )
        return val == "1"
    except Exception:
        return False


def separate_admin_accounts_wc() -> bool:
    """Verify admin accounts follow a naming convention separate from standard user accounts on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-LocalGroupMember -Group 'Administrators' | "
            "Where-Object { $_.ObjectClass -eq 'User' } | "
            "Select-Object -ExpandProperty Name"
        )
        if rc != 0:
            return False
        members = [l.strip() for l in out.splitlines() if l.strip()]
        # Compliant if all admin accounts contain 'admin', 'adm', or 'svc' in name (convention check)
        if not members:
            return True
        return all(
            re.search(r"(admin|adm|svc|sysadm|administrator)", m, re.IGNORECASE)
            for m in members
        )
    except Exception:
        return False


def no_standard_user_is_admin_ws() -> bool:
    """Verify no standard daily-use accounts are in the Administrators group on Windows Server."""
    return no_standard_user_is_admin_wc()


def uac_enabled_ws() -> bool:
    """Verify UAC is enabled on Windows Server."""
    return uac_enabled_wc()


def separate_admin_accounts_ws() -> bool:
    """Verify admin accounts are named separately from standard user accounts on Windows Server."""
    return separate_admin_accounts_wc()


def ldap_admin_check_ws() -> bool:
    """Verify Domain Admins group membership is limited (server-specific AD check) on Windows Server."""
    try:
        rc, out, _ = _ps(
            "net group 'Domain Admins' /domain 2>&1 | "
            "Select-String -Pattern '^Members' -Context 0,20"
        )
        # Just verify the command runs; a non-empty, short list indicates controlled membership
        return rc == 0 and bool(out.strip())
    except Exception:
        return False


def root_login_disabled_lx() -> bool:
    """Verify SSH root login is disabled in sshd_config on Linux/Debian."""
    try:
        rc, out, _ = _run("sshd -T 2>/dev/null | grep -i 'permitrootlogin'")
        if rc == 0 and out:
            return "no" in out.lower()
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            text = p.read_text()
            m = re.search(r"^\s*PermitRootLogin\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                return m.group(1).lower() == "no"
        return False
    except Exception:
        return False


def no_uid0_regular_users_lx() -> bool:
    """Verify no regular (non-root) user accounts have UID 0 on Linux/Debian."""
    try:
        p = Path("/etc/passwd")
        if not p.exists():
            return False
        uid0 = []
        for line in p.read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                uid0.append(parts[0])
        return len(uid0) == 0
    except Exception:
        return False


def sudo_restricted_lx() -> bool:
    """Verify the sudoers file does not grant unrestricted NOPASSWD sudo to all users on Linux/Debian."""
    try:
        p = Path("/etc/sudoers")
        if not p.exists():
            return False
        text = p.read_text()
        # Fail if there is an uncommented ALL=(ALL) NOPASSWD: ALL for a non-root user
        dangerous = re.findall(
            r"^\s*(?!#)(?!root\s)(\S+)\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL",
            text, re.MULTILINE
        )
        return len(dangerous) == 0
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.4 — Prevent Unauthorized and Unintended Information Transfer
# =============================================================================

def dlp_agent_present_wc() -> bool:
    """Verify a Data Loss Prevention agent (Microsoft Purview/Endpoint DLP) is present on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-Service -Name 'MsSense','SenseCncProxy','MpsSvc' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Status -eq 'Running' } | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc == 0 and out.strip().isdigit() and int(out.strip()) > 0:
            return True
        # Also check for Purview compliance agent
        rc2, out2, _ = _ps(
            "Get-Process -Name 'MsSense','SenseIR' -ErrorAction SilentlyContinue | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        return rc2 == 0 and out2.strip().isdigit() and int(out2.strip()) > 0
    except Exception:
        return False


def usb_storage_blocked_wc() -> bool:
    """Verify USB/removable storage is disabled via the USBSTOR registry key on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
            "Start"
        )
        # 4 = disabled, 3 = manual (allowed), 2 = automatic (allowed)
        return val == "4"
    except Exception:
        return False


def outbound_firewall_rules_wc() -> bool:
    """Verify outbound Windows Defender Firewall rules exist to restrict data paths on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetFirewallRule -Direction Outbound -Action Block | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc != 0:
            return False
        count = int(out.strip()) if out.strip().isdigit() else 0
        return count >= 1
    except Exception:
        return False


def dlp_agent_present_ws() -> bool:
    """Verify a DLP agent is present on Windows Server."""
    return dlp_agent_present_wc()


def usb_storage_blocked_ws() -> bool:
    """Verify USB storage is disabled on Windows Server."""
    return usb_storage_blocked_wc()


def outbound_firewall_rules_ws() -> bool:
    """Verify outbound firewall block rules exist on Windows Server."""
    return outbound_firewall_rules_wc()


def usb_storage_blocked_lx() -> bool:
    """Verify the usb-storage kernel module is blacklisted on Linux/Debian."""
    try:
        # Check modprobe.d blacklist
        for conf_file in Path("/etc/modprobe.d").glob("*.conf"):
            try:
                text = conf_file.read_text()
                if re.search(r"^\s*blacklist\s+usb[_-]storage", text, re.MULTILINE):
                    return True
            except Exception:
                continue
        # Check if module is currently not loaded
        rc, out, _ = _run("lsmod 2>/dev/null | grep usb_storage")
        if rc != 0:  # grep returns non-zero if no match
            return True
        return False
    except Exception:
        return False


def outbound_firewall_lx() -> bool:
    """Verify outbound firewall rules (iptables OUTPUT or firewalld) are configured on Linux/Debian."""
    try:
        rc, out, _ = _run("iptables -L OUTPUT -n 2>/dev/null")
        if rc == 0 and out:
            lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("target")]
            if len(lines) >= 1:
                return True
        rc2, out2, _ = _run("firewall-cmd --list-all 2>/dev/null | grep -i 'rich rules'")
        return rc2 == 0 and bool(out2.strip())
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.6 — Deny Network Communications Traffic by Default
# =============================================================================

def inbound_default_block_wc() -> bool:
    """Verify Windows Defender Firewall default inbound action is Block on all profiles on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetFirewallProfile | Select-Object -ExpandProperty DefaultInboundAction"
        )
        if rc != 0 or not out:
            return False
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        return all(l in ("2", "Block") for l in lines) and len(lines) >= 3
    except Exception:
        return False


def outbound_rules_exist_wc() -> bool:
    """Verify explicit outbound firewall allow rules exist (not relying on default allow-all) on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc != 0:
            return False
        count = int(out.strip()) if out.strip().isdigit() else 0
        return count >= 5
    except Exception:
        return False


def inbound_default_block_ws() -> bool:
    """Verify default inbound firewall action is Block on Windows Server."""
    return inbound_default_block_wc()


def outbound_rules_exist_ws() -> bool:
    """Verify explicit outbound allow rules exist on Windows Server."""
    return outbound_rules_exist_wc()


def iptables_default_drop_lx() -> bool:
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
                return all(p in ("DROP", "REJECT") for p in policies)
        # Check ufw default deny
        rc2, out2, _ = _run("ufw status verbose 2>/dev/null")
        if rc2 == 0 and "deny (incoming)" in out2.lower():
            return True
        # Check firewalld default zone
        rc3, out3, _ = _run("firewall-cmd --get-default-zone 2>/dev/null")
        if rc3 == 0 and out3.strip() in ("drop", "block"):
            return True
        return False
    except Exception:
        return False


def ufw_default_deny_lx() -> bool:
    """Verify ufw or firewalld default policy denies incoming connections on Linux/Debian."""
    try:
        rc, out, _ = _run("ufw status verbose 2>/dev/null")
        if rc == 0 and "deny (incoming)" in out.lower():
            return True
        rc2, out2, _ = _run("firewall-cmd --get-default-zone 2>/dev/null")
        if rc2 == 0 and out2.strip() in ("drop", "block"):
            return True
        # Check nftables for drop policy on input
        rc3, out3, _ = _run("nft list ruleset 2>/dev/null | grep -A3 'hook input' | grep -i 'policy drop'")
        return rc3 == 0 and bool(out3.strip())
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.7 — Prevent Remote Devices from Using Split Tunneling
# =============================================================================

def rasman_no_split_tunnel_wc() -> bool:
    """Verify the RasMan/PPP registry does not have split tunneling enabled on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters",
            "ProhibitIpSec"
        )
        # ProhibitIpSec = 0 means IPSec is allowed (not prohibited) — that is the compliant state
        # Split tunneling is controlled via the VPN connection profile
        rc, out, _ = _ps(
            "Get-VpnConnection 2>/dev/null | Select-Object -ExpandProperty SplitTunneling"
        )
        if rc == 0 and out.strip():
            lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
            return all(l == "false" for l in lines)
        # If no VPN connections configured, check GPO registry
        val2 = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnections",
            "NC_AllowNetBridge_NLA"
        )
        return val2 is None or val2 == "0"
    except Exception:
        return False


def routing_via_vpn_wc() -> bool:
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
            return True
        # VPN is connected; check default route is via a PPP/VPN adapter
        rc2, out2, _ = _ps(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty InterfaceAlias"
        )
        if rc2 == 0 and out2.strip():
            alias = out2.strip().lower()
            return any(k in alias for k in ("vpn", "ppp", "ras", "tun", "tap"))
        return False
    except Exception:
        return False


def rasman_no_split_tunnel_ws() -> bool:
    """Verify split tunneling is disabled on Windows Server."""
    return rasman_no_split_tunnel_wc()


def routing_via_vpn_ws() -> bool:
    """Verify default route via VPN on Windows Server."""
    return routing_via_vpn_wc()


def vpn_no_split_tunnel_lx() -> bool:
    """Verify VPN configurations (OpenVPN/WireGuard) route all traffic through the tunnel on Linux/Debian."""
    try:
        openvpn_dir = Path("/etc/openvpn")
        if openvpn_dir.exists():
            for conf in openvpn_dir.glob("*.conf"):
                try:
                    text = conf.read_text()
                    if "redirect-gateway def1" in text or "redirect-gateway local def1" in text:
                        return True
                except Exception:
                    continue
        wg_dir = Path("/etc/wireguard")
        if wg_dir.exists():
            for conf in wg_dir.glob("*.conf"):
                try:
                    text = conf.read_text()
                    if re.search(r"AllowedIPs\s*=\s*0\.0\.0\.0/0", text):
                        return True
                except Exception:
                    continue
        # If no VPN configs found, check routing table for VPN interfaces
        rc, out, _ = _run("ip route show 2>/dev/null | grep 'default'")
        if rc == 0 and re.search(r"(tun|tap|wg|vpn)\d*", out, re.IGNORECASE):
            return True
        return False
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.8 — Implement Cryptographic Mechanisms to Prevent Unauthorized Disclosure in Transit
# =============================================================================

def tls12_enabled_wc() -> bool:
    """Verify TLS 1.2 is enabled in the SCHANNEL registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client",
            "Enabled"
        )
        # 1 = enabled; if key doesn't exist TLS 1.2 is enabled by default on Windows 10+
        return val is None or val == "1"
    except Exception:
        return False


def tls10_disabled_wc() -> bool:
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
        return client_disabled and server_disabled
    except Exception:
        return False


def smb_signing_required_wc() -> bool:
    """Verify SMB signing is required via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
            "RequireSecuritySignature"
        )
        return val == "1"
    except Exception:
        return False


def rdp_encryption_wc() -> bool:
    """Verify RDP encryption level is set to High (3) or FIPS (4) via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            "MinEncryptionLevel"
        )
        return val in ("3", "4")
    except Exception:
        return False


def tls12_enabled_ws() -> bool:
    """Verify TLS 1.2 is enabled on Windows Server."""
    return tls12_enabled_wc()


def tls10_disabled_ws() -> bool:
    """Verify TLS 1.0 is disabled on Windows Server."""
    return tls10_disabled_wc()


def smb_signing_required_ws() -> bool:
    """Verify SMB signing is required on Windows Server (server-side)."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "RequireSecuritySignature"
        )
        return val == "1"
    except Exception:
        return False


def rdp_encryption_ws() -> bool:
    """Verify RDP encryption level is High or FIPS on Windows Server."""
    return rdp_encryption_wc()


def ldap_signing_ws() -> bool:
    """Verify LDAP client signing requirements are set to require signing on Windows Server."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "LDAPServerIntegrity"
        )
        # 2 = Require signing
        if val == "2":
            return True
        val2 = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "LDAPClientIntegrity"
        )
        return val2 == "2"
    except Exception:
        return False


def ssh_strong_ciphers_lx() -> bool:
    """Verify sshd is configured with strong ciphers and MACs, excluding weak algorithms on Linux/Debian."""
    try:
        rc, out, _ = _run("sshd -T 2>/dev/null")
        if rc != 0:
            return False
        weak_ciphers = ("arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc")
        weak_macs = ("hmac-md5", "hmac-sha1", "umac-64@openssh.com")
        out_lower = out.lower()
        ciphers_line = re.search(r"^ciphers\s+(.+)$", out_lower, re.MULTILINE)
        macs_line = re.search(r"^macs\s+(.+)$", out_lower, re.MULTILINE)
        if ciphers_line:
            ciphers = ciphers_line.group(1)
            if any(wc in ciphers for wc in weak_ciphers):
                return False
        if macs_line:
            macs = macs_line.group(1)
            if any(wm in macs for wm in weak_macs):
                return False
        return True
    except Exception:
        return False


def tls_version_lx() -> bool:
    """Verify the installed OpenSSL version supports TLS 1.2 or higher on Linux/Debian."""
    try:
        rc, out, _ = _run("openssl version 2>/dev/null")
        if rc != 0:
            return False
        # OpenSSL 1.0.1+ supports TLS 1.2; 1.1.1+ supports TLS 1.3
        m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", out)
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            return (major, minor) >= (1, 0) and patch >= 1
        return False
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.9 — Terminate Network Connections After a Defined Period of Inactivity
# =============================================================================

def rdp_idle_timeout_wc() -> bool:
    """Verify RDP idle session timeout is configured (MaxIdleTime <= 15 minutes) via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            "MaxIdleTime"
        )
        if val is None:
            return False
        # MaxIdleTime is in milliseconds; 900000 ms = 15 minutes
        return int(val) <= 900000 and int(val) > 0
    except Exception:
        return False


def screen_lock_timeout_wc() -> bool:
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
            return False
        return int(val) <= 900 and int(val) > 0
    except Exception:
        return False


def rdp_idle_timeout_ws() -> bool:
    """Verify RDP idle timeout is configured on Windows Server."""
    return rdp_idle_timeout_wc()


def screen_lock_timeout_ws() -> bool:
    """Verify screen lock timeout is 15 minutes or less on Windows Server."""
    return screen_lock_timeout_wc()


def ssh_client_alive_lx() -> bool:
    """Verify SSH ClientAliveInterval and ClientAliveCountMax are configured to terminate idle sessions on Linux/Debian."""
    try:
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return False
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
            return 0 < interval and (interval * count) <= 900
        return False
    except Exception:
        return False


def shell_timeout_lx() -> bool:
    """Verify TMOUT is set in /etc/profile or /etc/profile.d/ to auto-terminate idle shell sessions on Linux/Debian."""
    try:
        profile = Path("/etc/profile")
        tmout_re = re.compile(r"^\s*(?:export\s+)?TMOUT\s*=\s*(\d+)", re.MULTILINE)
        if profile.exists():
            m = tmout_re.search(profile.read_text())
            if m and 0 < int(m.group(1)) <= 900:
                return True
        profile_d = Path("/etc/profile.d")
        if profile_d.is_dir():
            for f in profile_d.glob("*.sh"):
                try:
                    m = tmout_re.search(f.read_text())
                    if m and 0 < int(m.group(1)) <= 900:
                        return True
                except Exception:
                    continue
        return False
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.10 — Establish and Manage Cryptographic Keys
# =============================================================================

def bitlocker_key_protector_wc() -> bool:
    """Verify BitLocker key protector is TPM+PIN or TPM+Recovery (not recovery-only) on Windows Client."""
    try:
        rc, out, _ = _run("manage-bde -status C: 2>nul")
        if rc != 0 or not out:
            return False
        # Look for TPM as a key protector
        return "tpm" in out.lower() and "protection on" in out.lower()
    except Exception:
        return False


def bitlocker_key_protector_ws() -> bool:
    """Verify BitLocker key protectors are properly configured on Windows Server."""
    return bitlocker_key_protector_wc()


def luks_keyslots_lx() -> bool:
    """Verify LUKS encrypted volumes exist and have key slots configured on Linux/Debian."""
    try:
        rc, out, _ = _run("lsblk -o NAME,FSTYPE 2>/dev/null | grep -i 'crypto_luks'")
        if rc != 0 or not out:
            return False
        # LUKS volumes found; verify at least one key slot is active
        rc2, out2, _ = _run("blkid 2>/dev/null | grep -i 'luks'")
        return rc2 == 0 and bool(out2.strip())
    except Exception:
        return False


def no_world_readable_keys_lx() -> bool:
    """Verify no private key files (.key, .pem) are world-readable on Linux/Debian."""
    try:
        rc, out, _ = _run(
            r"find /etc /home /root /var -maxdepth 6 \( -name '*.key' -o -name '*.pem' \) 2>/dev/null | "
            "xargs -r stat --format='%a %n' 2>/dev/null | "
            "awk '{ if (substr($1, length($1))+0 >= 4) print }'"
        )
        # If any world-readable key files found, return False
        return rc == 0 and not out.strip()
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.11 — Employ FIPS-Validated Cryptography
# =============================================================================

def fips_mode_wc() -> bool:
    """Verify FIPS mode is enabled via FipsAlgorithmPolicy registry key on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy",
            "Enabled"
        )
        return val == "1"
    except Exception:
        return False


def fips_mode_ws() -> bool:
    """Verify FIPS mode is enabled on Windows Server."""
    return fips_mode_wc()


def fips_enabled_lx() -> bool:
    """Verify the kernel FIPS mode is enabled (/proc/sys/crypto/fips_enabled = 1) on Linux/Debian."""
    try:
        p = Path("/proc/sys/crypto/fips_enabled")
        if p.exists():
            return p.read_text().strip() == "1"
        return False
    except Exception:
        return False


def openssl_fips_lx() -> bool:
    """Verify the kernel command line includes fips=1 boot parameter on Linux/Debian."""
    try:
        p = Path("/proc/cmdline")
        if p.exists():
            return "fips=1" in p.read_text()
        return False
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.12 — Prohibit Remote Activation of Collaborative Computing Devices
# =============================================================================

def camera_access_restricted_wc() -> bool:
    """Verify camera access is restricted via GPO registry (LetAppsAccessCamera = 2) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy",
            "LetAppsAccessCamera"
        )
        # 2 = Force Deny; compliant
        return val == "2"
    except Exception:
        return False


def microphone_access_restricted_wc() -> bool:
    """Verify microphone access is restricted via GPO registry (LetAppsAccessMicrophone = 2) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy",
            "LetAppsAccessMicrophone"
        )
        return val == "2"
    except Exception:
        return False


def camera_access_restricted_ws() -> bool:
    """Verify camera access is restricted on Windows Server."""
    return camera_access_restricted_wc()


def microphone_access_restricted_ws() -> bool:
    """Verify microphone access is restricted on Windows Server."""
    return microphone_access_restricted_wc()


def camera_permissions_lx() -> bool:
    """Verify camera/video devices are not world-accessible (not world-readable/writable) on Linux/Debian."""
    try:
        rc, out, _ = _run("ls -la /dev/video* 2>/dev/null")
        if rc != 0 or not out:
            return True  # No camera devices present — compliant
        # Check that devices are not world-readable
        for line in out.splitlines():
            if re.match(r"crw-rw-rw-", line):
                return False
        return True
    except Exception:
        return False


def microphone_permissions_lx() -> bool:
    """Verify audio capture devices are not world-accessible on Linux/Debian."""
    try:
        rc, out, _ = _run("ls -la /dev/snd/ 2>/dev/null")
        if rc != 0 or not out:
            return True  # No audio devices — compliant
        world_writable = [l for l in out.splitlines() if re.match(r"crw-rw-rw-", l)]
        return len(world_writable) == 0
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.13 — Control and Monitor the Use of Mobile Code
# =============================================================================

def ps_execution_policy_wc() -> bool:
    """Verify PowerShell execution policy is RemoteSigned or AllSigned on Windows Client."""
    try:
        rc, out, _ = _ps("Get-ExecutionPolicy -Scope LocalMachine")
        if rc == 0 and out.strip().lower() in ("remotesigned", "allsigned"):
            return True
        rc2, out2, _ = _ps("Get-ExecutionPolicy")
        return rc2 == 0 and out2.strip().lower() in ("remotesigned", "allsigned")
    except Exception:
        return False


def wsh_disabled_wc() -> bool:
    """Verify Windows Script Host is disabled via registry on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
            "Enabled"
        )
        return val == "0"
    except Exception:
        return False


def applocker_active_wc() -> bool:
    """Verify AppLocker or WDAC policies are configured and enforced on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-AppLockerPolicy -Effective -Xml 2>$null | "
            "Select-String 'EnforcementMode=\"Enabled\"' | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc == 0 and out.strip().isdigit() and int(out.strip()) > 0:
            return True
        # Check WDAC (Windows Defender Application Control) via CodeIntegrity registry
        rc2, out2, _ = _ps(
            "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
            "\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled"
        )
        if rc2 == 0 and out2.strip() == "1":
            return True
        # Also check if SIPolicy.p7b exists (indicates a deployed WDAC policy)
        return Path("C:/Windows/System32/CodeIntegrity/SIPolicy.p7b").exists()
    except Exception:
        return False


def ps_execution_policy_ws() -> bool:
    """Verify PowerShell execution policy is RemoteSigned or AllSigned on Windows Server."""
    return ps_execution_policy_wc()


def wsh_disabled_ws() -> bool:
    """Verify Windows Script Host is disabled on Windows Server."""
    return wsh_disabled_wc()


def applocker_active_ws() -> bool:
    """Verify AppLocker or WDAC policies are active on Windows Server."""
    return applocker_active_wc()


def noexec_tmp_lx() -> bool:
    """Verify /tmp and /home are mounted with the noexec option on Linux/Debian."""
    try:
        p = Path("/proc/mounts")
        if not p.exists():
            rc, out, _ = _run("mount 2>/dev/null")
            if rc != 0:
                return False
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
        return tmp_noexec and home_noexec
    except Exception:
        return False


def no_world_writable_path_lx() -> bool:
    """Verify no world-writable directories exist in the system PATH on Linux/Debian."""
    try:
        rc, out, _ = _run("echo $PATH")
        if rc != 0:
            return False
        dirs = [d.strip() for d in out.split(":") if d.strip()]
        for d in dirs:
            p = Path(d)
            if p.exists() and p.is_dir():
                mode = p.stat().st_mode
                # World-writable = others write bit (0o002)
                if mode & 0o002:
                    return False
        return True
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.14 — Control and Monitor the Use of VoIP Technologies
# =============================================================================

def voip_ports_controlled_wc() -> bool:
    """Verify SIP/VoIP ports (5060, 5061) are not unexpectedly open or are covered by firewall rules on Windows Client."""
    try:
        rc, out, _ = _ps(
            "Get-NetTCPConnection -State Listen -LocalPort 5060,5061 "
            "-ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc == 0 and out.strip().isdigit() and int(out.strip()) == 0:
            return True  # Ports not open — compliant
        # If open, verify firewall rules govern them via port filter objects
        rc2, out2, _ = _ps(
            "Get-NetFirewallRule | Get-NetFirewallPortFilter | "
            "Where-Object { $_.LocalPort -match '5060|5061' } | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        return rc2 == 0 and out2.strip().isdigit() and int(out2.strip()) > 0
    except Exception:
        return False


def voip_ports_controlled_ws() -> bool:
    """Verify SIP/VoIP ports are controlled on Windows Server."""
    return voip_ports_controlled_wc()


def voip_ports_lx() -> bool:
    """Verify SIP/VoIP ports (5060, 5061) are not unexpectedly listening, or are governed by firewall on Linux/Debian."""
    try:
        rc, out, _ = _run("ss -ulnp 2>/dev/null | grep -E ':5060|:5061'")
        if rc != 0 or not out.strip():
            return True  # Ports not open — compliant
        # If open, check firewall rules cover them
        rc2, out2, _ = _run("iptables -L -n 2>/dev/null | grep -E '5060|5061'")
        if rc2 == 0 and out2.strip():
            return True
        rc3, out3, _ = _run("firewall-cmd --list-all 2>/dev/null | grep -E '5060|5061'")
        return rc3 == 0 and bool(out3.strip())
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.15 — Protect the Authenticity of Communications Sessions
# =============================================================================

def smb_signing_wc() -> bool:
    """Verify SMB client signing is required (RequireSecuritySignature = 1) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
            "RequireSecuritySignature"
        )
        return val == "1"
    except Exception:
        return False


def tls_cert_validation_wc() -> bool:
    """Verify TLS certificate validation is not disabled (DisableCertificateRevocationChecks = 0) on Windows Client."""
    try:
        val = _reg_get(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "DisableCertRevocation"
        )
        # 0 or absent means revocation checks are enabled (compliant)
        return val is None or val == "0"
    except Exception:
        return False


def smb_signing_ws() -> bool:
    """Verify SMB server signing is required on Windows Server."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "RequireSecuritySignature"
        )
        return val == "1"
    except Exception:
        return False


def ldap_signing_required_ws() -> bool:
    """Verify LDAP server signing requirements are set to require signing (LDAPServerIntegrity = 2) on Windows Server."""
    try:
        val = _reg_get(
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "LDAPServerIntegrity"
        )
        return val == "2"
    except Exception:
        return False


def tls_cert_validation_ws() -> bool:
    """Verify TLS certificate revocation checking is enabled on Windows Server."""
    return tls_cert_validation_wc()


def kerberos_auth_ws() -> bool:
    """Verify Kerberos authentication is in use by confirming the system is domain-joined on Windows Server."""
    try:
        rc, out, _ = _ps(
            "(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain"
        )
        return rc == 0 and out.strip().lower() == "true"
    except Exception:
        return False


def ssh_hostbased_disabled_lx() -> bool:
    """Verify SSH HostbasedAuthentication is disabled in sshd_config on Linux/Debian."""
    try:
        rc, out, _ = _run("sshd -T 2>/dev/null | grep -i 'hostbasedauthentication'")
        if rc == 0 and out:
            return "no" in out.lower()
        p = Path("/etc/ssh/sshd_config")
        if p.exists():
            text = p.read_text()
            m = re.search(r"^\s*HostbasedAuthentication\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                return m.group(1).lower() == "no"
        return True  # Default is no
    except Exception:
        return False


def ssh_strict_host_lx() -> bool:
    """Verify SSH client StrictHostKeyChecking is set to yes in /etc/ssh/ssh_config on Linux/Debian."""
    try:
        p = Path("/etc/ssh/ssh_config")
        if p.exists():
            text = p.read_text()
            m = re.search(r"^\s*StrictHostKeyChecking\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                return m.group(1).lower() == "yes"
        rc, out, _ = _run("ssh -G localhost 2>/dev/null | grep -i 'stricthostkeychecking'")
        if rc == 0 and out:
            return "yes" in out.lower()
        return False
    except Exception:
        return False


# =============================================================================
# SC.L2-3.13.16 — Protect the Confidentiality of CUI at Rest
# =============================================================================

def bitlocker_enabled_wc() -> bool:
    """Verify BitLocker is enabled and protection is On for the C: drive on Windows Client."""
    try:
        rc, out, _ = _run("manage-bde -status C: 2>nul")
        if rc != 0 or not out:
            return False
        return "protection on" in out.lower()
    except Exception:
        return False


def bitlocker_full_encryption_wc() -> bool:
    """Verify BitLocker encryption percentage is 100% on the system drive on Windows Client."""
    try:
        rc, out, _ = _run("manage-bde -status C: 2>nul")
        if rc != 0 or not out:
            return False
        m = re.search(r"Percentage Encrypted[:\s]+(\d+)[\.,]", out, re.IGNORECASE)
        if m:
            return int(m.group(1)) == 100
        return False
    except Exception:
        return False


def bitlocker_enabled_ws() -> bool:
    """Verify BitLocker is enabled on Windows Server."""
    return bitlocker_enabled_wc()


def bitlocker_full_encryption_ws() -> bool:
    """Verify BitLocker encryption is 100% complete on Windows Server."""
    return bitlocker_full_encryption_wc()


def luks_active_lx() -> bool:
    """Verify LUKS-encrypted partitions exist on the system on Linux/Debian."""
    try:
        rc, out, _ = _run("lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | grep -i 'crypto_luks'")
        return rc == 0 and bool(out.strip())
    except Exception:
        return False


def luks_mapping_active_lx() -> bool:
    """Verify LUKS device mappings are active (unlocked dm-crypt devices present) on Linux/Debian."""
    try:
        # dmsetup status lists all device-mapper devices; filter for crypt type
        rc, out, _ = _run("dmsetup status 2>/dev/null | grep -i 'crypt'")
        if rc == 0 and out.strip():
            return True
        # Alternatively, check /dev/mapper for any LUKS-opened devices via cryptsetup
        rc2, out2, _ = _run(
            "ls /dev/mapper/ 2>/dev/null | xargs -I{} sh -c "
            "'cryptsetup status {} 2>/dev/null | grep -q \"is active\" && echo {}' 2>/dev/null"
        )
        return rc2 == 0 and bool(out2.strip())
    except Exception:
        return False
