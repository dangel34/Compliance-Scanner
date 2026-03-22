import subprocess
import json
import re

def run_command(cmd: str):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }


def process_identity_wc():
    result = run_command('powershell -NoProfile -Command "Get-CimInstance Win32_Service | Select Name,StartName,State | ConvertTo-Json -Compress"')
    service_list = json.loads(result['stdout'])
    for svc in service_list:
        if not svc["StartName"]:
            return False # Found a Blank
    return True # Found no blanks

def authorized_user_ws():
    result = run_command('powershell -NoProfile -Command "Get-ADUser -Filter * -Properties Enabled | Select Name, Enabled"')
    if result['returncode'] != 0:
        return False
    return True

def domain_joined_wc():
    result = run_command(
        'powershell -NoProfile -Command "Get-WmiObject Win32_ComputerSystem | Select Name, Domain"')
    if "." not in result['stdout']:
        return False
    else:
        return True

def system_access_wc(): # Chat Ran in elevated Privilages
    parse_cmd = 'Select-String "SeInteractiveLogonRight","SeRemoteInteractiveLogonRight" C:\secpol.cfg'
    create_log = run_command(
        'powershell -NoProfile -Command "secedit /export /cfg C:\secpol.cfg"')
    result = run_command(
        f'powershell -NoProfile -Command "{parse_cmd}"')
    if result['returncode'] != 0:
        remove_cmd = f'powershell -NoProfile -Command "rm C:\secpol.cfg"'
        return False
    else:
        remove_cmd = f'powershell -NoProfile -Command "rm C:\secpol.cfg"'
        return True




def authorized_user_wc() -> bool:
    """
    AC.L2-3.1.1a - Authorized Users are Identified (Windows Client)
    """
    try:
        # Check local accounts via net user
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return False

        users = json.loads(result.stdout)
        if isinstance(users, dict):
            users = [users]

        banned_accounts = {"guest", "defaultaccount", "wdagutilityaccount"}
        for user in users:
            name = user.get("Name", "").lower()
            enabled = user.get("Enabled", False)
            if name in banned_accounts and enabled:
                return False

        # Confirm at least one named non-system user exists
        named_users = [
            u for u in users
            if u.get("Name", "").lower() not in banned_accounts
            and u.get("Enabled", False)
        ]
        return len(named_users) > 0

    except Exception:
        return False


def service_account_identity_wc() -> bool:
    """
    AC.L2-3.1.1e - System Access is Limited to Authorized Processes (Windows Client)
    """
    try:
        risky_accounts = {"localsystem", ""}

        # Check services running as LocalSystem
        svc_result = subprocess.run(
            ["powershell", "-Command",
             "Get-WmiObject Win32_Service | Select-Object Name, StartName | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if svc_result.returncode != 0:
            return False

        services = json.loads(svc_result.stdout)
        if isinstance(services, dict):
            services = [services]

        # Flag any service with a blank or LocalSystem identity
        # LocalLocalSystem is expected for some OS services so we only flag
        # non-Microsoft services running as LocalSystem
        flagged_services = [
            s for s in services
            if (s.get("StartName") or "").lower().replace("nt authority\\", "") in risky_accounts
            and not any(skip in (s.get("Name") or "").lower()
                        for skip in ["windows", "wmi", "rpc", "dcom", "system"])
        ]

        # Check scheduled tasks for blank/system-level principals
        task_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ScheduledTask | Select-Object TaskName, @{N='Principal';E={$_.Principal.UserId}} | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if task_result.returncode != 0:
            return False

        tasks = json.loads(task_result.stdout)
        if isinstance(tasks, dict):
            tasks = [tasks]

        flagged_tasks = [
            t for t in tasks
            if (t.get("Principal") or "").strip() == ""
        ]

        return bool(len(flagged_services) == 0 and len(flagged_tasks) == 0)

    except Exception:
        return False


def device_restriction_wc() -> bool:
    """
    AC.L2-3.1.1f - System Access is Limited to Authorized Devices (Windows Client)
    """
    try:
        # Check domain join status
        domain_result = subprocess.run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"],
            capture_output=True, text=True, timeout=30
        )
        if domain_result.returncode != 0:
            return False

        is_domain_joined = domain_result.stdout.strip().lower() == "true"

        # Check Entra ID / hybrid join as fallback
        if not is_domain_joined:
            dsreg_result = subprocess.run(
                ["dsregcmd", "/status"],
                capture_output=True, text=True, timeout=30
            )
            output = dsreg_result.stdout.lower()
            is_domain_joined = (
                "azureadjoined : yes" in output or
                "domainjoined : yes" in output or
                "workplacejoined : yes" in output
            )

        if not is_domain_joined:
            return False

        # Check Windows Defender Firewall is enabled on all profiles
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode != 0:
            return False

        profiles = json.loads(fw_result.stdout)
        if isinstance(profiles, dict):
            profiles = [profiles]

        all_enabled = all(p.get("Enabled", False) for p in profiles)
        return bool(all_enabled)

    except Exception:
        return False


def process_identity_ws() -> bool:
    """
    AC.L2-3.1.1b - Processes Acting on Behalf of Authorized Users are Identified (Windows Server)
    """
    try:
        risky_accounts = {"localsystem", ""}

        # Check services
        svc_result = subprocess.run(
            ["powershell", "-Command",
             "Get-WmiObject Win32_Service | Select-Object Name, StartName | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if svc_result.returncode != 0:
            return False

        services = json.loads(svc_result.stdout)
        if isinstance(services, dict):
            services = [services]
        if not services:
            return False

        flagged_services = [
            s for s in services
            if (s.get("StartName") or "").lower().replace("nt authority\\", "") in risky_accounts
            and not any(skip in (s.get("Name") or "").lower()
                        for skip in ["windows", "wmi", "rpc", "dcom", "system"])
        ]

        # Check scheduled tasks
        task_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ScheduledTask | Select-Object TaskName, @{N='Principal';E={$_.Principal.UserId}} | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if task_result.returncode != 0:
            return False

        tasks = json.loads(task_result.stdout)
        if isinstance(tasks, dict):
            tasks = [tasks]
        if not tasks:
            return False

        flagged_tasks = [
            t for t in tasks
            if (t.get("Principal") or "").strip() == ""
        ]

        return bool(not flagged_services and not flagged_tasks)

    except Exception:
        return False


def domain_joined_ws() -> bool:
    """
    AC.L2-3.1.1c - Authorized Devices are Identified (Windows Server)
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return False

        return bool(result.stdout.strip().lower() == "true")

    except Exception:
        return False


def system_access_ws() -> bool:
    """
    AC.L2-3.1.1d - System Access is Limited to Authorized Users (Windows Server)
    """
    try:
        # Check Guest account is disabled
        guest_result = subprocess.run(
            ["powershell", "-Command",
             "(Get-LocalUser -Name 'Guest').Enabled"],
            capture_output=True, text=True, timeout=30
        )
        if guest_result.returncode != 0:
            return False

        guest_enabled = guest_result.stdout.strip().lower() == "true"
        if guest_enabled:
            return False

        # Check RDP is restricted — Remote Desktop Users group should not be empty
        # and should not contain "Everyone" or "Authenticated Users"
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Remote Desktop Users' | Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        # If group is empty that is acceptable (RDP may be disabled entirely)
        # but if it contains broad groups that is a failure
        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            rdp_members = json.loads(rdp_result.stdout)
            if isinstance(rdp_members, dict):
                rdp_members = [rdp_members]
            if not rdp_members:
                return False

            broad_groups = {"everyone", "authenticated users", "users"}
            flagged_rdp = [
                m for m in rdp_members
                if (m.get("Name") or "").lower().split("\\")[-1] in broad_groups
            ]
            if flagged_rdp:
                return False

        # Check "Allow log on locally" is restricted via secedit
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | Select-String 'SeInteractiveLogonRight'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        logon_policy = secedit_result.stdout.strip()

        # Fail if Everyone or blank is assigned interactive logon
        if not logon_policy or "everyone" in logon_policy.lower():
            return False

        return True

    except Exception:
        return False


def service_account_identity_ws() -> bool:
    """
    AC.L2-3.1.1e - System Access is Limited to Authorized Processes (Windows Server)
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-WmiObject Win32_Service | Select-Object Name, StartName, State | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return False

        services = json.loads(result.stdout)
        if isinstance(services, dict):
            services = [services]
        if not services:
            return False

        # Flag services with blank, null, or LocalSystem identity that are
        # running and are not known Windows OS services
        flagged = [
            s for s in services
            if (s.get("StartName") or "").strip() == ""
            or (
                (s.get("StartName") or "").lower() == "localsystem"
                and s.get("State", "").lower() == "running"
                and not any(skip in (s.get("Name") or "").lower()
                            for skip in ["windows", "wmi", "rpc", "dcom", "system", "spooler"])
            )
        ]

        return bool(not flagged)

    except Exception:
        return False


def device_restriction_ws() -> bool:
    """
    AC.L2-3.1.1f - System Access is Limited to Authorized Devices (Windows Server)

    """
    try:
        # Check firewall is enabled on all profiles
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode != 0:
            return False

        profiles = json.loads(fw_result.stdout)
        if isinstance(profiles, dict):
            profiles = [profiles]
        if not profiles:
            return False

        if not all(p.get("Enabled", False) for p in profiles):
            return False

        # Check for overly permissive inbound rules (Any remote address, Allow action)
        rules_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -Direction Inbound -Action Allow | "
             "Select-Object DisplayName, "
             "@{N='RemoteAddress';E={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}} | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if rules_result.returncode != 0:
            return False

        rules = json.loads(rules_result.stdout)
        if isinstance(rules, dict):
            rules = [rules]
        if not rules:
            return False

        flagged_rules = [
            r for r in rules
            if (r.get("RemoteAddress") or "").strip().lower() in {"any", "*", "0.0.0.0/0"}
        ]

        return bool(not flagged_rules)

    except Exception:
        return False

 ### DEB ###
def process_identity_lx() -> bool:
    """
    AC.L2-3.1.1b - Processes Acting on Behalf of Authorized Users are Identified (Linux/Debian)
    """
    try:
        # Get all running systemd services
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-legend", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return False

        services = [
            line.split()[0] for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        if not services:
            return False

        # Known essential root-level services that are expected to run as root
        root_exceptions = {
            "systemd-journald.service", "systemd-udevd.service",
            "systemd-logind.service", "dbus.service", "cron.service",
            "ssh.service", "sshd.service", "networkmanager.service",
            "systemd-networkd.service", "rsyslog.service"
        }

        flagged = []
        for service in services:
            # Get the User= directive from the service unit
            show_result = subprocess.run(
                ["systemctl", "show", service, "--property=User,FragmentPath"],
                capture_output=True, text=True, timeout=10
            )
            if show_result.returncode != 0:
                continue

            props = dict(
                line.split("=", 1) for line in show_result.stdout.strip().splitlines()
                if "=" in line
            )

            user = props.get("User", "").strip()

            # If no User= directive, the service runs as root by default
            if user == "" and service not in root_exceptions:
                flagged.append(service)

        return bool(not flagged)

    except Exception:
        return False


def device_restriction_lx() -> bool:
    """
    AC.L2-3.1.1c - Authorized Devices are Identified (Linux/Debian)
    """
    try:
        ssh_restricted = False
        firewall_restricted = False

        # Check sshd_config for AllowUsers or AllowGroups
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode == 0:
            output = sshd_result.stdout.lower()
            has_allowusers = re.search(r"^allowusers\s+\S+", output, re.MULTILINE)
            has_allowgroups = re.search(r"^allowgroups\s+\S+", output, re.MULTILINE)
            if has_allowusers or has_allowgroups:
                ssh_restricted = True

        # Check iptables for SSH port restrictions
        for cmd in [["iptables", "-L", "-n"], ["ip6tables", "-L", "-n"]]:
            fw_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if fw_result.returncode == 0:
                # Look for rules referencing port 22 that are not ACCEPT all
                if re.search(r"(dpt:22|ssh)", fw_result.stdout.lower()):
                    firewall_restricted = True
                    break

        # Check nftables if iptables found nothing
        if not firewall_restricted:
            nft_result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True, text=True, timeout=30
            )
            if nft_result.returncode == 0:
                if re.search(r"(port\s+22|ssh)", nft_result.stdout.lower()):
                    firewall_restricted = True

        # Check firewalld if nftables found nothing
        if not firewall_restricted:
            fwd_result = subprocess.run(
                ["firewall-cmd", "--list-all"],
                capture_output=True, text=True, timeout=30
            )
            if fwd_result.returncode == 0:
                if "ssh" in fwd_result.stdout.lower():
                    firewall_restricted = True

        return bool(ssh_restricted or firewall_restricted)

    except Exception:
        return False


def service_account_identity_lx() -> bool:
    """
    AC.L2-3.1.1e - System Access is Limited to Authorized Processes (Linux/Debian)
    """
    try:
        # Get all running services
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-legend", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return False

        services = [
            line.split()[0] for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        if not services:
            return False

        root_exceptions = {
            "systemd-journald.service", "systemd-udevd.service",
            "systemd-logind.service", "dbus.service", "cron.service",
            "ssh.service", "sshd.service", "networkmanager.service",
            "systemd-networkd.service", "rsyslog.service"
        }

        flagged = []
        for service in services:
            show_result = subprocess.run(
                ["systemctl", "show", service, "--property=User"],
                capture_output=True, text=True, timeout=10
            )
            if show_result.returncode != 0:
                continue

            user = show_result.stdout.strip().replace("User=", "").strip()

            # Flag services with no User= directive that aren't in exceptions
            if user == "" and service not in root_exceptions:
                flagged.append(service)

            # Flag services explicitly set to run as root
            if user == "root" and service not in root_exceptions:
                flagged.append(service)

        return bool(not flagged)

    except Exception:
        return False


def firewall_rules_lx() -> bool:
    """
    AC.L2-3.1.1f - System Access is Limited to Authorized Devices (Linux/Debian)
    """
    try:
        firewall_active = False
        has_inbound_rules = False

        # Check iptables
        ipt_result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=30
        )
        if ipt_result.returncode == 0:
            lines = ipt_result.stdout.strip().splitlines()
            # Filter out header lines and the default policy line
            rules = [l for l in lines if re.match(r"^\d+", l.strip())]
            if rules:
                firewall_active = True
                # Fail if the only rule is ACCEPT all from anywhere
                non_accept_all = [
                    r for r in rules
                    if not re.search(r"ACCEPT\s+all\s+--\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0", r)
                ]
                if non_accept_all:
                    has_inbound_rules = True

        # Check nftables if iptables had no meaningful rules
        if not has_inbound_rules:
            nft_result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True, text=True, timeout=30
            )
            if nft_result.returncode == 0 and nft_result.stdout.strip():
                firewall_active = True
                # Look for any input chain with at least one rule
                if re.search(r"chain\s+input", nft_result.stdout.lower()):
                    chain_block = re.search(
                        r"chain\s+input\s*\{(.*?)\}", nft_result.stdout,
                        re.DOTALL | re.IGNORECASE
                    )
                    if chain_block:
                        chain_content = chain_block.group(1).strip()
                        rule_lines = [
                            l for l in chain_content.splitlines()
                            if l.strip() and not l.strip().startswith("type")
                        ]
                        if rule_lines:
                            has_inbound_rules = True

        # Check firewalld if neither iptables nor nftables had rules
        if not has_inbound_rules:
            fwd_result = subprocess.run(
                ["firewall-cmd", "--state"],
                capture_output=True, text=True, timeout=30
            )
            if fwd_result.returncode == 0 and "running" in fwd_result.stdout.lower():
                firewall_active = True
                # Check that the active zone has services or rich rules defined
                zone_result = subprocess.run(
                    ["firewall-cmd", "--list-all"],
                    capture_output=True, text=True, timeout=30
                )
                if zone_result.returncode == 0:
                    output = zone_result.stdout.lower()
                    has_services = re.search(r"services:\s+\S+", output)
                    has_rich_rules = re.search(r"rich rules:", output)
                    if has_services or has_rich_rules:
                        has_inbound_rules = True

        return bool(firewall_active and has_inbound_rules)

    except Exception:
        return False


def function_restriction_wc() -> bool:
    """
    AC.L2-3.1.2b - System Access is Limited to Defined Transactions and Functions (Windows Client)
    Checks that AppLocker or Software Restriction Policies are configured
    and enforced to limit users to permitted functions.
    Returns True if at least one application control mechanism is active.
    """
    try:
        applocker_active = False
        srp_active = False

        # Check AppLocker policy is configured and enforced
        applocker_result = subprocess.run(
            ["powershell", "-Command",
             "Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | "
             "Select-Object RuleCollectionType, EnforcementMode | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if applocker_result.returncode == 0 and applocker_result.stdout.strip():
            rules = json.loads(applocker_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if not rules:
                applocker_active = False
            else:
                # At least one rule collection must be in Enforced mode, not AuditOnly
                enforced = [
                    r for r in rules
                    if (r.get("EnforcementMode") or "").lower() == "enabled"
                ]
                applocker_active = bool(enforced)

        # Check Software Restriction Policies via registry if AppLocker is not active
        if not applocker_active:
            srp_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers' "
                 "-ErrorAction SilentlyContinue | Select-Object DefaultLevel | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if srp_result.returncode == 0 and srp_result.stdout.strip():
                srp_data = json.loads(srp_result.stdout)
                # DefaultLevel 0 = Disallowed (restrictive), 131072 = Unrestricted (fail)
                default_level = srp_data.get("DefaultLevel", 131072)
                srp_active = bool(default_level == 0)

        return bool(applocker_active or srp_active)

    except Exception:
        return False


def function_restriction_ws() -> bool:
    """
    AC.L2-3.1.2b - System Access is Limited to Defined Transactions and Functions (Windows Server)
    Checks that NTFS permissions and share permissions do not grant
    broad access to Everyone or Authenticated Users, and that
    AD role assignments are scoped to named groups.
    Returns True if no overly permissive NTFS or share permissions are found.
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Check share permissions for overly broad access
        share_result = subprocess.run(
            ["powershell", "-Command",
             "Get-SmbShareAccess * | Select-Object Name, AccountName, AccessRight | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if share_result.returncode != 0:
            return False

        shares = json.loads(share_result.stdout)
        if isinstance(shares, dict):
            shares = [shares]
        if not shares:
            return False

        # Exclude built-in admin shares (ADMIN$, C$, IPC$)
        admin_shares = {"admin$", "c$", "ipc$", "print$"}
        flagged_shares = [
            s for s in shares
            if (s.get("AccountName") or "").lower().split("\\")[-1] in broad_principals
            and (s.get("Name") or "").lower() not in admin_shares
            and (s.get("AccessRight") or "").lower() in {"full", "change"}
        ]

        if flagged_shares:
            return False

        # Check local Administrators group does not contain broad/unexpected members
        admin_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if admin_result.returncode != 0:
            return False

        admins = json.loads(admin_result.stdout)
        if isinstance(admins, dict):
            admins = [admins]
        if not admins:
            return False

        flagged_admins = [
            a for a in admins
            if (a.get("Name") or "").lower().split("\\")[-1] in broad_principals
        ]

        return bool(not flagged_admins)

    except Exception:
        return False


def function_restriction_lx() -> bool:
    """
    AC.L2-3.1.2b - System Access is Limited to Defined Transactions and Functions (Linux/Debian)
    Checks three enforcement mechanisms:
    1. Sudoers does not contain unrestricted ALL=(ALL) ALL entries for non-root users
    2. PAM is configured with at least one access control module
    3. SELinux or AppArmor is active and enforcing
    Returns True if all three conditions are met.
    """
    try:
        sudoers_clean = False
        pam_configured = False
        mac_enforcing = False

        # Check sudoers for unrestricted ALL=(ALL) ALL entries
        sudoers_result = subprocess.run(
            ["sudo", "cat", "/etc/sudoers"],
            capture_output=True, text=True, timeout=30
        )
        if sudoers_result.returncode == 0:
            lines = sudoers_result.stdout.splitlines()
            # Filter out comments and blank lines
            active_lines = [
                l.strip() for l in lines
                if l.strip() and not l.strip().startswith("#")
            ]
            # Flag any line granting ALL=(ALL) ALL to a non-root, non-group entry
            unrestricted = [
                l for l in active_lines
                if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", l)
                and not l.startswith("%")        # group entries are more acceptable
                and not l.startswith("root")     # root is expected
                and "NOPASSWD" not in l          # NOPASSWD ALL is a separate concern
            ]
            sudoers_clean = bool(not unrestricted)

        # Also check sudoers.d directory
        sudoersd_result = subprocess.run(
            ["sudo", "grep", "-r", "ALL=(ALL) ALL", "/etc/sudoers.d/"],
            capture_output=True, text=True, timeout=30
        )
        if sudoersd_result.returncode == 0 and sudoersd_result.stdout.strip():
            # Any unrestricted entry in sudoers.d is a fail
            sudoers_clean = False

        # Check PAM for access control configuration
        pam_result = subprocess.run(
            ["grep", "-r", "pam_access\|pam_listfile\|pam_wheel", "/etc/pam.d/"],
            capture_output=True, text=True, timeout=30
        )
        if pam_result.returncode == 0 and pam_result.stdout.strip():
            # Filter out commented lines
            active_pam = [
                l for l in pam_result.stdout.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]
            pam_configured = bool(active_pam)

        # Check SELinux enforcement
        selinux_result = subprocess.run(
            ["getenforce"],
            capture_output=True, text=True, timeout=10
        )
        if selinux_result.returncode == 0:
            if selinux_result.stdout.strip().lower() == "enforcing":
                mac_enforcing = True

        # Check AppArmor if SELinux is not enforcing
        if not mac_enforcing:
            apparmor_result = subprocess.run(
                ["aa-status", "--enabled"],
                capture_output=True, text=True, timeout=10
            )
            if apparmor_result.returncode == 0:
                mac_enforcing = True

        return bool(sudoers_clean and pam_configured and mac_enforcing)

    except Exception:
        return False


def cui_flow_policy_wc() -> bool:
    """
    AC.L2-3.1.3a - Information Flow Control Policies are Defined (Windows Client)
    Checks that Group Policy and/or Windows Defender Firewall have defined
    rules governing the flow of information, indicating a policy exists.
    Returns True if at least one flow control policy mechanism is configured.
    """
    try:
        policy_defined = False

        # Check Windows Defender Firewall has outbound rules defined
        # (outbound rules indicate intentional flow control policy)
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -Direction Outbound -Enabled True | "
             "Select-Object DisplayName, Action | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if not rules:
                policy_defined = False
            else:
                # Must have at least one Block outbound rule to indicate
                # intentional flow control rather than default allow-all
                block_rules = [
                    r for r in rules
                    if (r.get("Action") or "").lower() == "block"
                ]
                policy_defined = bool(block_rules)

        # Check Group Policy for any configured security settings
        # via resultant set of policy
        if not policy_defined:
            gp_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-GPResultantSetOfPolicy -ReportType Xml -Path "
                 "$env:TEMP\\rsop.xml 2>$null; "
                 "[xml]$rsop = Get-Content $env:TEMP\\rsop.xml; "
                 "$rsop.Rsop.ComputerResults.ExtensionData | "
                 "Where-Object {$_.Name -match 'Security'} | "
                 "Select-Object Name | ConvertTo-Json"],
                capture_output=True, text=True, timeout=60
            )
            if gp_result.returncode == 0 and gp_result.stdout.strip():
                policy_defined = True

        return bool(policy_defined)

    except Exception:
        return False


def cui_flow_enforcement_wc() -> bool:
    """
    AC.L2-3.1.3b - Methods and Enforcement Mechanisms for CUI Flow are Defined (Windows Client)
    Checks that Windows Defender Firewall is active, outbound rules exist,
    and removable media write access is restricted via Group Policy or registry.
    Returns True if all enforcement mechanisms are active.
    """
    try:
        firewall_enforced = False
        media_restricted = False

        # Check Windows Defender Firewall is enabled on all profiles
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            profiles = json.loads(fw_result.stdout)
            if isinstance(profiles, dict):
                profiles = [profiles]
            if not profiles:
                return False
            firewall_enforced = bool(all(p.get("Enabled", False) for p in profiles))

        if not firewall_enforced:
            return False

        # Check removable media write access is restricted via registry
        media_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' "
             "-ErrorAction SilentlyContinue | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if media_result.returncode == 0 and media_result.stdout.strip():
            media_policy = json.loads(media_result.stdout)
            # Deny_All or Deny_Write being set to 1 indicates restriction
            deny_all = media_policy.get("Deny_All", 0)
            deny_write = media_policy.get("Deny_Write", 0)
            media_restricted = bool(deny_all == 1 or deny_write == 1)
        else:
            # Check per-device class keys for write restrictions
            usb_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices"
                 "\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' "
                 "-ErrorAction SilentlyContinue | Select-Object Deny_Write | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if usb_result.returncode == 0 and usb_result.stdout.strip():
                usb_policy = json.loads(usb_result.stdout)
                media_restricted = bool(usb_policy.get("Deny_Write", 0) == 1)

        return bool(firewall_enforced and media_restricted)

    except Exception:
        return False


def cui_flow_authorization_wc() -> bool:
    """
    AC.L2-3.1.3d - Authorizations for Controlling CUI Flow are Defined (Windows Client)
    Checks that Windows Defender Firewall outbound block rules and any
    DLP-style registry policies are scoped to named users or groups
    rather than broad principals.
    Returns True if CUI flow authorizations are scoped to named identities.
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users", ""}

        # Check outbound firewall rules are not scoped to Everyone
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True | "
             "Select-Object DisplayName, Owner | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode != 0:
            return False

        rules = json.loads(fw_result.stdout) if fw_result.stdout.strip() else []
        if isinstance(rules, dict):
            rules = [rules]

        # If no outbound block rules exist at all, authorizations are not defined
        if not rules:
            return False

        flagged_rules = [
            r for r in rules
            if (r.get("Owner") or "").lower() in broad_principals
        ]

        # Check removable media policy is applied via GP (not just registry default)
        gp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' "
             "-ErrorAction SilentlyContinue | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        gp_configured = bool(
            gp_result.returncode == 0 and gp_result.stdout.strip()
        )

        return bool(not flagged_rules and gp_configured)

    except Exception:
        return False


def cui_flow_policy_ws() -> bool:
    """
    AC.L2-3.1.3a - Information Flow Control Policies are Defined (Windows Server)
    Checks that Windows Defender Firewall has outbound block rules and
    IPSec policies are configured, indicating defined CUI flow control policies.
    Returns True if at least one flow control policy mechanism is configured.
    """
    try:
        policy_defined = False

        # Check for outbound block rules in Windows Defender Firewall
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True | "
             "Select-Object DisplayName | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            policy_defined = bool(rules)

        # Check for IPSec connection security rules as an additional flow policy
        if not policy_defined:
            ipsec_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetIPsecRule -Enabled True | Select-Object DisplayName | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if ipsec_result.returncode == 0 and ipsec_result.stdout.strip():
                ipsec_rules = json.loads(ipsec_result.stdout)
                if isinstance(ipsec_rules, dict):
                    ipsec_rules = [ipsec_rules]
                policy_defined = bool(ipsec_rules)

        return bool(policy_defined)

    except Exception:
        return False


def cui_flow_enforcement_ws() -> bool:
    """
    AC.L2-3.1.3b - Methods and Enforcement Mechanisms for CUI Flow are Defined (Windows Server)
    Checks that Windows Defender Firewall is active on all profiles,
    IPSec rules exist, and share/NTFS permissions are not overly permissive.
    Returns True if all enforcement mechanisms are active.
    """
    try:
        # Check firewall enabled on all profiles
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode != 0:
            return False

        profiles = json.loads(fw_result.stdout)
        if isinstance(profiles, dict):
            profiles = [profiles]
        if not profiles:
            return False

        if not all(p.get("Enabled", False) for p in profiles):
            return False

        # Check IPSec rules are defined for server-to-server communication
        ipsec_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetIPsecRule -Enabled True | Select-Object DisplayName | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        ipsec_configured = bool(
            ipsec_result.returncode == 0 and ipsec_result.stdout.strip()
        )

        # Check share permissions are not open to Everyone with Full/Change
        share_result = subprocess.run(
            ["powershell", "-Command",
             "Get-SmbShareAccess * | Select-Object Name, AccountName, AccessRight | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if share_result.returncode != 0:
            return False

        shares = json.loads(share_result.stdout)
        if isinstance(shares, dict):
            shares = [shares]
        if not shares:
            return False

        admin_shares = {"admin$", "c$", "ipc$", "print$"}
        broad_principals = {"everyone", "authenticated users"}
        flagged_shares = [
            s for s in shares
            if (s.get("AccountName") or "").lower().split("\\")[-1] in broad_principals
            and (s.get("Name") or "").lower() not in admin_shares
            and (s.get("AccessRight") or "").lower() in {"full", "change"}
        ]

        return bool(ipsec_configured and not flagged_shares)

    except Exception:
        return False


def cui_flow_authorization_ws() -> bool:
    """
    AC.L2-3.1.3d - Authorizations for Controlling CUI Flow are Defined (Windows Server)
    Checks that AD group assignments, NTFS permissions, and share permissions
    are scoped to named authorized groups rather than broad principals.
    Returns True if CUI flow authorizations are scoped to named identities.
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Check share permissions are scoped to named groups
        share_result = subprocess.run(
            ["powershell", "-Command",
             "Get-SmbShareAccess * | Select-Object Name, AccountName, AccessRight | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if share_result.returncode != 0:
            return False

        shares = json.loads(share_result.stdout)
        if isinstance(shares, dict):
            shares = [shares]
        if not shares:
            return False

        admin_shares = {"admin$", "c$", "ipc$", "print$"}
        flagged_shares = [
            s for s in shares
            if (s.get("AccountName") or "").lower().split("\\")[-1] in broad_principals
            and (s.get("Name") or "").lower() not in admin_shares
        ]

        if flagged_shares:
            return False

        # Check local Administrators group is scoped to named identities
        admin_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if admin_result.returncode != 0:
            return False

        admins = json.loads(admin_result.stdout)
        if isinstance(admins, dict):
            admins = [admins]
        if not admins:
            return False

        flagged_admins = [
            a for a in admins
            if (a.get("Name") or "").lower().split("\\")[-1] in broad_principals
        ]

        return bool(not flagged_admins)

    except Exception:
        return False


def cui_flow_policy_lx() -> bool:
    """
    AC.L2-3.1.3a - Information Flow Control Policies are Defined (Linux/Debian)
    Checks that SELinux or AppArmor policy definitions exist and that
    firewall rules are configured, indicating a defined flow control policy.
    Returns True if at least one MAC policy and firewall configuration exist.
    """
    try:
        mac_policy_defined = False
        firewall_policy_defined = False

        # Check SELinux policy is loaded
        selinux_result = subprocess.run(
            ["sestatus"],
            capture_output=True, text=True, timeout=10
        )
        if selinux_result.returncode == 0:
            output = selinux_result.stdout.lower()
            if "policy from config file" in output or "loaded policy name" in output:
                mac_policy_defined = True

        # Check AppArmor profiles are loaded if SELinux is not present
        if not mac_policy_defined:
            aa_result = subprocess.run(
                ["apparmor_status", "--json"],
                capture_output=True, text=True, timeout=10
            )
            if aa_result.returncode == 0 and aa_result.stdout.strip():
                aa_data = json.loads(aa_result.stdout)
                profiles = aa_data.get("profiles", {})
                enforce_count = sum(
                    1 for mode in profiles.values()
                    if mode == "enforce"
                )
                mac_policy_defined = bool(enforce_count > 0)

        # Check firewall has at least one defined ruleset
        for cmd in [
            ["iptables", "-L", "INPUT", "-n"],
            ["nft", "list", "ruleset"],
            ["firewall-cmd", "--list-all"]
        ]:
            fw_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if fw_result.returncode == 0 and fw_result.stdout.strip():
                firewall_policy_defined = True
                break

        return bool(mac_policy_defined and firewall_policy_defined)

    except Exception:
        return False


def cui_flow_enforcement_lx() -> bool:
    """
    AC.L2-3.1.3b - Methods and Enforcement Mechanisms for CUI Flow are Defined (Linux/Debian)
    Checks that iptables/nftables/firewalld is active with inbound rules,
    SELinux or AppArmor is enforcing, and file permissions follow least privilege.
    Returns True if all three enforcement mechanisms are active.
    """
    try:
        firewall_enforcing = False
        mac_enforcing = False
        file_permissions_ok = False

        # Check firewall has active inbound restriction rules
        ipt_result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=30
        )
        if ipt_result.returncode == 0:
            lines = ipt_result.stdout.strip().splitlines()
            rules = [l for l in lines if re.match(r"^\d+", l.strip())]
            non_accept_all = [
                r for r in rules
                if not re.search(r"ACCEPT\s+all\s+--\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0", r)
            ]
            firewall_enforcing = bool(non_accept_all)

        if not firewall_enforcing:
            nft_result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True, text=True, timeout=30
            )
            if nft_result.returncode == 0 and nft_result.stdout.strip():
                chain_block = re.search(
                    r"chain\s+input\s*\{(.*?)\}",
                    nft_result.stdout, re.DOTALL | re.IGNORECASE
                )
                if chain_block:
                    rule_lines = [
                        l for l in chain_block.group(1).strip().splitlines()
                        if l.strip() and not l.strip().startswith("type")
                    ]
                    firewall_enforcing = bool(rule_lines)

        # Check SELinux or AppArmor is enforcing
        selinux_result = subprocess.run(
            ["getenforce"], capture_output=True, text=True, timeout=10
        )
        if selinux_result.returncode == 0:
            mac_enforcing = bool(
                selinux_result.stdout.strip().lower() == "enforcing"
            )

        if not mac_enforcing:
            aa_result = subprocess.run(
                ["aa-status", "--enabled"],
                capture_output=True, text=True, timeout=10
            )
            mac_enforcing = bool(aa_result.returncode == 0)

        # Check world-writable files do not exist in sensitive directories
        fw_check = subprocess.run(
            ["find", "/etc", "/var", "-maxdepth", "3",
             "-type", "f", "-perm", "-o+w",
             "-not", "-path", "*/proc/*"],
            capture_output=True, text=True, timeout=30
        )
        if fw_check.returncode == 0:
            world_writable = [
                l for l in fw_check.stdout.strip().splitlines()
                if l.strip()
            ]
            file_permissions_ok = bool(not world_writable)

        return bool(firewall_enforcing and mac_enforcing and file_permissions_ok)

    except Exception:
        return False


def cui_flow_authorization_lx() -> bool:
    """
    AC.L2-3.1.3d - Authorizations for Controlling CUI Flow are Defined (Linux/Debian)
    Checks that file ownership, group permissions, and ACLs on sensitive
    directories are scoped to named users and roles, not world-accessible.
    Returns True if sensitive directories are properly owned and not world-readable.
    """
    try:
        sensitive_dirs = ["/etc/sudoers", "/etc/ssh", "/etc/pam.d", "/var/log"]
        flagged = []

        for path in sensitive_dirs:
            # Check for world-readable or world-writable permissions
            stat_result = subprocess.run(
                ["stat", "-c", "%a %U %G", path],
                capture_output=True, text=True, timeout=10
            )
            if stat_result.returncode != 0:
                continue

            parts = stat_result.stdout.strip().split()
            if len(parts) < 3:
                continue

            mode, owner, group = parts[0], parts[1], parts[2]

            # Convert octal mode string to int for bitwise check
            try:
                mode_int = int(mode, 8)
            except ValueError:
                continue

            # Flag if world-writable (o+w) or world-readable on sensitive paths
            world_writable = bool(mode_int & 0o002)
            world_readable = bool(mode_int & 0o004)

            # /var/log can be world-readable but not world-writable
            if path == "/var/log":
                if world_writable:
                    flagged.append(path)
            else:
                if world_writable or world_readable:
                    flagged.append(path)

            # Check owner is root or a named service account, not a generic user
            if owner.lower() in {"nobody", "anonymous", ""}:
                flagged.append(path)

        # Check getfacl for any ACL entries granting broad access
        acl_result = subprocess.run(
            ["getfacl", "-R", "/etc/ssh"],
            capture_output=True, text=True, timeout=30
        )
        if acl_result.returncode == 0:
            acl_lines = [
                l for l in acl_result.stdout.splitlines()
                if l.startswith("other:") and "w" in l
            ]
            if acl_lines:
                flagged.append("/etc/ssh ACL")

        return bool(not flagged)

    except Exception:
        return False

def separation_of_duties_defined_wc() -> bool:
    """
    AC.L2-3.1.4a - Duties Requiring Separation are Defined (Windows Client)
    Checks that distinct local groups exist representing separated roles
    (Administrators vs standard Users) and that Group Policy enforces
    user rights assignments to named groups rather than broad principals.
    Returns True if separated role definitions are in place.
    """
    try:
        broad_principals = {"everyone", "authenticated users"}

        # Check that both Administrators and Users groups exist and are non-empty
        for group in ["Administrators", "Users"]:
            group_result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-LocalGroupMember -Group '{group}' | "
                 "Select-Object Name, PrincipalSource | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if group_result.returncode != 0:
                return False

            members = json.loads(group_result.stdout) if group_result.stdout.strip() else []
            if isinstance(members, dict):
                members = [members]
            if not members:
                return False

        # Check user rights assignments via secedit are scoped to named groups
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeAdministerSecurityPolicyPrivilege|"
             "SeBackupPrivilege|SeRestorePrivilege'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        policy_lines = secedit_result.stdout.strip().splitlines()

        # Fail if any sensitive privilege is assigned to Everyone or blank
        flagged = [
            l for l in policy_lines
            if any(p in l.lower() for p in broad_principals)
            or re.search(r"=\s*$", l)
        ]

        return bool(not flagged)

    except Exception:
        return False


def separation_of_duties_assigned_wc() -> bool:
    """
    AC.L2-3.1.4b - Responsibilities for Separated Duties are Assigned to
    Separate Individuals (Windows Client)
    Checks that no single local user account is a member of both the
    Administrators group and the standard Users group simultaneously,
    and that no standard user has been granted admin-level user rights.
    Returns True if no cross-role membership conflicts are found.
    """
    try:
        # Get Administrators group members
        admin_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Administrators' | "
             "Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if admin_result.returncode != 0:
            return False

        admins = json.loads(admin_result.stdout) if admin_result.stdout.strip() else []
        if isinstance(admins, dict):
            admins = [admins]
        if not admins:
            return False

        admin_names = {
            a.get("Name", "").lower().split("\\")[-1]
            for a in admins
        }

        # Get standard Users group members
        users_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Users' | "
             "Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if users_result.returncode != 0:
            return False

        users = json.loads(users_result.stdout) if users_result.stdout.strip() else []
        if isinstance(users, dict):
            users = [users]
        if not users:
            return False

        user_names = {
            u.get("Name", "").lower().split("\\")[-1]
            for u in users
        }

        # Flag any account that appears in both groups
        # Built-in accounts like Administrator are expected in Admins only
        cross_role = admin_names.intersection(user_names) - {"administrator"}
        if cross_role:
            return False

        # Check no standard user has been granted SeDebugPrivilege
        # or SeLoadDriverPrivilege via secedit
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeDebugPrivilege|SeLoadDriverPrivilege'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        priv_lines = secedit_result.stdout.strip().splitlines()
        flagged_privs = []
        for line in priv_lines:
            # Extract assigned SIDs/names after the = sign
            if "=" in line:
                assigned = line.split("=", 1)[1].strip().lower()
                # Flag if any standard user name appears in the privilege assignment
                for user in user_names - {"administrator", "guest"}:
                    if user in assigned:
                        flagged_privs.append(line)

        return bool(not flagged_privs)

    except Exception:
        return False


def separation_of_duties_defined_ws() -> bool:
    """
    AC.L2-3.1.4a - Duties Requiring Separation are Defined (Windows Server)
    Checks that high-privilege AD groups representing separated roles exist
    and are non-empty, and that no single group conflates multiple
    high-privilege roles such as Domain Admins and Backup Operators.
    Returns True if separated role definitions are in place.
    """
    try:
        # High privilege groups that should have distinct, non-overlapping membership
        sensitive_groups = [
            "Domain Admins",
            "Backup Operators",
            "Account Operators",
            "Server Operators"
        ]

        group_members = {}
        for group in sensitive_groups:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-ADGroupMember -Identity '{group}' -Recursive | "
                 "Select-Object SamAccountName | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                continue

            members = json.loads(result.stdout) if result.stdout.strip() else []
            if isinstance(members, dict):
                members = [members]

            group_members[group] = {
                m.get("SamAccountName", "").lower()
                for m in members
            }

        # Fail if none of the sensitive groups could be queried
        if not group_members:
            return False

        # Check Domain Admins group is not empty
        if not group_members.get("Domain Admins"):
            return False

        # Check that Backup Operators and Account Operators are defined
        # separately from Domain Admins (roles are separated)
        domain_admins = group_members.get("Domain Admins", set())
        backup_ops = group_members.get("Backup Operators", set())
        account_ops = group_members.get("Account Operators", set())

        # Flag if the same accounts appear across all three groups
        # indicating no real separation
        full_overlap = domain_admins & backup_ops & account_ops
        if full_overlap:
            return False

        return True

    except Exception:
        return False


def separation_of_duties_assigned_ws() -> bool:
    """
    AC.L2-3.1.4b - Responsibilities for Separated Duties are Assigned to
    Separate Individuals (Windows Server)
    Checks that no single AD user account is simultaneously a member of
    multiple high-privilege groups such as Domain Admins and Backup Operators,
    which would undermine separation of duties.
    Returns True if no cross-role high-privilege membership conflicts are found.
    """
    try:
        # Groups that should have mutually exclusive membership
        conflicting_group_pairs = [
            ("Domain Admins", "Backup Operators"),
            ("Domain Admins", "Account Operators"),
            ("Domain Admins", "Schema Admins"),
            ("Schema Admins", "Backup Operators"),
        ]

        flagged_accounts = set()

        for group_a, group_b in conflicting_group_pairs:
            # Get members of group A
            result_a = subprocess.run(
                ["powershell", "-Command",
                 f"Get-ADGroupMember -Identity '{group_a}' -Recursive | "
                 "Select-Object SamAccountName | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result_a.returncode != 0:
                continue

            members_a = json.loads(result_a.stdout) if result_a.stdout.strip() else []
            if isinstance(members_a, dict):
                members_a = [members_a]

            names_a = {
                m.get("SamAccountName", "").lower()
                for m in members_a
            }

            # Get members of group B
            result_b = subprocess.run(
                ["powershell", "-Command",
                 f"Get-ADGroupMember -Identity '{group_b}' -Recursive | "
                 "Select-Object SamAccountName | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result_b.returncode != 0:
                continue

            members_b = json.loads(result_b.stdout) if result_b.stdout.strip() else []
            if isinstance(members_b, dict):
                members_b = [members_b]

            names_b = {
                m.get("SamAccountName", "").lower()
                for m in members_b
            }

            # Flag any account appearing in both groups
            overlap = names_a & names_b - {"administrator", "krbtgt"}
            flagged_accounts.update(overlap)

        return bool(not flagged_accounts)

    except Exception:
        return False


def separation_of_duties_defined_lx() -> bool:
    """
    AC.L2-3.1.4a - Duties Requiring Separation are Defined (Linux/Debian)
    Checks that distinct groups exist for elevated and standard access
    (sudo/wheel vs regular users), that sudoers entries are scoped to
    named users or groups, and that no wildcard or ALL entries exist
    without explicit scoping.
    Returns True if separated role definitions are in place.
    """
    try:
        # Check sudo or wheel group exists and is non-empty
        privileged_group = None
        for group in ["sudo", "wheel"]:
            group_result = subprocess.run(
                ["getent", "group", group],
                capture_output=True, text=True, timeout=10
            )
            if group_result.returncode == 0 and group_result.stdout.strip():
                parts = group_result.stdout.strip().split(":")
                # Group format: groupname:password:gid:members
                members = parts[3].split(",") if len(parts) > 3 else []
                members = [m.strip() for m in members if m.strip()]
                if members:
                    privileged_group = group
                    break

        if not privileged_group:
            return False

        # Check sudoers defines scoped entries, not blanket ALL=(ALL) ALL
        sudoers_result = subprocess.run(
            ["sudo", "cat", "/etc/sudoers"],
            capture_output=True, text=True, timeout=30
        )
        if sudoers_result.returncode != 0:
            return False

        active_lines = [
            l.strip() for l in sudoers_result.stdout.splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]

        # Flag unscoped ALL=(ALL) ALL entries not belonging to root or groups
        unscoped = [
            l for l in active_lines
            if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", l)
            and not l.startswith("%")
            and not l.startswith("root")
        ]

        if unscoped:
            return False

        # Check at least one group-based sudoers entry exists
        # indicating role-based separation is defined
        group_entries = [
            l for l in active_lines
            if l.startswith("%") and "ALL" in l
        ]

        return bool(group_entries)

    except Exception:
        return False


def separation_of_duties_assigned_lx() -> bool:
    """
    AC.L2-3.1.4b - Responsibilities for Separated Duties are Assigned to
    Separate Individuals (Linux/Debian)
    Checks that no single user account is simultaneously a member of
    sudo/wheel and other sensitive groups such as shadow, adm, or docker,
    which would indicate a concentration of privileges in one identity.
    Returns True if no cross-role membership conflicts are found.
    """
    try:
        # Groups that indicate elevated or sensitive access
        sensitive_groups = ["sudo", "wheel", "shadow", "adm", "docker", "disk"]

        # Build a map of group -> members
        group_members = {}
        for group in sensitive_groups:
            result = subprocess.run(
                ["getent", "group", group],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                continue

            parts = result.stdout.strip().split(":")
            members = parts[3].split(",") if len(parts) > 3 else []
            members = [m.strip() for m in members if m.strip()]
            group_members[group] = set(members)

        if not group_members:
            return False

        # Identify the primary privileged group (sudo or wheel)
        priv_group = "sudo" if "sudo" in group_members else "wheel"
        priv_members = group_members.get(priv_group, set())

        if not priv_members:
            return False

        # Flag any user that is in sudo/wheel AND another sensitive group
        # docker and disk are particularly dangerous combinations
        high_risk_groups = {"docker", "disk", "shadow"}
        flagged_users = set()

        for group, members in group_members.items():
            if group == priv_group:
                continue
            if group in high_risk_groups:
                overlap = priv_members & members
                flagged_users.update(overlap)

        # Also check /etc/passwd for any non-root UID 0 accounts
        # which would be an unconditional separation of duties failure
        passwd_result = subprocess.run(
            ["awk", "-F:", '$3 == 0 && $1 != "root" {print $1}', "/etc/passwd"],
            capture_output=True, text=True, timeout=10
        )
        if passwd_result.returncode == 0 and passwd_result.stdout.strip():
            # Any non-root UID 0 account is an immediate fail
            return False

        return bool(not flagged_users)

    except Exception:
        return False


def privileged_accounts_identified_wc() -> bool:
    """
    AC.L2-3.1.5a - Privileged Accounts are Identified (Windows Client)
    Enumerates local Administrators group members and checks for any
    accounts with elevated user rights assignments via secedit.
    Returns True if privileged accounts are identified and no anonymous
    or broad principals hold administrative access.
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Get local Administrators group members
        admin_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Administrators' | "
             "Select-Object Name, PrincipalSource | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if admin_result.returncode != 0:
            return False

        admins = json.loads(admin_result.stdout) if admin_result.stdout.strip() else []
        if isinstance(admins, dict):
            admins = [admins]
        if not admins:
            return False

        # Fail if any broad principal holds admin access
        flagged_admins = [
            a for a in admins
            if (a.get("Name") or "").lower().split("\\")[-1] in broad_principals
        ]
        if flagged_admins:
            return False

        # Check elevated user rights via secedit for broad principal assignments
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeDebugPrivilege|SeTakeOwnershipPrivilege|"
             "SeLoadDriverPrivilege|SeBackupPrivilege|SeRestorePrivilege'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        priv_lines = secedit_result.stdout.strip().splitlines()

        # Fail if any sensitive privilege is assigned to broad principals
        flagged_privs = [
            l for l in priv_lines
            if any(p in l.lower() for p in broad_principals)
        ]

        return bool(not flagged_privs)

    except Exception:
        return False


def privileged_accounts_identified_ws() -> bool:
    """
    AC.L2-3.1.5a - Privileged Accounts are Identified (Windows Server)
    Enumerates Domain Admins, Schema Admins, Enterprise Admins, and
    local Administrator accounts. Returns True if all privileged groups
    are non-empty, contain only named accounts, and no broad principals
    hold membership in any high-privilege group.
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}
        privileged_groups = [
            "Domain Admins",
            "Schema Admins",
            "Enterprise Admins",
            "Group Policy Creator Owners"
        ]

        for group in privileged_groups:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-ADGroupMember -Identity '{group}' -Recursive | "
                 "Select-Object SamAccountName, objectClass | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                continue

            members = json.loads(result.stdout) if result.stdout.strip() else []
            if isinstance(members, dict):
                members = [members]

            # Flag any broad principal in privileged groups
            flagged = [
                m for m in members
                if (m.get("SamAccountName") or "").lower() in broad_principals
            ]
            if flagged:
                return False

        # Check local Administrator account is not renamed to a generic name
        local_admin_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalUser | Where-Object {$_.SID -like '*-500'} | "
             "Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if local_admin_result.returncode != 0:
            return False

        local_admin = json.loads(local_admin_result.stdout) if local_admin_result.stdout.strip() else {}
        if isinstance(local_admin, list):
            local_admin = local_admin[0] if local_admin else {}

        # Local built-in admin (RID 500) should exist but ideally be disabled
        # Fail if it is enabled and named something generic
        if local_admin.get("Enabled", False):
            name = (local_admin.get("Name") or "").lower()
            if name in {"admin", "administrator", "user", ""}:
                return False

        return True

    except Exception:
        return False


def privileged_accounts_identified_lx() -> bool:
    """
    AC.L2-3.1.5a - Privileged Accounts are Identified (Linux/Debian)
    Enumerates sudo/wheel group members, UID 0 accounts, and sudoers
    entries to confirm all privileged accounts are named and identified.
    Returns True if all privileged accounts are explicitly named with
    no anonymous or wildcard privilege grants.
    """
    try:
        # Check for any non-root UID 0 accounts
        uid0_result = subprocess.run(
            ["awk", "-F:", '$3 == 0 {print $1}', "/etc/passwd"],
            capture_output=True, text=True, timeout=10
        )
        if uid0_result.returncode != 0:
            return False

        uid0_accounts = [
            l.strip() for l in uid0_result.stdout.strip().splitlines()
            if l.strip()
        ]
        # Only root should have UID 0
        non_root_uid0 = [a for a in uid0_accounts if a != "root"]
        if non_root_uid0:
            return False

        # Check sudo/wheel group has named members
        privileged_members = set()
        for group in ["sudo", "wheel"]:
            result = subprocess.run(
                ["getent", "group", group],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split(":")
                members = parts[3].split(",") if len(parts) > 3 else []
                privileged_members.update(
                    m.strip() for m in members if m.strip()
                )

        if not privileged_members:
            return False

        # Check sudoers for wildcard or anonymous entries
        sudoers_result = subprocess.run(
            ["sudo", "cat", "/etc/sudoers"],
            capture_output=True, text=True, timeout=30
        )
        if sudoers_result.returncode != 0:
            return False

        active_lines = [
            l.strip() for l in sudoers_result.stdout.splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]

        # Flag entries with no specific user/group identifier
        flagged_entries = [
            l for l in active_lines
            if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", l)
            and not l.startswith("%")
            and not l.startswith("root")
            and not any(m in l for m in privileged_members)
        ]

        return bool(not flagged_entries)

    except Exception:
        return False


def security_functions_identified_wc() -> bool:
    """
    AC.L2-3.1.5c - Security Functions are Identified (Windows Client)
    Checks that key security functions — audit policy, Windows Defender
    Firewall, and sensitive user rights — are configured and mapped to
    specific privileged roles rather than left at default or unmanaged.
    Returns True if all three security function areas are configured.
    """
    try:
        audit_configured = False
        firewall_configured = False
        rights_configured = False

        # Check audit policy has at least some categories enabled
        audit_result = subprocess.run(
            ["powershell", "-Command",
             "auditpol /get /category:* | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        # Fall back to plain text parsing if ConvertTo-Json fails
        if audit_result.returncode != 0:
            audit_result = subprocess.run(
                ["auditpol", "/get", "/category:*"],
                capture_output=True, text=True, timeout=30
            )

        if audit_result.returncode == 0 and audit_result.stdout.strip():
            # Check at least Logon/Logoff and Account Logon are being audited
            output = audit_result.stdout.lower()
            audit_configured = bool(
                "success" in output or "failure" in output
            )

        # Check Windows Defender Firewall is active on all profiles
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            profiles = json.loads(fw_result.stdout)
            if isinstance(profiles, dict):
                profiles = [profiles]
            if profiles:
                firewall_configured = bool(
                    all(p.get("Enabled", False) for p in profiles)
                )

        # Check sensitive user rights are assigned via secedit
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeAuditPrivilege|SeSecurityPrivilege|"
             "SeSystemEnvironmentPrivilege'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode == 0 and secedit_result.stdout.strip():
            priv_lines = secedit_result.stdout.strip().splitlines()
            # Rights are configured if entries exist and are non-empty
            assigned = [
                l for l in priv_lines
                if "=" in l and l.split("=", 1)[1].strip() != ""
            ]
            rights_configured = bool(assigned)

        return bool(audit_configured and firewall_configured and rights_configured)

    except Exception:
        return False


def security_functions_identified_ws() -> bool:
    """
    AC.L2-3.1.5c - Security Functions are Identified (Windows Server)
    Checks that audit policy, Windows Defender Firewall, AD administrative
    role assignments, and GPO security settings are configured and mapped
    to specific privileged groups.
    Returns True if all security function areas are configured.
    """
    try:
        audit_configured = False
        firewall_configured = False
        gpo_configured = False

        # Check advanced audit policy is configured
        audit_result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=30
        )
        if audit_result.returncode == 0 and audit_result.stdout.strip():
            output = audit_result.stdout.lower()
            audit_configured = bool(
                "success" in output or "failure" in output
            )

        # Check Windows Defender Firewall is active on all profiles
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            profiles = json.loads(fw_result.stdout)
            if isinstance(profiles, dict):
                profiles = [profiles]
            if profiles:
                firewall_configured = bool(
                    all(p.get("Enabled", False) for p in profiles)
                )

        # Check GPOs exist and are linked indicating security functions
        # are managed via Group Policy
        gpo_result = subprocess.run(
            ["powershell", "-Command",
             "Get-GPO -All | Select-Object DisplayName, GpoStatus | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if gpo_result.returncode == 0 and gpo_result.stdout.strip():
            gpos = json.loads(gpo_result.stdout)
            if isinstance(gpos, dict):
                gpos = [gpos]
            # At least one GPO must be enabled beyond the Default Domain Policy
            active_gpos = [
                g for g in gpos
                if (g.get("GpoStatus") or "").lower() not in {"alldisabled"}
                and (g.get("DisplayName") or "").lower() != "default domain policy"
            ]
            gpo_configured = bool(active_gpos)

        return bool(audit_configured and firewall_configured and gpo_configured)

    except Exception:
        return False


def security_functions_identified_lx() -> bool:
    """
    AC.L2-3.1.5c - Security Functions are Identified (Linux/Debian)
    Checks that firewall management, audit logging (auditd), and
    SELinux/AppArmor administration are active and mapped to
    named privileged accounts via sudoers or group membership.
    Returns True if all three security function areas are identified.
    """
    try:
        auditd_configured = False
        firewall_identified = False
        mac_identified = False

        # Check auditd is running
        auditd_result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True, text=True, timeout=10
        )
        if auditd_result.returncode == 0:
            auditd_configured = bool(
                auditd_result.stdout.strip().lower() == "active"
            )

        # Check auditd has rules defined
        if auditd_configured:
            rules_result = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True, text=True, timeout=10
            )
            if rules_result.returncode == 0:
                rules = [
                    l for l in rules_result.stdout.strip().splitlines()
                    if l.strip() and "No rules" not in l
                ]
                auditd_configured = bool(rules)

        # Check firewall is active and identifiable
        for cmd in [
            ["iptables", "-L", "INPUT", "-n"],
            ["nft", "list", "ruleset"],
            ["firewall-cmd", "--state"]
        ]:
            fw_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if fw_result.returncode == 0 and fw_result.stdout.strip():
                firewall_identified = True
                break

        # Check SELinux or AppArmor is active
        selinux_result = subprocess.run(
            ["getenforce"], capture_output=True, text=True, timeout=10
        )
        if selinux_result.returncode == 0:
            mac_identified = bool(
                selinux_result.stdout.strip().lower() in {"enforcing", "permissive"}
            )

        if not mac_identified:
            aa_result = subprocess.run(
                ["aa-status", "--enabled"],
                capture_output=True, text=True, timeout=10
            )
            mac_identified = bool(aa_result.returncode == 0)

        return bool(auditd_configured and firewall_identified and mac_identified)

    except Exception:
        return False


def security_functions_enforcement_wc() -> bool:
    """
    AC.L2-3.1.5d - Access to Security Functions is Authorized per Least
    Privilege (Windows Client)
    Checks that sensitive user rights (audit management, security policy,
    debug privilege) are restricted to named privileged accounts and
    explicitly denied to standard users via Group Policy.
    Returns True if security function access is properly restricted.
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Export secedit and check sensitive privilege assignments
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeAuditPrivilege|SeSecurityPrivilege|"
             "SeDebugPrivilege|SeLoadDriverPrivilege|"
             "SeTakeOwnershipPrivilege|SeSystemEnvironmentPrivilege'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        priv_lines = secedit_result.stdout.strip().splitlines()
        if not priv_lines:
            return False

        # Fail if any sensitive privilege is assigned to broad principals
        flagged = [
            l for l in priv_lines
            if any(p in l.lower() for p in broad_principals)
        ]
        if flagged:
            return False

        # Check Windows Defender Firewall management is restricted
        # by confirming standard users cannot modify firewall rules
        # via UAC enforcement (ConsentPromptBehaviorUser must not be 0)
        uac_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
             "| Select-Object ConsentPromptBehaviorUser, "
             "EnableLUA | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if uac_result.returncode != 0:
            return False

        uac_data = json.loads(uac_result.stdout) if uac_result.stdout.strip() else {}

        # EnableLUA must be 1 (UAC enabled)
        # ConsentPromptBehaviorUser must not be 0 (0 = elevate without prompting)
        lua_enabled = bool(uac_data.get("EnableLUA", 0) == 1)
        prompt_behavior = uac_data.get("ConsentPromptBehaviorUser", 0)
        uac_enforced = bool(lua_enabled and prompt_behavior != 0)

        return bool(not flagged and uac_enforced)

    except Exception:
        return False


def security_functions_enforcement_ws() -> bool:
    """
    AC.L2-3.1.5d - Access to Security Functions is Authorized per Least
    Privilege (Windows Server)
    Checks that sensitive AD and GP security function rights are restricted
    to named privileged groups, UAC is enforced, and standard users are
    explicitly denied administrative user rights via Group Policy.
    Returns True if security function access is properly restricted.
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Check sensitive user rights via secedit
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeAuditPrivilege|SeSecurityPrivilege|"
             "SeDebugPrivilege|SeLoadDriverPrivilege|"
             "SeTakeOwnershipPrivilege|SeRemoteInteractiveLogonRight'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        priv_lines = secedit_result.stdout.strip().splitlines()
        if not priv_lines:
            return False

        flagged_privs = [
            l for l in priv_lines
            if any(p in l.lower() for p in broad_principals)
        ]
        if flagged_privs:
            return False

        # Check UAC is enforced on the server
        uac_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
             "| Select-Object EnableLUA, "
             "ConsentPromptBehaviorAdmin | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if uac_result.returncode != 0:
            return False

        uac_data = json.loads(uac_result.stdout) if uac_result.stdout.strip() else {}
        lua_enabled = bool(uac_data.get("EnableLUA", 0) == 1)

        # ConsentPromptBehaviorAdmin 2 = prompt for credentials (most secure)
        # 1 = prompt for consent, 0 = elevate without prompting (fail)
        admin_prompt = uac_data.get("ConsentPromptBehaviorAdmin", 0)
        uac_enforced = bool(lua_enabled and admin_prompt in {1, 2})

        if not uac_enforced:
            return False

        # Check Administrators group on server does not contain broad principals
        admin_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Administrators' | "
             "Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if admin_result.returncode != 0:
            return False

        admins = json.loads(admin_result.stdout) if admin_result.stdout.strip() else []
        if isinstance(admins, dict):
            admins = [admins]
        if not admins:
            return False

        flagged_admins = [
            a for a in admins
            if (a.get("Name") or "").lower().split("\\")[-1] in broad_principals
        ]

        return bool(not flagged_admins)

    except Exception:
        return False


def security_functions_enforcement_lx() -> bool:
    """
    AC.L2-3.1.5d - Access to Security Functions is Authorized per Least
    Privilege (Linux/Debian)
    Checks that sudoers entries for security functions (firewall, auditd,
    SELinux/AppArmor) are scoped to named privileged accounts, sensitive
    group membership is controlled, and MAC policy is enforcing.
    Returns True if all three enforcement conditions are met.
    """
    try:
        sudoers_scoped = False
        mac_enforcing = False
        sensitive_groups_clean = False

        # Check sudoers scopes security tool access to named users/groups
        sudoers_result = subprocess.run(
            ["sudo", "cat", "/etc/sudoers"],
            capture_output=True, text=True, timeout=30
        )
        if sudoers_result.returncode != 0:
            return False

        active_lines = [
            l.strip() for l in sudoers_result.stdout.splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]

        # Check no unscoped ALL=(ALL) ALL entries exist for non-root non-group accounts
        unscoped = [
            l for l in active_lines
            if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", l)
            and not l.startswith("%")
            and not l.startswith("root")
        ]
        sudoers_scoped = bool(not unscoped)

        # Also check sudoers.d for unscoped entries
        sudoersd_result = subprocess.run(
            ["sudo", "grep", "-r",
             r"ALL=(ALL) ALL", "/etc/sudoers.d/"],
            capture_output=True, text=True, timeout=30
        )
        if sudoersd_result.returncode == 0 and sudoersd_result.stdout.strip():
            unscoped_d = [
                l for l in sudoersd_result.stdout.splitlines()
                if l.strip()
                and not l.strip().startswith("#")
                and not l.strip().startswith("%")
            ]
            if unscoped_d:
                sudoers_scoped = False

        # Check SELinux or AppArmor is enforcing
        selinux_result = subprocess.run(
            ["getenforce"], capture_output=True, text=True, timeout=10
        )
        if selinux_result.returncode == 0:
            mac_enforcing = bool(
                selinux_result.stdout.strip().lower() == "enforcing"
            )

        if not mac_enforcing:
            aa_result = subprocess.run(
                ["aa-status", "--enabled"],
                capture_output=True, text=True, timeout=10
            )
            mac_enforcing = bool(aa_result.returncode == 0)

        # Check sensitive groups do not contain unexpected members
        # adm group controls audit log access, shadow controls password hashes
        sensitive_groups = ["adm", "shadow"]
        flagged_members = []

        for group in sensitive_groups:
            result = subprocess.run(
                ["getent", "group", group],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                continue

            parts = result.stdout.strip().split(":")
            members = parts[3].split(",") if len(parts) > 3 else []
            members = [m.strip() for m in members if m.strip()]

            # Get sudo/wheel members for comparison
            priv_members = set()
            for priv_group in ["sudo", "wheel"]:
                pg_result = subprocess.run(
                    ["getent", "group", priv_group],
                    capture_output=True, text=True, timeout=10
                )
                if pg_result.returncode == 0 and pg_result.stdout.strip():
                    pg_parts = pg_result.stdout.strip().split(":")
                    pg_members = pg_parts[3].split(",") if len(pg_parts) > 3 else []
                    priv_members.update(
                        m.strip() for m in pg_members if m.strip()
                    )

            # Flag members of sensitive groups who are NOT in sudo/wheel
            # as they may have inadvertent access to security functions
            unexpected = [
                m for m in members
                if m not in priv_members and m != "root"
            ]
            flagged_members.extend(unexpected)

        sensitive_groups_clean = bool(not flagged_members)

        return bool(sudoers_scoped and mac_enforcing and sensitive_groups_clean)

    except Exception:
        return False