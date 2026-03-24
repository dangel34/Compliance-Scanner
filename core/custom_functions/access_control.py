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

def nonprivileged_access_wc() -> bool:
    """
    AC.L2-3.1.6b - Users are Required to Use Non-Privileged Accounts for
    Nonsecurity Functions (Windows Client)
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Check UAC is enabled and standard users are prompted
        uac_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
             "| Select-Object EnableLUA, ConsentPromptBehaviorUser, "
             "ConsentPromptBehaviorAdmin | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if uac_result.returncode != 0:
            return False

        uac_data = json.loads(uac_result.stdout) if uac_result.stdout.strip() else {}
        if not uac_data:
            return False

        # EnableLUA must be 1
        if not bool(uac_data.get("EnableLUA", 0) == 1):
            return False

        # ConsentPromptBehaviorUser must not be 0 (silent elevation)
        # 0 = auto-elevate without prompt (fail)
        # 1 = prompt for credentials (pass)
        # 3 = prompt for consent (pass)
        if bool(uac_data.get("ConsentPromptBehaviorUser", 0) == 0):
            return False

        # Check standard Users group does not overlap with Administrators
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

        admin_names = {
            a.get("Name", "").lower().split("\\")[-1]
            for a in admins
        }
        user_names = {
            u.get("Name", "").lower().split("\\")[-1]
            for u in users
        }

        # Flag any account in both groups indicating an admin
        # is also being used as a standard daily-use account
        cross_role = admin_names.intersection(user_names) - {"administrator"}
        if cross_role:
            return False

        # Check no broad principal holds admin rights
        flagged_admins = [
            a for a in admins
            if (a.get("Name") or "").lower().split("\\")[-1] in broad_principals
        ]
        if flagged_admins:
            return False

        # Check sensitive privileges are not assigned to standard users
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeDebugPrivilege|SeTakeOwnershipPrivilege|"
             "SeLoadDriverPrivilege|SeBackupPrivilege'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        priv_lines = secedit_result.stdout.strip().splitlines()
        flagged_privs = [
            l for l in priv_lines
            if any(u in l.lower() for u in user_names - {"administrator", "guest"})
        ]

        return bool(not flagged_privs)

    except Exception:
        return False


def nonprivileged_access_ws() -> bool:
    """
    AC.L2-3.1.6b - Users are Required to Use Non-Privileged Accounts for
    Nonsecurity Functions (Windows Server)

    """
    try:
        # Check UAC is enforced on the server
        uac_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
             "| Select-Object EnableLUA, ConsentPromptBehaviorAdmin | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if uac_result.returncode != 0:
            return False

        uac_data = json.loads(uac_result.stdout) if uac_result.stdout.strip() else {}
        if not uac_data:
            return False

        if not bool(uac_data.get("EnableLUA", 0) == 1):
            return False

        # ConsentPromptBehaviorAdmin must not be 0 (silent elevation)
        admin_prompt = uac_data.get("ConsentPromptBehaviorAdmin", 0)
        if not bool(admin_prompt in {1, 2, 5}):
            return False

        # Check Domain Admins do not have mailbox-style accounts
        # by verifying no DA account has a standard UPN suffix
        # or is also listed as a standard enabled user with a description
        # suggesting daily use
        da_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | "
             "ForEach-Object { Get-ADUser $_.SamAccountName "
             "-Properties Description, EmailAddress, LastLogonDate } | "
             "Select-Object SamAccountName, Description, "
             "EmailAddress, Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if da_result.returncode != 0:
            return False

        da_members = json.loads(da_result.stdout) if da_result.stdout.strip() else []
        if isinstance(da_members, dict):
            da_members = [da_members]
        if not da_members:
            return False

        # Flag DA accounts that have email addresses assigned
        # indicating they are being used as daily-use accounts
        flagged_da = [
            m for m in da_members
            if (m.get("EmailAddress") or "").strip() != ""
        ]
        if flagged_da:
            return False

        # Check interactive logon is restricted for DA accounts
        # by verifying "Allow log on locally" is not open to Domain Admins
        # on non-DC machines via secedit
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeInteractiveLogonRight|"
             "SeDenyInteractiveLogonRight'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        logon_lines = secedit_result.stdout.strip().splitlines()

        # Fail if interactive logon is open to Everyone or broad principals
        broad_principals = {"everyone", "authenticated users", "users"}
        flagged_logon = [
            l for l in logon_lines
            if "SeInteractiveLogonRight" in l
            and any(p in l.lower() for p in broad_principals)
        ]

        return bool(not flagged_logon)

    except Exception:
        return False


def nonprivileged_access_lx() -> bool:
    """
    AC.L2-3.1.6b - Users are Required to Use Non-Privileged Accounts for
    Nonsecurity Functions (Linux/Debian)
    """
    try:
        root_login_disabled = False
        no_unrestricted_sudo = False
        no_standard_priv_overlap = False

        # Check root SSH login is disabled
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode == 0:
            output = sshd_result.stdout.lower()
            permit_root = re.search(
                r"^permitrootlogin\s+(\S+)", output, re.MULTILINE
            )
            if permit_root:
                root_login_disabled = bool(
                    permit_root.group(1).lower() in {"no", "prohibit-password"}
                )

        # Check standard users do not have unrestricted sudo access
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

        # Get standard users (UID >= 1000)
        passwd_result = subprocess.run(
            ["awk", "-F:", '$3 >= 1000 && $1 != "nobody" {print $1}',
             "/etc/passwd"],
            capture_output=True, text=True, timeout=10
        )
        if passwd_result.returncode != 0:
            return False

        standard_users = {
            l.strip() for l in passwd_result.stdout.strip().splitlines()
            if l.strip()
        }

        if not standard_users:
            return False

        # Flag any standard user with an unrestricted ALL=(ALL) ALL entry
        unrestricted = [
            l for l in active_lines
            if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", l)
            and not l.startswith("%")
            and not l.startswith("root")
            and any(u in l for u in standard_users)
        ]
        no_unrestricted_sudo = bool(not unrestricted)

        # Also check sudoers.d
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
                and any(u in l for u in standard_users)
            ]
            if unscoped_d:
                no_unrestricted_sudo = False

        # Check standard users are not members of privileged security groups
        security_groups = ["sudo", "wheel", "shadow", "adm", "docker", "disk"]
        flagged_users = set()

        for group in security_groups:
            result = subprocess.run(
                ["getent", "group", group],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                continue

            parts = result.stdout.strip().split(":")
            members = parts[3].split(",") if len(parts) > 3 else []
            members = {m.strip() for m in members if m.strip()}

            # Flag standard users (UID >= 1000) found in security groups
            overlap = standard_users & members
            flagged_users.update(overlap)

        no_standard_priv_overlap = bool(not flagged_users)

        return bool(
            root_login_disabled
            and no_unrestricted_sudo
            and no_standard_priv_overlap
        )

    except Exception:
        return False


# AC.L2-3.1.7 Funcs
def privileged_function_prevention_wc() -> bool:
    """
    AC.L2-3.1.7c - Non-Privileged Users are Prevented from Executing
    Privileged Functions (Windows Client)
    """
    try:
        uac_enforced = False
        applocker_or_srp_active = False
        rights_restricted = False

        broad_principals = {"everyone", "authenticated users", "users"}

        # Check UAC is fully enforced
        uac_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
             "| Select-Object EnableLUA, ConsentPromptBehaviorUser, "
             "ConsentPromptBehaviorAdmin | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if uac_result.returncode != 0:
            return False

        uac_data = json.loads(uac_result.stdout) if uac_result.stdout.strip() else {}
        if not uac_data:
            return False

        lua_enabled = bool(uac_data.get("EnableLUA", 0) == 1)
        user_prompt = uac_data.get("ConsentPromptBehaviorUser", 0)
        # User prompt must not be 0 (silent elevation)
        uac_enforced = bool(lua_enabled and user_prompt != 0)

        # Check AppLocker has enforced rules
        applocker_result = subprocess.run(
            ["powershell", "-Command",
             "Get-AppLockerPolicy -Effective | "
             "Select-Object -ExpandProperty RuleCollections | "
             "Select-Object RuleCollectionType, EnforcementMode | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if applocker_result.returncode == 0 and applocker_result.stdout.strip():
            rules = json.loads(applocker_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if rules:
                enforced = [
                    r for r in rules
                    if (r.get("EnforcementMode") or "").lower() == "enabled"
                ]
                applocker_or_srp_active = bool(enforced)

        # Fall back to SRP if AppLocker not active
        if not applocker_or_srp_active:
            srp_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object DefaultLevel | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if srp_result.returncode == 0 and srp_result.stdout.strip():
                srp_data = json.loads(srp_result.stdout)
                applocker_or_srp_active = bool(
                    srp_data.get("DefaultLevel", 131072) == 0
                )

        # Check sensitive user rights are not assigned to broad principals
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeDebugPrivilege|SeTakeOwnershipPrivilege|"
             "SeLoadDriverPrivilege|SeBackupPrivilege|"
             "SeRestorePrivilege|SeSecurityPrivilege'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        priv_lines = secedit_result.stdout.strip().splitlines()
        flagged = [
            l for l in priv_lines
            if any(p in l.lower() for p in broad_principals)
        ]
        rights_restricted = bool(not flagged)

        return bool(uac_enforced and applocker_or_srp_active and rights_restricted)

    except Exception:
        return False


def privileged_function_prevention_ws() -> bool:
    """
    AC.L2-3.1.7c - Non-Privileged Users are Prevented from Executing
    Privileged Functions (Windows Server)
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Check UAC is enforced
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
        if not uac_data:
            return False

        lua_enabled = bool(uac_data.get("EnableLUA", 0) == 1)
        admin_prompt = uac_data.get("ConsentPromptBehaviorAdmin", 0)
        uac_enforced = bool(lua_enabled and admin_prompt in {1, 2, 5})

        if not uac_enforced:
            return False

        # Check sensitive user rights are not assigned to broad principals
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'SeDebugPrivilege|SeTakeOwnershipPrivilege|"
             "SeLoadDriverPrivilege|SeBackupPrivilege|SeRestorePrivilege|"
             "SeSecurityPrivilege|SeAuditPrivilege|"
             "SeSystemEnvironmentPrivilege'"],
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

        # Check Administrators group does not contain broad principals
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


def privileged_function_prevention_lx() -> bool:
    """
    AC.L2-3.1.7c - Non-Privileged Users are Prevented from Executing
    Privileged Functions (Linux/Debian)
    """
    try:
        sudoers_restricted = False
        pam_configured = False
        mac_enforcing = False
        suid_controlled = False

        # Check sudoers has no unscoped ALL=(ALL) ALL for standard users
        passwd_result = subprocess.run(
            ["awk", "-F:", '$3 >= 1000 && $1 != "nobody" {print $1}',
             "/etc/passwd"],
            capture_output=True, text=True, timeout=10
        )
        if passwd_result.returncode != 0:
            return False

        standard_users = {
            l.strip() for l in passwd_result.stdout.strip().splitlines()
            if l.strip()
        }

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

        unrestricted = [
            l for l in active_lines
            if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", l)
            and not l.startswith("%")
            and not l.startswith("root")
            and any(u in l for u in standard_users)
        ]
        sudoers_restricted = bool(not unrestricted)

        # Check PAM has at least one access control module configured
        pam_result = subprocess.run(
            ["grep", "-r",
             "pam_access\\|pam_listfile\\|pam_wheel",
             "/etc/pam.d/"],
            capture_output=True, text=True, timeout=30
        )
        if pam_result.returncode == 0 and pam_result.stdout.strip():
            active_pam = [
                l for l in pam_result.stdout.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]
            pam_configured = bool(active_pam)

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

        # Check SUID/SGID binaries are limited to known system paths
        # and not present in user-writable directories
        suid_result = subprocess.run(
            ["find", "/home", "/tmp", "/var/tmp",
             "-type", "f", "-perm", "/6000"],
            capture_output=True, text=True, timeout=30
        )
        if suid_result.returncode == 0:
            suid_files = [
                l.strip() for l in suid_result.stdout.strip().splitlines()
                if l.strip()
            ]
            # Any SUID/SGID binary in user-writable dirs is a hard fail
            suid_controlled = bool(not suid_files)

        return bool(
            sudoers_restricted
            and pam_configured
            and mac_enforcing
            and suid_controlled
        )

    except Exception:
        return False


def privileged_function_audit_wc() -> bool:
    """
    AC.L2-3.1.7d - Execution of Privileged Functions is Captured in
    Audit Logs (Windows Client)
    """
    try:
        required_categories = {
            "privilege use",
            "account management",
            "policy change",
            "logon"
        }

        audit_result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=30
        )
        if audit_result.returncode != 0:
            return False

        output = audit_result.stdout.lower()
        lines = output.strip().splitlines()

        # Build a map of category -> audit setting
        category_settings = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                # Lines follow format: "  Category Name    Success/Failure/Both/No Auditing"
                setting = parts[-1].lower()
                name = " ".join(parts[:-1]).strip()
                category_settings[name] = setting

        # Check each required category has Success, Failure, or both enabled
        missing = []
        for category in required_categories:
            matched = [
                k for k in category_settings
                if category in k
            ]
            if not matched:
                missing.append(category)
                continue

            # At least one subcategory must be auditing success or failure
            audited = [
                k for k in matched
                if category_settings[k] in {
                    "success", "failure", "success and failure"
                }
            ]
            if not audited:
                missing.append(category)

        return bool(not missing)

    except Exception:
        return False


def privileged_function_audit_ws() -> bool:
    """
    AC.L2-3.1.7d - Execution of Privileged Functions is Captured in
    Audit Logs (Windows Server)
    """
    try:
        required_categories = {
            "privilege use",
            "account management",
            "policy change",
            "logon",
            "directory service access",
            "system"
        }

        audit_result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=30
        )
        if audit_result.returncode != 0:
            return False

        output = audit_result.stdout.lower()
        lines = output.strip().splitlines()

        category_settings = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                setting = parts[-1].lower()
                name = " ".join(parts[:-1]).strip()
                category_settings[name] = setting

        missing = []
        for category in required_categories:
            matched = [
                k for k in category_settings
                if category in k
            ]
            if not matched:
                missing.append(category)
                continue

            audited = [
                k for k in matched
                if category_settings[k] in {
                    "success", "failure", "success and failure"
                }
            ]
            if not audited:
                missing.append(category)

        # Additionally check audit log size is sufficient
        # to retain privileged function records
        log_result = subprocess.run(
            ["powershell", "-Command",
             "Get-WinEvent -ListLog Security | "
             "Select-Object MaximumSizeInBytes | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if log_result.returncode == 0 and log_result.stdout.strip():
            log_data = json.loads(log_result.stdout)
            max_size = log_data.get("MaximumSizeInBytes", 0)
            # Security log should be at least 128MB (134217728 bytes)
            if max_size < 134217728:
                return False

        return bool(not missing)

    except Exception:
        return False


def privileged_function_audit_lx() -> bool:
    """
    AC.L2-3.1.7d - Execution of Privileged Functions is Captured in
    Audit Logs (Linux/Debian)
    """
    try:
        auditd_active = False
        has_sudo_rules = False
        has_priv_rules = False
        has_file_rules = False

        # Check auditd is running
        auditd_result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True, text=True, timeout=10
        )
        auditd_active = bool(
            auditd_result.returncode == 0
            and auditd_result.stdout.strip().lower() == "active"
        )

        if not auditd_active:
            return False

        # Get all active auditd rules
        rules_result = subprocess.run(
            ["auditctl", "-l"],
            capture_output=True, text=True, timeout=10
        )
        if rules_result.returncode != 0:
            return False

        rules = rules_result.stdout.lower()

        if "no rules" in rules or not rules.strip():
            return False

        # Check for sudo/su execution capture rules
        # Looking for rules watching /usr/bin/sudo or /bin/su
        has_sudo_rules = bool(
            re.search(r"(\/usr\/bin\/sudo|\/bin\/su|\/usr\/bin\/su)", rules)
        )

        # Check for privilege escalation capture
        # Looking for rules on setuid, execve with elevated context
        has_priv_rules = bool(
            re.search(
                r"(execve|setuid|setgid|privileged|priv_esc)",
                rules
            )
        )

        # Check for sensitive file access rules
        # Looking for rules watching /etc/passwd, /etc/shadow, /etc/sudoers
        has_file_rules = bool(
            re.search(
                r"(\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|\/etc\/group)",
                rules
            )
        )

        # Check audit log exists and is being written to
        log_result = subprocess.run(
            ["test", "-f", "/var/log/audit/audit.log"],
            capture_output=True, text=True, timeout=10
        )
        log_exists = bool(log_result.returncode == 0)

        if not log_exists:
            return False

        # Check audit log is non-empty
        size_result = subprocess.run(
            ["stat", "-c", "%s", "/var/log/audit/audit.log"],
            capture_output=True, text=True, timeout=10
        )
        if size_result.returncode == 0:
            try:
                log_size = int(size_result.stdout.strip())
                if log_size == 0:
                    return False
            except ValueError:
                return False

        return bool(
            auditd_active
            and has_sudo_rules
            and has_priv_rules
            and has_file_rules
            and log_exists
        )

    except Exception:
        return False

# AC.L2-3.1.8
def logon_attempt_limit_wc() -> bool:
    """
    AC.L2-3.1.8b - Defined Means of Limiting Unsuccessful Logon Attempts
    is Implemented (Windows Client)
    Checks that local account lockout policy is configured with an
    acceptable threshold (3-5 attempts), lockout duration (>= 15 minutes),
    and observation window (>= 15 minutes) via secedit.
    Returns True if all three lockout policy values meet minimum requirements.
    """
    try:
        # Export local security policy via secedit
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'LockoutBadCount|LockoutDuration|"
             "ResetLockoutCount'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        lines = secedit_result.stdout.strip().splitlines()
        if not lines:
            return False

        # Parse key value pairs from secedit output
        policy = {}
        for line in lines:
            if "=" in line:
                key, _, value = line.partition("=")
                policy[key.strip().lower()] = value.strip()

        # LockoutBadCount must be between 1 and 5 (0 = never lockout = fail)
        bad_count = int(policy.get("lockoutbadcount", 0))
        if not bool(1 <= bad_count <= 5):
            return False

        # LockoutDuration must be >= 15 minutes (0 = admin unlock only,
        # which is acceptable but we require >= 15 for automation purposes)
        lockout_duration = int(policy.get("lockoutduration", 0))
        if not bool(lockout_duration >= 15):
            return False

        # ResetLockoutCount (observation window) must be >= 15 minutes
        reset_count = int(policy.get("resetlockoutcount", 0))
        if not bool(reset_count >= 15):
            return False

        return True

    except Exception:
        return False


def logon_attempt_limit_defined_ws() -> bool:
    """
    AC.L2-3.1.8a - Means of Limiting Unsuccessful Logon Attempts is
    Defined (Windows Server)
    """
    try:
        # Check Default Domain Policy lockout settings via Get-ADDefaultDomainPasswordPolicy
        policy_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ADDefaultDomainPasswordPolicy | "
             "Select-Object LockoutThreshold, LockoutDuration, "
             "LockoutObservationWindow | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if policy_result.returncode != 0:
            return False

        policy = json.loads(policy_result.stdout) if policy_result.stdout.strip() else {}
        if not policy:
            return False

        # LockoutThreshold must be between 1 and 5
        threshold = int(policy.get("LockoutThreshold", 0))
        if not bool(1 <= threshold <= 5):
            return False

        # LockoutDuration is returned as an ISO 8601 duration string
        # e.g. "00:15:00" — must be >= 15 minutes
        duration_str = policy.get("LockoutDuration", "00:00:00")
        duration_parts = str(duration_str).split(":")
        if len(duration_parts) >= 2:
            try:
                duration_minutes = (
                    int(duration_parts[0]) * 60 +
                    int(duration_parts[1])
                )
            except ValueError:
                return False
        else:
            return False

        if not bool(duration_minutes >= 15):
            return False

        # LockoutObservationWindow must be >= 15 minutes
        window_str = policy.get("LockoutObservationWindow", "00:00:00")
        window_parts = str(window_str).split(":")
        if len(window_parts) >= 2:
            try:
                window_minutes = (
                    int(window_parts[0]) * 60 +
                    int(window_parts[1])
                )
            except ValueError:
                return False
        else:
            return False

        if not bool(window_minutes >= 15):
            return False

        return True

    except Exception:
        return False


def logon_attempt_limit_ws() -> bool:
    """
    AC.L2-3.1.8b - Defined Means of Limiting Unsuccessful Logon Attempts
    is Implemented (Windows Server)
    Checks that the domain account lockout policy is actively enforced
    with acceptable values and that the local secedit policy on the
    server also reflects the lockout configuration.
    Returns True if both domain and local lockout policies are enforced.
    """
    try:
        # Check domain policy is defined first by reusing the logic
        # from logon_attempt_limit_defined_ws
        domain_policy_ok = logon_attempt_limit_defined_ws()
        if not domain_policy_ok:
            return False

        # Additionally verify local secedit reflects lockout policy
        # to confirm GPO has been applied to this specific server
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'LockoutBadCount|LockoutDuration|"
             "ResetLockoutCount'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode != 0:
            return False

        lines = secedit_result.stdout.strip().splitlines()
        if not lines:
            return False

        policy = {}
        for line in lines:
            if "=" in line:
                key, _, value = line.partition("=")
                policy[key.strip().lower()] = value.strip()

        # Verify local policy reflects domain lockout settings
        bad_count = int(policy.get("lockoutbadcount", 0))
        if not bool(1 <= bad_count <= 5):
            return False

        lockout_duration = int(policy.get("lockoutduration", 0))
        if not bool(lockout_duration >= 15):
            return False

        reset_count = int(policy.get("resetlockoutcount", 0))
        if not bool(reset_count >= 15):
            return False

        # Check RDP lockout is also enforced via registry
        # MaxConnectionTime and related settings for RDP sessions
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\"
             "RemoteDesktop\\WinStations\\RDP-Tcp' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object MaxFailedLogins | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        # RDP lockout is optional but preferred — not a hard fail
        # if registry key does not exist as domain policy covers it
        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            rdp_data = json.loads(rdp_result.stdout)
            max_failed = rdp_data.get("MaxFailedLogins", 0)
            if max_failed == 0:
                # 0 means no RDP-specific limit but domain policy still applies
                pass

        return True

    except Exception:
        return False


def logon_attempt_limit_lx() -> bool:
    """
    AC.L2-3.1.8b - Defined Means of Limiting Unsuccessful Logon Attempts
    is Implemented (Linux/Debian)
    """
    try:
        pam_lockout_active = False
        ssh_limited = False

        # Check pam_faillock configuration
        faillock_result = subprocess.run(
            ["cat", "/etc/security/faillock.conf"],
            capture_output=True, text=True, timeout=10
        )

        if faillock_result.returncode == 0 and faillock_result.stdout.strip():
            conf = faillock_result.stdout.lower()
            active_lines = [
                l.strip() for l in conf.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]

            deny_value = None
            unlock_value = None

            for line in active_lines:
                if line.startswith("deny"):
                    match = re.search(r"deny\s*=\s*(\d+)", line)
                    if match:
                        deny_value = int(match.group(1))
                if line.startswith("unlock_time"):
                    match = re.search(r"unlock_time\s*=\s*(\d+)", line)
                    if match:
                        unlock_value = int(match.group(1))

            if deny_value is not None and unlock_value is not None:
                # deny must be between 1 and 5
                # unlock_time must be >= 900 seconds (15 minutes)
                pam_lockout_active = bool(
                    1 <= deny_value <= 5
                    and unlock_value >= 900
                )

        # Fall back to checking PAM stack directly for pam_faillock
        if not pam_lockout_active:
            pam_result = subprocess.run(
                ["grep", "-r", "pam_faillock", "/etc/pam.d/"],
                capture_output=True, text=True, timeout=30
            )
            if pam_result.returncode == 0 and pam_result.stdout.strip():
                active_pam = [
                    l for l in pam_result.stdout.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                    and "preauth" in l.lower() or "authfail" in l.lower()
                ]

                for line in active_pam:
                    deny_match = re.search(r"deny=(\d+)", line)
                    unlock_match = re.search(r"unlock_time=(\d+)", line)
                    if deny_match and unlock_match:
                        deny_val = int(deny_match.group(1))
                        unlock_val = int(unlock_match.group(1))
                        if 1 <= deny_val <= 5 and unlock_val >= 900:
                            pam_lockout_active = True
                            break

        # Fall back to pam_tally2 if pam_faillock not found
        if not pam_lockout_active:
            tally_result = subprocess.run(
                ["grep", "-r", "pam_tally2", "/etc/pam.d/"],
                capture_output=True, text=True, timeout=30
            )
            if tally_result.returncode == 0 and tally_result.stdout.strip():
                active_tally = [
                    l for l in tally_result.stdout.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                ]
                for line in active_tally:
                    deny_match = re.search(r"deny=(\d+)", line)
                    unlock_match = re.search(r"unlock_time=(\d+)", line)
                    if deny_match and unlock_match:
                        deny_val = int(deny_match.group(1))
                        unlock_val = int(unlock_match.group(1))
                        if 1 <= deny_val <= 5 and unlock_val >= 900:
                            pam_lockout_active = True
                            break

        # Check SSH MaxAuthTries is configured and <= 4
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode == 0:
            output = sshd_result.stdout.lower()
            max_auth = re.search(r"^maxauthtries\s+(\d+)", output, re.MULTILINE)
            if max_auth:
                ssh_limited = bool(int(max_auth.group(1)) <= 4)

        return bool(pam_lockout_active and ssh_limited)

    except Exception:
        return False

# AC.L2-3.1.9

def login_banner_wc() -> bool:
    """
    AC.L2-3.1.9b - Privacy and Security Notices are Displayed (Windows Client)
    """
    try:
        # Check registry keys for logon banner
        banner_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
             "Policies\\System' | "
             "Select-Object LegalNoticeCaption, "
             "LegalNoticeText | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if banner_result.returncode != 0:
            return False

        banner_data = json.loads(banner_result.stdout) if banner_result.stdout.strip() else {}
        if not banner_data:
            return False

        caption = (banner_data.get("LegalNoticeCaption") or "").strip()
        text = (banner_data.get("LegalNoticeText") or "").strip()

        # Both caption and text must be non-empty
        if not caption or not text:
            return False

        # Check banner text contains at least some meaningful content
        # Minimum length of 20 characters to avoid placeholder text
        if len(text) < 20:
            return False

        # Check for common placeholder values that indicate
        # the banner has not been properly configured
        placeholder_values = {
            "insert notice here",
            "banner text",
            "legal notice",
            "enter text here",
            "tbd",
            "todo"
        }
        if text.lower() in placeholder_values or caption.lower() in placeholder_values:
            return False

        return True

    except Exception:
        return False


def login_banner_ws() -> bool:
    """
    AC.L2-3.1.9b - Privacy and Security Notices are Displayed (Windows Server)
    """
    try:
        # Check registry keys for interactive logon banner
        banner_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
             "Policies\\System' | "
             "Select-Object LegalNoticeCaption, "
             "LegalNoticeText | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if banner_result.returncode != 0:
            return False

        banner_data = json.loads(banner_result.stdout) if banner_result.stdout.strip() else {}
        if not banner_data:
            return False

        caption = (banner_data.get("LegalNoticeCaption") or "").strip()
        text = (banner_data.get("LegalNoticeText") or "").strip()

        if not caption or not text:
            return False

        if len(text) < 20:
            return False

        placeholder_values = {
            "insert notice here",
            "banner text",
            "legal notice",
            "enter text here",
            "tbd",
            "todo"
        }
        if text.lower() in placeholder_values or caption.lower() in placeholder_values:
            return False

        # Check GPO is enforcing the banner via the same registry path
        # under HKLM\SOFTWARE\Policies (GPO-managed path)
        gpo_banner_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
             "System' -ErrorAction SilentlyContinue | "
             "Select-Object legalnoticecaption, "
             "legalnoticetext | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        # GPO enforcement is preferred but not required if local policy is set
        gpo_enforced = False
        if gpo_banner_result.returncode == 0 and gpo_banner_result.stdout.strip():
            gpo_data = json.loads(gpo_banner_result.stdout)
            gpo_caption = (gpo_data.get("legalnoticecaption") or "").strip()
            gpo_text = (gpo_data.get("legalnoticetext") or "").strip()
            gpo_enforced = bool(gpo_caption and gpo_text and len(gpo_text) >= 20)

        # Check RDP session banner is configured via registry
        rdp_banner_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Terminal Server\\WinStations\\RDP-Tcp' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object fDisableCam | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        # For RDP we check that NLA is enforced which requires
        # authentication before the session is established
        # ensuring the banner is seen before access is granted
        nla_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Terminal Server\\WinStations\\RDP-Tcp' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object UserAuthentication | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        rdp_configured = False
        if nla_result.returncode == 0 and nla_result.stdout.strip():
            nla_data = json.loads(nla_result.stdout)
            # UserAuthentication 1 = NLA required
            rdp_configured = bool(nla_data.get("UserAuthentication", 0) == 1)

        # Pass if local banner is set and either GPO enforces it
        # or RDP NLA is configured
        return bool(
            caption and text and len(text) >= 20
            and (gpo_enforced or rdp_configured)
        )

    except Exception:
        return False


def login_banner_lx() -> bool:
    """
    AC.L2-3.1.9b - Privacy and Security Notices are Displayed (Linux/Debian)
    """
    try:
        issue_configured = False
        ssh_banner_configured = False

        placeholder_values = {
            "insert notice here",
            "banner text",
            "legal notice",
            "enter text here",
            "tbd",
            "todo",
            "welcome",
            "ubuntu",
            "debian",
            "linux"
        }

        # Check /etc/issue for local console banner
        issue_result = subprocess.run(
            ["cat", "/etc/issue"],
            capture_output=True, text=True, timeout=10
        )
        if issue_result.returncode == 0:
            issue_text = issue_result.stdout.strip()
            # Strip escape sequences like \n \l \s \r commonly
            # found in default /etc/issue files
            clean_text = re.sub(r"\\[a-zA-Z]", "", issue_text).strip()

            if (
                clean_text
                and len(clean_text) >= 20
                and clean_text.lower() not in placeholder_values
                and not any(p in clean_text.lower() for p in placeholder_values)
            ):
                issue_configured = True

        # Check /etc/issue.net for network login banner
        issue_net_result = subprocess.run(
            ["cat", "/etc/issue.net"],
            capture_output=True, text=True, timeout=10
        )
        issue_net_configured = False
        if issue_net_result.returncode == 0:
            net_text = issue_net_result.stdout.strip()
            clean_net = re.sub(r"\\[a-zA-Z]", "", net_text).strip()
            if (
                clean_net
                and len(clean_net) >= 20
                and not any(p in clean_net.lower() for p in placeholder_values)
            ):
                issue_net_configured = True

        # Check SSH Banner directive points to a valid non-empty file
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode == 0:
            output = sshd_result.stdout.lower()
            banner_match = re.search(
                r"^banner\s+(\S+)", output, re.MULTILINE
            )
            if banner_match:
                banner_path = banner_match.group(1).strip()

                # Check the banner file is not "none"
                if banner_path != "none":
                    banner_file_result = subprocess.run(
                        ["cat", banner_path],
                        capture_output=True, text=True, timeout=10
                    )
                    if banner_file_result.returncode == 0:
                        banner_text = banner_file_result.stdout.strip()
                        if (
                            banner_text
                            and len(banner_text) >= 20
                            and not any(
                                p in banner_text.lower()
                                for p in placeholder_values
                            )
                        ):
                            ssh_banner_configured = True

        # Check /etc/motd for post-login notice as additional signal
        motd_result = subprocess.run(
            ["cat", "/etc/motd"],
            capture_output=True, text=True, timeout=10
        )
        motd_configured = False
        if motd_result.returncode == 0:
            motd_text = motd_result.stdout.strip()
            if (
                motd_text
                and len(motd_text) >= 20
                and not any(p in motd_text.lower() for p in placeholder_values)
            ):
                motd_configured = True

        # Require at minimum /etc/issue AND SSH banner to be configured
        # /etc/issue.net and /etc/motd are additional signals but not required
        # for a pass since some environments may not use all four
        if not issue_configured and not issue_net_configured:
            return False

        if not ssh_banner_configured:
            return False

        return bool(
            (issue_configured or issue_net_configured)
            and ssh_banner_configured
        )

    except Exception:
        return False

# AC.L2-3.1.10

def session_lock_wc() -> bool:
    """
    AC.L2-3.1.10b - Session Lock is Initiated After Defined Period of
    Inactivity (Windows Client)
    """
    try:
        # Check screen saver settings via registry for current user policy
        # These keys are set via Group Policy
        screensaver_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKCU:\\Software\\Policies\\Microsoft\\Windows\\"
             "Control Panel\\Desktop' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object ScreenSaveActive, ScreenSaveTimeOut, "
             "ScreenSaverIsSecure | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        ss_data = {}
        if screensaver_result.returncode == 0 and screensaver_result.stdout.strip():
            ss_data = json.loads(screensaver_result.stdout)

        # Fall back to HKCU desktop settings if GPO key not present
        if not ss_data:
            fallback_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKCU:\\Control Panel\\Desktop' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object ScreenSaveActive, ScreenSaveTimeOut, "
                 "ScreenSaverIsSecure | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if fallback_result.returncode == 0 and fallback_result.stdout.strip():
                ss_data = json.loads(fallback_result.stdout)

        if not ss_data:
            return False

        # ScreenSaveActive must be "1" or 1
        active = str(ss_data.get("ScreenSaveActive", "0")).strip()
        if active != "1":
            return False

        # ScreenSaveTimeOut must be <= 900 seconds (15 minutes)
        try:
            timeout = int(ss_data.get("ScreenSaveTimeOut", 0))
        except (ValueError, TypeError):
            return False

        if not bool(1 <= timeout <= 900):
            return False

        # ScreenSaverIsSecure must be "1" (password required on resume)
        secure = str(ss_data.get("ScreenSaverIsSecure", "0")).strip()
        if secure != "1":
            return False

        return True

    except Exception:
        return False


def pattern_hiding_wc() -> bool:
    """
    AC.L2-3.1.10c - Previously Visible Information is Concealed via
    Pattern-Hiding Display (Windows Client)
    """
    try:
        # Get the configured screen saver executable
        ss_exe_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKCU:\\Software\\Policies\\Microsoft\\Windows\\"
             "Control Panel\\Desktop' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object SCRNSAVE.EXE | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        ss_exe = ""
        if ss_exe_result.returncode == 0 and ss_exe_result.stdout.strip():
            exe_data = json.loads(ss_exe_result.stdout)
            ss_exe = (exe_data.get("SCRNSAVE.EXE") or "").lower().strip()

        # Fall back to HKCU desktop settings
        if not ss_exe:
            fallback_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKCU:\\Control Panel\\Desktop' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object 'SCRNSAVE.EXE' | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if fallback_result.returncode == 0 and fallback_result.stdout.strip():
                fallback_data = json.loads(fallback_result.stdout)
                ss_exe = (fallback_data.get("SCRNSAVE.EXE") or "").lower().strip()

        if not ss_exe:
            return False

        # Acceptable pattern-hiding screen savers
        # scrnsave.scr = blank screen (most secure)
        # logon.scr = secure logon screen
        # Mystify, Ribbons, Bubbles are acceptable as they hide content
        acceptable_screensavers = {
            "scrnsave.scr",
            "logon.scr",
            "mystify.scr",
            "ribbons.scr",
            "bubbles.scr",
            "sstext3d.scr"
        }

        # Unacceptable screen savers that expose previously visible content
        unacceptable_screensavers = {
            "photos.scr",         # Photo slideshow exposes images
            "none",               # No screen saver
            ""                    # Empty/not configured
        }

        ss_filename = ss_exe.split("\\")[-1].lower()

        if ss_filename in unacceptable_screensavers:
            return False

        # If not explicitly in acceptable list, check it is not
        # a photo or video-based screen saver
        if ss_filename not in acceptable_screensavers:
            if any(kw in ss_filename for kw in ["photo", "video", "slide"]):
                return False

        return True

    except Exception:
        return False


def session_lock_ws() -> bool:
    """
    AC.L2-3.1.10b - Session Lock is Initiated After Defined Period of
    """
    try:
        local_lock_ok = False
        rdp_lock_ok = False

        # Check screen saver settings via GPO registry path
        screensaver_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKCU:\\Software\\Policies\\Microsoft\\Windows\\"
             "Control Panel\\Desktop' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object ScreenSaveActive, ScreenSaveTimeOut, "
             "ScreenSaverIsSecure | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        ss_data = {}
        if screensaver_result.returncode == 0 and screensaver_result.stdout.strip():
            ss_data = json.loads(screensaver_result.stdout)

        if not ss_data:
            fallback_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKCU:\\Control Panel\\Desktop' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object ScreenSaveActive, ScreenSaveTimeOut, "
                 "ScreenSaverIsSecure | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if fallback_result.returncode == 0 and fallback_result.stdout.strip():
                ss_data = json.loads(fallback_result.stdout)

        if ss_data:
            active = str(ss_data.get("ScreenSaveActive", "0")).strip()
            try:
                timeout = int(ss_data.get("ScreenSaveTimeOut", 0))
            except (ValueError, TypeError):
                timeout = 0
            secure = str(ss_data.get("ScreenSaverIsSecure", "0")).strip()
            local_lock_ok = bool(
                active == "1"
                and 1 <= timeout <= 900
                and secure == "1"
            )

        # Check RDP idle session timeout via Group Policy registry
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\"
             "Terminal Services' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object MaxIdleTime, MaxDisconnectionTime, "
             "fResetBroken | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            rdp_data = json.loads(rdp_result.stdout)

            # MaxIdleTime is in milliseconds, must be <= 900000 (15 minutes)
            max_idle = rdp_data.get("MaxIdleTime", 0)
            try:
                max_idle_ms = int(max_idle)
            except (ValueError, TypeError):
                max_idle_ms = 0

            # fResetBroken must be 1 to disconnect/end session on timeout
            reset_broken = rdp_data.get("fResetBroken", 0)

            rdp_lock_ok = bool(
                1 <= max_idle_ms <= 900000
                and reset_broken == 1
            )

        return bool(local_lock_ok and rdp_lock_ok)

    except Exception:
        return False


def pattern_hiding_ws() -> bool:
    """
    AC.L2-3.1.10c - Previously Visible Information is Concealed via
    Pattern-Hiding Display (Windows Server)
    """
    try:
        local_pattern_ok = False
        rdp_pattern_ok = False

        # Check screen saver executable is pattern-hiding
        ss_exe_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKCU:\\Software\\Policies\\Microsoft\\Windows\\"
             "Control Panel\\Desktop' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object 'SCRNSAVE.EXE' | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        ss_exe = ""
        if ss_exe_result.returncode == 0 and ss_exe_result.stdout.strip():
            exe_data = json.loads(ss_exe_result.stdout)
            ss_exe = (exe_data.get("SCRNSAVE.EXE") or "").lower().strip()

        if not ss_exe:
            fallback_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKCU:\\Control Panel\\Desktop' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object 'SCRNSAVE.EXE' | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if fallback_result.returncode == 0 and fallback_result.stdout.strip():
                fallback_data = json.loads(fallback_result.stdout)
                ss_exe = (fallback_data.get("SCRNSAVE.EXE") or "").lower().strip()

        acceptable_screensavers = {
            "scrnsave.scr",
            "logon.scr",
            "mystify.scr",
            "ribbons.scr",
            "bubbles.scr",
            "sstext3d.scr"
        }

        unacceptable_screensavers = {"photos.scr", "none", ""}

        if ss_exe:
            ss_filename = ss_exe.split("\\")[-1].lower()
            if ss_filename not in unacceptable_screensavers:
                if ss_filename in acceptable_screensavers or not any(
                    kw in ss_filename for kw in ["photo", "video", "slide"]
                ):
                    local_pattern_ok = True

        # Check RDP is configured to show logon screen on reconnect
        # DisableAutoReconnect and fPromptForPassword enforce
        # that reconnecting sessions must re-authenticate
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\"
             "Terminal Services' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object fPromptForPassword, "
             "fDisableAutoReconnect | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            rdp_data = json.loads(rdp_result.stdout)
            # fPromptForPassword = 1 means password required on reconnect
            prompt = rdp_data.get("fPromptForPassword", 0)
            rdp_pattern_ok = bool(prompt == 1)

        return bool(local_pattern_ok and rdp_pattern_ok)

    except Exception:
        return False


def session_lock_lx() -> bool:
    """
    AC.L2-3.1.10b - Session Lock is Initiated After Defined Period of
    Inactivity (Linux/Debian)
    """
    try:
        ssh_timeout_ok = False
        shell_timeout_ok = False

        # Check SSH ClientAliveInterval and ClientAliveCountMax
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode == 0:
            output = sshd_result.stdout.lower()

            interval_match = re.search(
                r"^clientaliveinterval\s+(\d+)",
                output, re.MULTILINE
            )
            count_match = re.search(
                r"^clientalivecountmax\s+(\d+)",
                output, re.MULTILINE
            )

            if interval_match and count_match:
                interval = int(interval_match.group(1))
                count = int(count_match.group(1))

                # Total idle timeout = interval * count
                # Must be > 0 and <= 900 seconds (15 minutes)
                total_timeout = interval * count
                ssh_timeout_ok = bool(
                    interval > 0
                    and count >= 1
                    and 1 <= total_timeout <= 900
                )

        # Check TMOUT is set system-wide in profile files
        tmout_files = [
            "/etc/profile",
            "/etc/profile.d/tmout.sh",
            "/etc/bashrc",
            "/etc/bash.bashrc"
        ]

        for filepath in tmout_files:
            cat_result = subprocess.run(
                ["cat", filepath],
                capture_output=True, text=True, timeout=10
            )
            if cat_result.returncode != 0:
                continue

            active_lines = [
                l.strip() for l in cat_result.stdout.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]

            for line in active_lines:
                tmout_match = re.search(
                    r"TMOUT\s*=\s*(\d+)", line
                )
                if tmout_match:
                    tmout_val = int(tmout_match.group(1))
                    # TMOUT must be > 0 and <= 900 seconds
                    if 1 <= tmout_val <= 900:
                        shell_timeout_ok = True
                        break

            if shell_timeout_ok:
                break

        return bool(ssh_timeout_ok and shell_timeout_ok)

    except Exception:
        return False


def pattern_hiding_lx() -> bool:
    """
    AC.L2-3.1.10c - Previously Visible Information is Concealed via
    Pattern-Hiding Display (Linux/Debian)
    """
    try:
        tmout_readonly = False
        ssh_pattern_ok = False
        gui_blank_ok = False

        # Check TMOUT is exported as readonly to prevent override
        tmout_files = [
            "/etc/profile",
            "/etc/profile.d/tmout.sh",
            "/etc/bashrc",
            "/etc/bash.bashrc"
        ]

        for filepath in tmout_files:
            cat_result = subprocess.run(
                ["cat", filepath],
                capture_output=True, text=True, timeout=10
            )
            if cat_result.returncode != 0:
                continue

            active_lines = [
                l.strip() for l in cat_result.stdout.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]

            for line in active_lines:
                # Check for readonly TMOUT or typeset -r TMOUT
                if re.search(
                    r"(readonly\s+TMOUT|typeset\s+-r\s+TMOUT|"
                    r"declare\s+-r\s+TMOUT)",
                    line
                ):
                    tmout_readonly = True
                    break

            if tmout_readonly:
                break

        # Check SSH does not permit environment variable overrides
        # that could allow users to reset TMOUT via SSH session
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode == 0:
            output = sshd_result.stdout.lower()

            # PermitUserEnvironment must be no to prevent
            # users from overriding TMOUT via ~/.ssh/environment
            permit_env_match = re.search(
                r"^permituserenvironment\s+(\S+)",
                output, re.MULTILINE
            )
            if permit_env_match:
                ssh_pattern_ok = bool(
                    permit_env_match.group(1).lower() == "no"
                )
            else:
                # Default is no so absence of the key is acceptable
                ssh_pattern_ok = True

        # Check GUI screen lock blanks display if a desktop environment
        # is present — check for gsettings (GNOME) or xset (X11)
        gsettings_result = subprocess.run(
            ["gsettings", "get",
             "org.gnome.desktop.screensaver", "picture-opacity"],
            capture_output=True, text=True, timeout=10
        )

        if gsettings_result.returncode == 0:
            # Check GNOME screensaver is set to blank screen
            blank_result = subprocess.run(
                ["gsettings", "get",
                 "org.gnome.desktop.screensaver", "picture-uri"],
                capture_output=True, text=True, timeout=10
            )
            if blank_result.returncode == 0:
                picture_uri = blank_result.stdout.strip().lower()
                # Empty URI or "none" indicates blank screen
                gui_blank_ok = bool(
                    picture_uri in {"''", '""', "", "none", "'none'"}
                )

            # Also check idle activation is enabled
            idle_result = subprocess.run(
                ["gsettings", "get",
                 "org.gnome.desktop.screensaver", "idle-activation-enabled"],
                capture_output=True, text=True, timeout=10
            )
            if idle_result.returncode == 0:
                idle_enabled = idle_result.stdout.strip().lower()
                if idle_enabled != "true":
                    gui_blank_ok = False
        else:
            # No GUI detected — terminal-only systems pass this check
            # since TMOUT readonly handles pattern hiding for CLI sessions
            gui_blank_ok = True

        return bool(tmout_readonly and ssh_pattern_ok and gui_blank_ok)

    except Exception:
        return False


def session_termination_wc() -> bool:
    """
    AC.L2-3.1.11b - User Session is Automatically Terminated After Defined
    Conditions (Windows Client)
    """
    try:
        mechanisms_active = 0

        # Check machine inactivity limit via Group Policy registry
        # This setting locks/terminates the session at the OS level
        # regardless of user-level screen saver settings
        inactivity_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
             "Policies\\System' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object InactivityTimeoutSecs | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if inactivity_result.returncode == 0 and inactivity_result.stdout.strip():
            inactivity_data = json.loads(inactivity_result.stdout)
            timeout_secs = inactivity_data.get("InactivityTimeoutSecs", 0)
            try:
                timeout_secs = int(timeout_secs)
            except (ValueError, TypeError):
                timeout_secs = 0
            # Must be > 0 and <= 900 seconds (15 minutes)
            if bool(1 <= timeout_secs <= 900):
                mechanisms_active += 1

        # Check screen saver is configured with password and timeout
        # Reuse registry check logic from session_lock_wc
        screensaver_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKCU:\\Software\\Policies\\Microsoft\\Windows\\"
             "Control Panel\\Desktop' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object ScreenSaveActive, ScreenSaveTimeOut, "
             "ScreenSaverIsSecure | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        ss_data = {}
        if screensaver_result.returncode == 0 and screensaver_result.stdout.strip():
            ss_data = json.loads(screensaver_result.stdout)

        if not ss_data:
            fallback_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKCU:\\Control Panel\\Desktop' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object ScreenSaveActive, ScreenSaveTimeOut, "
                 "ScreenSaverIsSecure | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if fallback_result.returncode == 0 and fallback_result.stdout.strip():
                ss_data = json.loads(fallback_result.stdout)

        if ss_data:
            active = str(ss_data.get("ScreenSaveActive", "0")).strip()
            try:
                ss_timeout = int(ss_data.get("ScreenSaveTimeOut", 0))
            except (ValueError, TypeError):
                ss_timeout = 0
            secure = str(ss_data.get("ScreenSaverIsSecure", "0")).strip()
            if bool(active == "1" and 1 <= ss_timeout <= 900 and secure == "1"):
                mechanisms_active += 1

        # Check force logoff when logon hours expire via secedit
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet; "
             "Get-Content $env:TEMP\\secpol.cfg | "
             "Select-String 'ForceLogoffWhenHourExpire'"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode == 0 and secedit_result.stdout.strip():
            logoff_lines = secedit_result.stdout.strip().splitlines()
            for line in logoff_lines:
                if "=" in line:
                    value = line.split("=", 1)[1].strip()
                    # ForceLogoffWhenHourExpire = 1 means force logoff
                    if value == "1":
                        mechanisms_active += 1
                        break

        # Require at least 2 of 3 mechanisms to be active
        return bool(mechanisms_active >= 2)

    except Exception:
        return False


def session_termination_ws() -> bool:
    """
    AC.L2-3.1.11b - User Session is Automatically Terminated After Defined
    Conditions (Windows Server)
    """
    try:
        rdp_termination_ok = False
        inactivity_limit_ok = False
        session_time_limit_ok = False

        # Check RDP idle session termination settings via GP registry
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\"
             "Terminal Services' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object MaxIdleTime, MaxDisconnectionTime, "
             "MaxConnectionTime, fResetBroken | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            rdp_data = json.loads(rdp_result.stdout)

            # MaxIdleTime in milliseconds must be > 0 and <= 900000 (15 min)
            try:
                max_idle = int(rdp_data.get("MaxIdleTime", 0))
            except (ValueError, TypeError):
                max_idle = 0

            # fResetBroken = 1 means terminate rather than just disconnect
            reset_broken = rdp_data.get("fResetBroken", 0)

            rdp_termination_ok = bool(
                1 <= max_idle <= 900000
                and reset_broken == 1
            )

            # MaxConnectionTime limits total session duration
            # Must be configured (> 0) to enforce session time limits
            try:
                max_conn = int(rdp_data.get("MaxConnectionTime", 0))
            except (ValueError, TypeError):
                max_conn = 0

            # MaxDisconnectionTime limits how long a disconnected
            # session can persist before being terminated
            try:
                max_disconn = int(rdp_data.get("MaxDisconnectionTime", 0))
            except (ValueError, TypeError):
                max_disconn = 0

            session_time_limit_ok = bool(
                max_conn > 0 or max_disconn > 0
            )

        # Check machine inactivity limit via Group Policy registry
        inactivity_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
             "Policies\\System' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object InactivityTimeoutSecs | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if inactivity_result.returncode == 0 and inactivity_result.stdout.strip():
            inactivity_data = json.loads(inactivity_result.stdout)
            try:
                timeout_secs = int(
                    inactivity_data.get("InactivityTimeoutSecs", 0)
                )
            except (ValueError, TypeError):
                timeout_secs = 0
            inactivity_limit_ok = bool(1 <= timeout_secs <= 900)

        return bool(
            rdp_termination_ok
            and inactivity_limit_ok
            and session_time_limit_ok
        )

    except Exception:
        return False


def session_termination_lx() -> bool:
    """
    AC.L2-3.1.11b - User Session is Automatically Terminated After Defined
    """
    try:
        ssh_termination_ok = False
        tmout_readonly_ok = False
        pam_limits_ok = False

        # Check SSH ClientAlive settings terminate idle sessions
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode == 0:
            output = sshd_result.stdout.lower()

            interval_match = re.search(
                r"^clientaliveinterval\s+(\d+)",
                output, re.MULTILINE
            )
            count_match = re.search(
                r"^clientalivecountmax\s+(\d+)",
                output, re.MULTILINE
            )

            if interval_match and count_match:
                interval = int(interval_match.group(1))
                count = int(count_match.group(1))
                total_timeout = interval * count

                # Total timeout must be > 0 and <= 900 seconds
                # CountMax must be low (1-3) to ensure quick termination
                # after missed keepalives
                ssh_termination_ok = bool(
                    interval > 0
                    and 1 <= count <= 3
                    and 1 <= total_timeout <= 900
                )

        # Check TMOUT is set as readonly in system profile files
        tmout_files = [
            "/etc/profile",
            "/etc/profile.d/tmout.sh",
            "/etc/bashrc",
            "/etc/bash.bashrc"
        ]

        for filepath in tmout_files:
            cat_result = subprocess.run(
                ["cat", filepath],
                capture_output=True, text=True, timeout=10
            )
            if cat_result.returncode != 0:
                continue

            active_lines = [
                l.strip() for l in cat_result.stdout.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]

            has_tmout = False
            has_readonly = False

            for line in active_lines:
                tmout_match = re.search(r"TMOUT\s*=\s*(\d+)", line)
                if tmout_match:
                    tmout_val = int(tmout_match.group(1))
                    if 1 <= tmout_val <= 900:
                        has_tmout = True

                if re.search(
                    r"(readonly\s+TMOUT|typeset\s+-r\s+TMOUT|"
                    r"declare\s+-r\s+TMOUT)",
                    line
                ):
                    has_readonly = True

            if has_tmout and has_readonly:
                tmout_readonly_ok = True
                break

        # Check PAM limits are configured for session control
        # Check /etc/security/limits.conf for session restrictions
        limits_result = subprocess.run(
            ["grep", "-v", "^#", "/etc/security/limits.conf"],
            capture_output=True, text=True, timeout=10
        )

        if limits_result.returncode == 0 and limits_result.stdout.strip():
            active_limits = [
                l.strip() for l in limits_result.stdout.splitlines()
                if l.strip()
            ]
            # Check for maxlogins or maxsyslogins limits
            session_limits = [
                l for l in active_limits
                if any(
                    kw in l.lower()
                    for kw in ["maxlogins", "maxsyslogins", "maxproc"]
                )
            ]
            pam_limits_ok = bool(session_limits)

        # Fall back to checking loginctl for active session limits
        if not pam_limits_ok:
            loginctl_result = subprocess.run(
                ["loginctl", "show-session"],
                capture_output=True, text=True, timeout=10
            )
            if loginctl_result.returncode == 0:
                output = loginctl_result.stdout.lower()
                # Check IdleHint or IdleAction is configured
                if re.search(r"(idleaction|idlehint|stopidlesessiontimeout)", output):
                    pam_limits_ok = True

        # Fall back to checking systemd-logind.conf for idle action
        if not pam_limits_ok:
            logind_result = subprocess.run(
                ["cat", "/etc/systemd/logind.conf"],
                capture_output=True, text=True, timeout=10
            )
            if logind_result.returncode == 0:
                active_lines = [
                    l.strip() for l in logind_result.stdout.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                ]
                for line in active_lines:
                    if re.search(
                        r"(StopIdleSessionSec|IdleAction|KillUserProcesses)",
                        line
                    ):
                        # StopIdleSessionSec must be configured and non-zero
                        if "=" in line:
                            value = line.split("=", 1)[1].strip()
                            if value.lower() not in {"0", "no", "infinity", ""}:
                                pam_limits_ok = True
                                break

        return bool(
            ssh_termination_ok
            and tmout_readonly_ok
            and pam_limits_ok
        )

    except Exception:
        return False

def remote_access_control_wc() -> bool:
    """
    AC.L2-3.1.12c - Remote Access Sessions are Controlled (Windows Client)
    """
    try:
        rdp_group_restricted = False
        nla_enforced = False
        firewall_restricted = False

        # Check RDP is restricted to named groups via Remote Desktop Users
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Remote Desktop Users' | "
             "Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            members = json.loads(rdp_result.stdout)
            if isinstance(members, dict):
                members = [members]
            if not members:
                rdp_group_restricted = False
            else:
                broad_principals = {"everyone", "authenticated users", "users"}
                flagged = [
                    m for m in members
                    if (m.get("Name") or "").lower().split("\\")[-1]
                    in broad_principals
                ]
                rdp_group_restricted = bool(not flagged)
        else:
            # Empty Remote Desktop Users group means RDP access is
            # controlled at a higher level (e.g. Administrators only)
            rdp_group_restricted = True

        # Check NLA is enforced via registry
        nla_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Terminal Server\\WinStations\\RDP-Tcp' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object UserAuthentication | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if nla_result.returncode == 0 and nla_result.stdout.strip():
            nla_data = json.loads(nla_result.stdout)
            nla_enforced = bool(nla_data.get("UserAuthentication", 0) == 1)

        # Check Windows Defender Firewall restricts RDP (port 3389)
        # to specific source addresses
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -DisplayName '*Remote Desktop*' "
             "-Direction Inbound -Action Allow -Enabled True | "
             "Select-Object DisplayName, "
             "@{N='RemoteAddress';E={"
             "(Get-NetFirewallAddressFilter "
             "-AssociatedNetFirewallRule $_).RemoteAddress}} | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if rules:
                # Fail if any RDP rule allows from Any
                open_rules = [
                    r for r in rules
                    if str(r.get("RemoteAddress") or "").lower()
                    in {"any", "*", "0.0.0.0/0"}
                ]
                firewall_restricted = bool(not open_rules)
            else:
                # No specific RDP firewall rules found
                firewall_restricted = False

        return bool(rdp_group_restricted and nla_enforced and firewall_restricted)

    except Exception:
        return False


def remote_access_monitoring_wc() -> bool:
    """
    AC.L2-3.1.12d - Remote Access Sessions are Monitored (Windows Client)
    """
    try:
        required_categories = {
            "logon",
            "logoff",
            "account logon",
            "other logon/logoff events"
        }

        audit_result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=30
        )
        if audit_result.returncode != 0:
            return False

        output = audit_result.stdout.lower()
        lines = output.strip().splitlines()

        category_settings = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                setting = parts[-1].lower()
                name = " ".join(parts[:-1]).strip()
                category_settings[name] = setting

        missing = []
        for category in required_categories:
            matched = [
                k for k in category_settings
                if category in k
            ]
            if not matched:
                missing.append(category)
                continue

            audited = [
                k for k in matched
                if category_settings[k] in {
                    "success", "failure", "success and failure"
                }
            ]
            if not audited:
                missing.append(category)

        return bool(not missing)

    except Exception:
        return False


def remote_access_control_ws() -> bool:
    """
    AC.L2-3.1.12c - Remote Access Sessions are Controlled (Windows Server)

    """
    try:
        rdp_group_restricted = False
        nla_enforced = False
        firewall_restricted = False
        session_limits_ok = False

        broad_principals = {"everyone", "authenticated users", "users"}

        # Check Remote Desktop Users group is scoped to named accounts
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group 'Remote Desktop Users' | "
             "Select-Object Name | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            members = json.loads(rdp_result.stdout)
            if isinstance(members, dict):
                members = [members]
            flagged = [
                m for m in members
                if (m.get("Name") or "").lower().split("\\")[-1]
                in broad_principals
            ]
            rdp_group_restricted = bool(not flagged)
        else:
            rdp_group_restricted = True

        # Check NLA is enforced
        nla_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Terminal Server\\WinStations\\RDP-Tcp' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object UserAuthentication | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if nla_result.returncode == 0 and nla_result.stdout.strip():
            nla_data = json.loads(nla_result.stdout)
            nla_enforced = bool(nla_data.get("UserAuthentication", 0) == 1)

        # Check Windows Defender Firewall restricts RDP port 3389
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -DisplayName '*Remote Desktop*' "
             "-Direction Inbound -Action Allow -Enabled True | "
             "Select-Object DisplayName, "
             "@{N='RemoteAddress';E={"
             "(Get-NetFirewallAddressFilter "
             "-AssociatedNetFirewallRule $_).RemoteAddress}} | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if rules:
                open_rules = [
                    r for r in rules
                    if str(r.get("RemoteAddress") or "").lower()
                    in {"any", "*", "0.0.0.0/0"}
                ]
                firewall_restricted = bool(not open_rules)

        # Check RDP session time limits via GP registry
        session_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\"
             "Terminal Services' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object MaxIdleTime, MaxConnectionTime, "
             "MaxDisconnectionTime, fResetBroken | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if session_result.returncode == 0 and session_result.stdout.strip():
            session_data = json.loads(session_result.stdout)
            try:
                max_idle = int(session_data.get("MaxIdleTime", 0))
            except (ValueError, TypeError):
                max_idle = 0
            reset_broken = session_data.get("fResetBroken", 0)
            session_limits_ok = bool(
                1 <= max_idle <= 900000
                and reset_broken == 1
            )

        return bool(
            rdp_group_restricted
            and nla_enforced
            and firewall_restricted
            and session_limits_ok
        )

    except Exception:
        return False


def remote_access_monitoring_ws() -> bool:
    """
    AC.L2-3.1.12d - Remote Access Sessions are Monitored (Windows Server)
    """
    try:
        required_categories = {
            "logon",
            "logoff",
            "account logon",
            "other logon/logoff events",
            "special logon",
            "directory service access"
        }

        audit_result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=30
        )
        if audit_result.returncode != 0:
            return False

        output = audit_result.stdout.lower()
        lines = output.strip().splitlines()

        category_settings = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                setting = parts[-1].lower()
                name = " ".join(parts[:-1]).strip()
                category_settings[name] = setting

        missing = []
        for category in required_categories:
            matched = [
                k for k in category_settings
                if category in k
            ]
            if not matched:
                missing.append(category)
                continue

            audited = [
                k for k in matched
                if category_settings[k] in {
                    "success", "failure", "success and failure"
                }
            ]
            if not audited:
                missing.append(category)

        if missing:
            return False

        # Check Security log size is at least 128MB
        log_result = subprocess.run(
            ["powershell", "-Command",
             "Get-WinEvent -ListLog Security | "
             "Select-Object MaximumSizeInBytes | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if log_result.returncode == 0 and log_result.stdout.strip():
            log_data = json.loads(log_result.stdout)
            max_size = log_data.get("MaximumSizeInBytes", 0)
            if int(max_size) < 134217728:
                return False

        return True

    except Exception:
        return False


def remote_access_control_lx() -> bool:
    """
    AC.L2-3.1.12c - Remote Access Sessions are Controlled (Linux/Debian)
    """
    try:
        user_restricted = False
        root_disabled = False
        key_auth_enforced = False
        firewall_restricted = False

        # Check sshd_config for access controls
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode != 0:
            return False

        output = sshd_result.stdout.lower()

        # Check AllowUsers or AllowGroups is configured
        has_allowusers = re.search(
            r"^allowusers\s+\S+", output, re.MULTILINE
        )
        has_allowgroups = re.search(
            r"^allowgroups\s+\S+", output, re.MULTILINE
        )
        user_restricted = bool(has_allowusers or has_allowgroups)

        # Check PermitRootLogin is no or prohibit-password
        root_match = re.search(
            r"^permitrootlogin\s+(\S+)", output, re.MULTILINE
        )
        if root_match:
            root_disabled = bool(
                root_match.group(1).lower()
                in {"no", "prohibit-password"}
            )

        # Check PasswordAuthentication is no (key-based auth enforced)
        passwd_match = re.search(
            r"^passwordauthentication\s+(\S+)", output, re.MULTILINE
        )
        if passwd_match:
            key_auth_enforced = bool(
                passwd_match.group(1).lower() == "no"
            )

        # Check PubkeyAuthentication is yes
        pubkey_match = re.search(
            r"^pubkeyauthentication\s+(\S+)", output, re.MULTILINE
        )
        pubkey_enabled = bool(
            pubkey_match and pubkey_match.group(1).lower() == "yes"
        )
        key_auth_enforced = bool(key_auth_enforced and pubkey_enabled)

        # Check firewall restricts SSH (port 22) to specific sources
        for cmd in [
            ["iptables", "-L", "INPUT", "-n"],
            ["nft", "list", "ruleset"],
            ["firewall-cmd", "--list-all"]
        ]:
            fw_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if fw_result.returncode == 0 and fw_result.stdout.strip():
                output_fw = fw_result.stdout.lower()
                # Check SSH port is referenced in firewall rules
                if re.search(r"(dpt:22|port\s+22|ssh)", output_fw):
                    # Check it is not open to all sources
                    if not re.search(
                        r"(0\.0\.0\.0/0.*dpt:22|"
                        r"accept.*ssh.*anywhere)",
                        output_fw
                    ):
                        firewall_restricted = True
                        break

        return bool(
            user_restricted
            and root_disabled
            and key_auth_enforced
            and firewall_restricted
        )

    except Exception:
        return False


def remote_access_monitoring_lx() -> bool:
    """
    AC.L2-3.1.12d - Remote Access Sessions are Monitored (Linux/Debian)
    """
    try:
        auditd_monitoring_ok = False
        auth_log_ok = False
        pam_logging_ok = False

        # Check auditd is active and has SSH-related rules
        auditd_result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True, text=True, timeout=10
        )
        if auditd_result.returncode == 0 and \
                auditd_result.stdout.strip().lower() == "active":

            rules_result = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True, text=True, timeout=10
            )
            if rules_result.returncode == 0:
                rules = rules_result.stdout.lower()
                if "no rules" not in rules and rules.strip():
                    # Check for rules watching SSH binary or auth events
                    has_ssh_rules = bool(
                        re.search(
                            r"(\/usr\/sbin\/sshd|\/usr\/bin\/ssh"
                            r"|\/etc\/ssh|execve)",
                            rules
                        )
                    )
                    # Check for rules watching auth-related files
                    has_auth_rules = bool(
                        re.search(
                            r"(\/etc\/passwd|\/etc\/shadow"
                            r"|\/var\/log\/auth)",
                            rules
                        )
                    )
                    auditd_monitoring_ok = bool(
                        has_ssh_rules or has_auth_rules
                    )

        # Check auth log exists and is non-empty
        # Debian/Ubuntu uses /var/log/auth.log
        # RHEL/CentOS uses /var/log/secure
        auth_log_paths = [
            "/var/log/auth.log",
            "/var/log/secure"
        ]
        for log_path in auth_log_paths:
            stat_result = subprocess.run(
                ["stat", "-c", "%s", log_path],
                capture_output=True, text=True, timeout=10
            )
            if stat_result.returncode == 0:
                try:
                    log_size = int(stat_result.stdout.strip())
                    if log_size > 0:
                        # Check log contains recent SSH entries
                        grep_result = subprocess.run(
                            ["grep", "-c", "sshd", log_path],
                            capture_output=True, text=True, timeout=10
                        )
                        if grep_result.returncode == 0:
                            try:
                                ssh_entries = int(
                                    grep_result.stdout.strip()
                                )
                                auth_log_ok = bool(ssh_entries > 0)
                            except ValueError:
                                auth_log_ok = False
                        break
                except ValueError:
                    continue

        # Check PAM session logging is configured
        # Look for pam_unix or pam_loginuid in PAM session stack
        pam_result = subprocess.run(
            ["grep", "-r",
             "session.*pam_unix\\|session.*pam_loginuid",
             "/etc/pam.d/"],
            capture_output=True, text=True, timeout=30
        )
        if pam_result.returncode == 0 and pam_result.stdout.strip():
            active_pam = [
                l for l in pam_result.stdout.splitlines()
                if l.strip() and not l.strip().startswith("#")
                and "session" in l.lower()
            ]
            pam_logging_ok = bool(active_pam)

        # Also check rsyslog or syslog is configured to capture auth
        if not pam_logging_ok:
            syslog_result = subprocess.run(
                ["grep", "-r", "auth", "/etc/rsyslog.conf",
                 "/etc/rsyslog.d/"],
                capture_output=True, text=True, timeout=10
            )
            if syslog_result.returncode == 0 and \
                    syslog_result.stdout.strip():
                active_syslog = [
                    l for l in syslog_result.stdout.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                ]
                pam_logging_ok = bool(active_syslog)

        return bool(
            auditd_monitoring_ok
            and auth_log_ok
            and pam_logging_ok
        )

    except Exception:
        return False

def remote_crypto_wc() -> bool:
    """
    AC.L2-3.1.13b - Cryptographic Mechanisms for Remote Access Sessions
    are Implemented (Windows Client)
    """
    try:
        rdp_crypto_ok = False
        fips_enabled = False
        weak_tls_disabled = False

        # Check RDP NLA and encryption level
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Terminal Server\\WinStations\\RDP-Tcp' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object UserAuthentication, "
             "SecurityLayer, MinEncryptionLevel | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            rdp_data = json.loads(rdp_result.stdout)
            # UserAuthentication = 1 means NLA enforced
            nla = bool(rdp_data.get("UserAuthentication", 0) == 1)
            # SecurityLayer = 2 means TLS (SSL) required
            # SecurityLayer = 1 means negotiate (acceptable)
            # SecurityLayer = 0 means RDP security (fail)
            security_layer = rdp_data.get("SecurityLayer", 0)
            tls_required = bool(security_layer in {1, 2})
            # MinEncryptionLevel = 3 means high (128-bit) encryption
            # MinEncryptionLevel = 4 means FIPS compliant
            min_enc = rdp_data.get("MinEncryptionLevel", 0)
            enc_strong = bool(min_enc in {3, 4})
            rdp_crypto_ok = bool(nla and tls_required and enc_strong)

        # Check FIPS mode is enabled via registry
        fips_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Lsa\\FipsAlgorithmPolicy' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fips_result.returncode == 0 and fips_result.stdout.strip():
            fips_data = json.loads(fips_result.stdout)
            fips_enabled = bool(fips_data.get("Enabled", 0) == 1)

        # Check weak TLS/SSL versions are disabled via Schannel registry
        weak_protocols = {
            "SSL 2.0": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Client",
            "SSL 3.0": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client",
            "TLS 1.0": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client",
            "TLS 1.1": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client"
        }

        all_weak_disabled = True
        for protocol, reg_path in weak_protocols.items():
            proto_result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-ItemProperty -Path '{reg_path}' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object Enabled, DisabledByDefault | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if proto_result.returncode == 0 and proto_result.stdout.strip():
                proto_data = json.loads(proto_result.stdout)
                enabled = proto_data.get("Enabled", 1)
                disabled_by_default = proto_data.get("DisabledByDefault", 0)
                # Protocol must be explicitly disabled
                # Enabled = 0 AND DisabledByDefault = 1
                if not bool(enabled == 0 and disabled_by_default == 1):
                    all_weak_disabled = False
                    break
            else:
                # Registry key absent means protocol uses system default
                # which may not be disabled — treat as not explicitly disabled
                all_weak_disabled = False
                break

        weak_tls_disabled = all_weak_disabled

        return bool(rdp_crypto_ok and fips_enabled and weak_tls_disabled)

    except Exception:
        return False


def remote_crypto_ws() -> bool:
    """
    AC.L2-3.1.13b - Cryptographic Mechanisms for Remote Access Sessions
    are Implemented (Windows Server)
    """
    try:
        rdp_crypto_ok = False
        fips_enabled = False
        weak_tls_disabled = False
        ipsec_configured = False

        # Check RDP NLA and encryption level
        rdp_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Terminal Server\\WinStations\\RDP-Tcp' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object UserAuthentication, "
             "SecurityLayer, MinEncryptionLevel | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if rdp_result.returncode == 0 and rdp_result.stdout.strip():
            rdp_data = json.loads(rdp_result.stdout)
            nla = bool(rdp_data.get("UserAuthentication", 0) == 1)
            security_layer = rdp_data.get("SecurityLayer", 0)
            tls_required = bool(security_layer in {1, 2})
            min_enc = rdp_data.get("MinEncryptionLevel", 0)
            enc_strong = bool(min_enc in {3, 4})
            rdp_crypto_ok = bool(nla and tls_required and enc_strong)

        # Check FIPS mode is enabled
        fips_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
             "Lsa\\FipsAlgorithmPolicy' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object Enabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if fips_result.returncode == 0 and fips_result.stdout.strip():
            fips_data = json.loads(fips_result.stdout)
            fips_enabled = bool(fips_data.get("Enabled", 0) == 1)

        # Check weak TLS/SSL versions disabled via Schannel
        weak_protocols = {
            "SSL 2.0": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server",
            "SSL 3.0": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server",
            "TLS 1.0": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server",
            "TLS 1.1": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                       "SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server"
        }

        all_weak_disabled = True
        for protocol, reg_path in weak_protocols.items():
            proto_result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-ItemProperty -Path '{reg_path}' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object Enabled, DisabledByDefault | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if proto_result.returncode == 0 and proto_result.stdout.strip():
                proto_data = json.loads(proto_result.stdout)
                enabled = proto_data.get("Enabled", 1)
                disabled_by_default = proto_data.get("DisabledByDefault", 0)
                if not bool(enabled == 0 and disabled_by_default == 1):
                    all_weak_disabled = False
                    break
            else:
                all_weak_disabled = False
                break

        weak_tls_disabled = all_weak_disabled

        # Check IPSec rules are configured for encrypted
        # server-to-server communication
        ipsec_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetIPsecRule -Enabled True | "
             "Select-Object DisplayName, "
             "EncryptionRequired | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if ipsec_result.returncode == 0 and ipsec_result.stdout.strip():
            ipsec_rules = json.loads(ipsec_result.stdout)
            if isinstance(ipsec_rules, dict):
                ipsec_rules = [ipsec_rules]
            if ipsec_rules:
                # At least one rule must require encryption
                encrypting_rules = [
                    r for r in ipsec_rules
                    if r.get("EncryptionRequired", False)
                ]
                ipsec_configured = bool(encrypting_rules)

        return bool(
            rdp_crypto_ok
            and fips_enabled
            and weak_tls_disabled
            and ipsec_configured
        )

    except Exception:
        return False


def remote_crypto_lx() -> bool:
    """
    AC.L2-3.1.13b - Cryptographic Mechanisms for Remote Access Sessions
    are Implemented (Linux/Debian)
    """
    try:
        ciphers_ok = False
        macs_ok = False
        kex_ok = False

        # Weak algorithms that must not be present in SSH config
        weak_ciphers = {
            "3des-cbc",
            "arcfour",
            "arcfour128",
            "arcfour256",
            "blowfish-cbc",
            "cast128-cbc",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc"
        }

        weak_macs = {
            "hmac-md5",
            "hmac-md5-96",
            "hmac-sha1",
            "hmac-sha1-96",
            "umac-64@openssh.com",
            "hmac-ripemd160"
        }

        weak_kex = {
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521"
        }

        # Get active SSH configuration
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode != 0:
            return False

        output = sshd_result.stdout.lower()

        # Check ciphers
        cipher_match = re.search(
            r"^ciphers\s+(.+)$", output, re.MULTILINE
        )
        if cipher_match:
            active_ciphers = {
                c.strip()
                for c in cipher_match.group(1).split(",")
            }
            flagged_ciphers = active_ciphers & weak_ciphers
            ciphers_ok = bool(not flagged_ciphers)
        else:
            # No explicit cipher list means SSH uses defaults
            # Check OpenSSH version to determine if defaults are safe
            version_result = subprocess.run(
                ["ssh", "-V"],
                capture_output=True, text=True, timeout=10
            )
            version_output = (
                version_result.stdout + version_result.stderr
            ).lower()
            version_match = re.search(r"openssh_(\d+)\.(\d+)", version_output)
            if version_match:
                major = int(version_match.group(1))
                minor = int(version_match.group(2))
                # OpenSSH 8.0+ removed weak ciphers from defaults
                ciphers_ok = bool(major >= 8)
            else:
                ciphers_ok = False

        # Check MACs
        mac_match = re.search(
            r"^macs\s+(.+)$", output, re.MULTILINE
        )
        if mac_match:
            active_macs = {
                m.strip()
                for m in mac_match.group(1).split(",")
            }
            flagged_macs = active_macs & weak_macs
            macs_ok = bool(not flagged_macs)
        else:
            # Default MACs in modern OpenSSH exclude weak ones
            version_result = subprocess.run(
                ["ssh", "-V"],
                capture_output=True, text=True, timeout=10
            )
            version_output = (
                version_result.stdout + version_result.stderr
            ).lower()
            version_match = re.search(r"openssh_(\d+)\.(\d+)", version_output)
            if version_match:
                major = int(version_match.group(1))
                macs_ok = bool(major >= 8)
            else:
                macs_ok = False

        # Check key exchange algorithms
        kex_match = re.search(
            r"^kexalgorithms\s+(.+)$", output, re.MULTILINE
        )
        if kex_match:
            active_kex = {
                k.strip()
                for k in kex_match.group(1).split(",")
            }
            flagged_kex = active_kex & weak_kex
            kex_ok = bool(not flagged_kex)
        else:
            # Default kex in modern OpenSSH excludes weak group1
            version_result = subprocess.run(
                ["ssh", "-V"],
                capture_output=True, text=True, timeout=10
            )
            version_output = (
                version_result.stdout + version_result.stderr
            ).lower()
            version_match = re.search(r"openssh_(\d+)\.(\d+)", version_output)
            if version_match:
                major = int(version_match.group(1))
                kex_ok = bool(major >= 8)
            else:
                kex_ok = False

        # Check SSH Protocol 1 is not enabled
        # In modern OpenSSH this is removed entirely but check anyway
        protocol_match = re.search(
            r"^protocol\s+(.+)$", output, re.MULTILINE
        )
        if protocol_match:
            protocols = protocol_match.group(1).strip()
            if "1" in protocols.split(","):
                # Protocol 1 explicitly enabled — hard fail
                return False

        return bool(ciphers_ok and macs_ok and kex_ok)

    except Exception:
        return False


def managed_access_routing_wc() -> bool:
    """
    AC.L2-3.1.14b - Remote Access is Routed Through Managed Network
    Access Control Points (Windows Client)

    """
    try:
        mechanisms_active = 0

        # RFC1918 private address ranges
        rfc1918_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168."
        )

        # Check VPN adapter is present and connected
        vpn_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetAdapter | Where-Object {"
             "$_.InterfaceDescription -match "
             "'VPN|Tunnel|WireGuard|OpenVPN|Cisco|Pulse|GlobalProtect'"
             "} | Select-Object Name, Status | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if vpn_result.returncode == 0 and vpn_result.stdout.strip():
            vpn_adapters = json.loads(vpn_result.stdout)
            if isinstance(vpn_adapters, dict):
                vpn_adapters = [vpn_adapters]
            if vpn_adapters:
                connected = [
                    a for a in vpn_adapters
                    if (a.get("Status") or "").lower() == "up"
                ]
                if connected:
                    mechanisms_active += 1

        # Check Windows Defender Firewall blocks inbound RDP
        # from non-RFC1918 addresses
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -DisplayName '*Remote Desktop*' "
             "-Direction Inbound -Action Allow -Enabled True | "
             "Select-Object DisplayName, "
             "@{N='RemoteAddress';E={"
             "(Get-NetFirewallAddressFilter "
             "-AssociatedNetFirewallRule $_).RemoteAddress}} | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if rules:
                # Check all RDP allow rules are scoped to RFC1918
                external_access = [
                    r for r in rules
                    if not any(
                        str(r.get("RemoteAddress") or "").startswith(prefix)
                        for prefix in rfc1918_prefixes
                    )
                    and str(r.get("RemoteAddress") or "").lower()
                    not in {"localsubnet", ""}
                ]
                if not external_access:
                    mechanisms_active += 1
            else:
                # No RDP rules means RDP may be blocked entirely
                mechanisms_active += 1

        # Check default gateway is an RFC1918 address
        gw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
             "Select-Object NextHop | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if gw_result.returncode == 0 and gw_result.stdout.strip():
            gw_data = json.loads(gw_result.stdout)
            if isinstance(gw_data, dict):
                gw_data = [gw_data]
            if gw_data:
                gateways = [
                    g.get("NextHop", "") for g in gw_data
                    if g.get("NextHop")
                ]
                # All default gateways must be RFC1918
                internal_gws = [
                    gw for gw in gateways
                    if any(gw.startswith(p) for p in rfc1918_prefixes)
                ]
                if internal_gws and len(internal_gws) == len(gateways):
                    mechanisms_active += 1

        return bool(mechanisms_active >= 2)

    except Exception:
        return False


def managed_access_routing_ws() -> bool:
    """
    AC.L2-3.1.14b - Remote Access is Routed Through Managed Network
    Access Control Points (Windows Server)
    """
    try:
        mgmt_restricted = False
        no_external_mgmt = False
        tunnel_configured = False

        rfc1918_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168."
        )

        # Management ports to check for external access restrictions
        mgmt_ports = ["3389", "5985", "5986", "22", "443"]

        # Check all inbound allow rules for management ports
        # are scoped to RFC1918 addresses
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -Direction Inbound "
             "-Action Allow -Enabled True | "
             "Select-Object DisplayName, "
             "@{N='LocalPort';E={"
             "(Get-NetFirewallPortFilter "
             "-AssociatedNetFirewallRule $_).LocalPort}}, "
             "@{N='RemoteAddress';E={"
             "(Get-NetFirewallAddressFilter "
             "-AssociatedNetFirewallRule $_).RemoteAddress}} | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if not rules:
                return False

            # Filter rules that apply to management ports
            mgmt_rules = [
                r for r in rules
                if any(
                    p in str(r.get("LocalPort") or "")
                    for p in mgmt_ports
                )
            ]

            if mgmt_rules:
                # Check all management rules are scoped to RFC1918
                external_mgmt = [
                    r for r in mgmt_rules
                    if not any(
                        str(r.get("RemoteAddress") or "").startswith(prefix)
                        for prefix in rfc1918_prefixes
                    )
                    and str(r.get("RemoteAddress") or "").lower()
                    not in {"localsubnet", "any", ""}
                ]
                mgmt_restricted = bool(not external_mgmt)
                no_external_mgmt = mgmt_restricted
            else:
                # No explicit management port rules found
                # Check default inbound policy is block
                profile_result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-NetFirewallProfile | "
                     "Select-Object Name, DefaultInboundAction | "
                     "ConvertTo-Json"],
                    capture_output=True, text=True, timeout=30
                )
                if profile_result.returncode == 0 and \
                        profile_result.stdout.strip():
                    profiles = json.loads(profile_result.stdout)
                    if isinstance(profiles, dict):
                        profiles = [profiles]
                    all_block = all(
                        (p.get("DefaultInboundAction") or "").lower()
                        == "block"
                        for p in profiles
                    )
                    mgmt_restricted = all_block
                    no_external_mgmt = all_block

        # Check IPSec rules are configured for management traffic
        ipsec_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetIPsecRule -Enabled True | "
             "Select-Object DisplayName, "
             "EncryptionRequired | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if ipsec_result.returncode == 0 and ipsec_result.stdout.strip():
            ipsec_rules = json.loads(ipsec_result.stdout)
            if isinstance(ipsec_rules, dict):
                ipsec_rules = [ipsec_rules]
            if ipsec_rules:
                encrypting_rules = [
                    r for r in ipsec_rules
                    if r.get("EncryptionRequired", False)
                ]
                tunnel_configured = bool(encrypting_rules)

        # Check VPN adapter as alternative to IPSec
        if not tunnel_configured:
            vpn_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object {"
                 "$_.InterfaceDescription -match "
                 "'VPN|Tunnel|WireGuard|OpenVPN|Cisco|Pulse|GlobalProtect'"
                 "} | Select-Object Name, Status | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if vpn_result.returncode == 0 and vpn_result.stdout.strip():
                vpn_adapters = json.loads(vpn_result.stdout)
                if isinstance(vpn_adapters, dict):
                    vpn_adapters = [vpn_adapters]
                connected = [
                    a for a in vpn_adapters
                    if (a.get("Status") or "").lower() == "up"
                ]
                tunnel_configured = bool(connected)

        return bool(
            mgmt_restricted
            and no_external_mgmt
            and tunnel_configured
        )

    except Exception:
        return False


def managed_access_routing_lx() -> bool:
    """
    AC.L2-3.1.14b - Remote Access is Routed Through Managed Network
    Access Control Points (Linux/Debian)
    """
    try:
        mechanisms_active = 0

        rfc1918_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168."
        )

        # Check SSH firewall rules restrict to RFC1918 sources
        ssh_firewall_restricted = False

        # Check iptables for SSH restrictions
        ipt_result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=30
        )
        if ipt_result.returncode == 0 and ipt_result.stdout.strip():
            lines = ipt_result.stdout.strip().splitlines()
            ssh_rules = [
                l for l in lines
                if re.search(r"dpt:22", l)
            ]
            if ssh_rules:
                # Check SSH rules are scoped to RFC1918 source IPs
                external_ssh = [
                    l for l in ssh_rules
                    if not any(
                        prefix.replace(".", r"\.")
                        in l for prefix in rfc1918_prefixes
                    )
                    and "accept" in l.lower()
                ]
                ssh_firewall_restricted = bool(not external_ssh)

        # Check nftables for SSH restrictions if iptables not conclusive
        if not ssh_firewall_restricted:
            nft_result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True, text=True, timeout=30
            )
            if nft_result.returncode == 0 and nft_result.stdout.strip():
                output = nft_result.stdout.lower()
                if re.search(r"port\s+22", output):
                    # Check if SSH port rules reference RFC1918 ranges
                    if re.search(
                        r"(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
                        output
                    ):
                        ssh_firewall_restricted = True

        # Also check sshd_config ListenAddress for binding to
        # internal interfaces only
        if not ssh_firewall_restricted:
            sshd_result = subprocess.run(
                ["sshd", "-T"],
                capture_output=True, text=True, timeout=30
            )
            if sshd_result.returncode == 0:
                output = sshd_result.stdout.lower()
                listen_matches = re.findall(
                    r"^listenaddress\s+(\S+)", output, re.MULTILINE
                )
                if listen_matches:
                    # All listen addresses must be RFC1918
                    all_internal = all(
                        any(
                            addr.startswith(p)
                            for p in rfc1918_prefixes
                        )
                        for addr in listen_matches
                        if addr != "0.0.0.0" and addr != "::"
                    )
                    ssh_firewall_restricted = bool(all_internal)

        if ssh_firewall_restricted:
            mechanisms_active += 1

        # Check default gateway is RFC1918
        gw_result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10
        )
        if gw_result.returncode == 0 and gw_result.stdout.strip():
            gw_match = re.search(
                r"default\s+via\s+(\S+)", gw_result.stdout
            )
            if gw_match:
                gateway_ip = gw_match.group(1)
                if any(
                    gateway_ip.startswith(p)
                    for p in rfc1918_prefixes
                ):
                    mechanisms_active += 1

        # Check VPN tunnel interface is present and active
        # Look for common VPN interface name patterns
        iface_result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True, timeout=10
        )
        if iface_result.returncode == 0 and iface_result.stdout.strip():
            output = iface_result.stdout.lower()
            vpn_ifaces = re.findall(
                r"(tun\d+|tap\d+|wg\d+|vpn\d*|ipsec\d*"
                r"|ppp\d+|l2tp\d*|openvpn\d*)",
                output
            )
            if vpn_ifaces:
                # Check at least one VPN interface is UP
                for iface in vpn_ifaces:
                    iface_check = subprocess.run(
                        ["ip", "link", "show", iface],
                        capture_output=True, text=True, timeout=10
                    )
                    if iface_check.returncode == 0:
                        if "state up" in iface_check.stdout.lower():
                            mechanisms_active += 1
                            break

        return bool(mechanisms_active >= 2)

    except Exception:
        return False

def remote_privileged_exec_wc() -> bool:
    """
    AC.L2-3.1.15c - Remote Execution of Privileged Commands is Authorized
    (Windows Client)
    """
    try:
        winrm_restricted = False
        winrm_source_restricted = False

        broad_principals = {"everyone", "authenticated users", "users"}

        # Check if WinRM service is running
        winrm_svc_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Service WinRM | Select-Object Status | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if winrm_svc_result.returncode == 0 and winrm_svc_result.stdout.strip():
            svc_data = json.loads(winrm_svc_result.stdout)
            status = (svc_data.get("Status") or "").lower()
            # If WinRM is not running, remote execution is effectively disabled
            if status != "running":
                return True

        # Check WinRM listener is configured and restricted
        listener_result = subprocess.run(
            ["powershell", "-Command",
             "Get-WSManInstance -ResourceURI winrm/config/listener "
             "-SelectorSet @{Address='*';Transport='HTTP'} "
             "-ErrorAction SilentlyContinue | "
             "Select-Object Address, Transport, Port | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )

        # Check WinRM trusted hosts is not set to wildcard
        trusted_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Item WSMan:\\localhost\\Client\\TrustedHosts | "
             "Select-Object Value | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if trusted_result.returncode == 0 and trusted_result.stdout.strip():
            trusted_data = json.loads(trusted_result.stdout)
            trusted_value = (trusted_data.get("Value") or "").strip()
            # Wildcard * means any host is trusted — hard fail
            if trusted_value == "*":
                return False
            winrm_source_restricted = True

        # Check PowerShell remoting session configurations
        # are restricted to named privileged accounts
        session_result = subprocess.run(
            ["powershell", "-Command",
             "Get-PSSessionConfiguration | "
             "Select-Object Name, Permission | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if session_result.returncode == 0 and session_result.stdout.strip():
            sessions = json.loads(session_result.stdout)
            if isinstance(sessions, dict):
                sessions = [sessions]
            if not sessions:
                return False

            # Flag any session configuration that grants access
            # to broad principals
            flagged_sessions = [
                s for s in sessions
                if any(
                    p in (s.get("Permission") or "").lower()
                    for p in broad_principals
                )
                and "AccessAllowed" in (s.get("Permission") or "")
            ]
            winrm_restricted = bool(not flagged_sessions)

        # Check WinRM firewall rules restrict inbound to RFC1918
        rfc1918_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168."
        )
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -DisplayName '*Windows Remote Management*' "
             "-Direction Inbound -Action Allow -Enabled True | "
             "Select-Object DisplayName, "
             "@{N='RemoteAddress';E={"
             "(Get-NetFirewallAddressFilter "
             "-AssociatedNetFirewallRule $_).RemoteAddress}} | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if rules:
                external_rules = [
                    r for r in rules
                    if not any(
                        str(r.get("RemoteAddress") or "").startswith(p)
                        for p in rfc1918_prefixes
                    )
                    and str(r.get("RemoteAddress") or "").lower()
                    not in {"localsubnet", ""}
                ]
                if not external_rules:
                    winrm_source_restricted = True

        return bool(winrm_restricted and winrm_source_restricted)

    except Exception:
        return False


def remote_security_info_access_wc() -> bool:
    """
    AC.L2-3.1.15d - Remote Access to Security-Relevant Information is
    Authorized (Windows Client)
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Check Windows Event Log (Security) access permissions
        evtlog_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Acl -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\"
             "Services\\EventLog\\Security' | "
             "Select-Object -ExpandProperty Access | "
             "Select-Object IdentityReference, "
             "RegistryRights, AccessControlType | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if evtlog_result.returncode == 0 and evtlog_result.stdout.strip():
            acls = json.loads(evtlog_result.stdout)
            if isinstance(acls, dict):
                acls = [acls]
            if not acls:
                return False

            # Flag any broad principal with Allow Full or Write access
            flagged_acls = [
                a for a in acls
                if (a.get("IdentityReference") or "").lower().split("\\")[-1]
                in broad_principals
                and (a.get("AccessControlType") or "").lower() == "allow"
                and any(
                    right in (a.get("RegistryRights") or "").lower()
                    for right in ["fullcontrol", "write", "setvalue"]
                )
            ]
            if flagged_acls:
                return False

        # Check security policy export path is restricted
        # secedit exports contain sensitive security configuration
        secedit_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Acl -Path $env:WINDIR\\security | "
             "Select-Object -ExpandProperty Access | "
             "Select-Object IdentityReference, "
             "FileSystemRights, AccessControlType | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if secedit_result.returncode == 0 and secedit_result.stdout.strip():
            acls = json.loads(secedit_result.stdout)
            if isinstance(acls, dict):
                acls = [acls]

            flagged_security_dir = [
                a for a in acls
                if (a.get("IdentityReference") or "").lower().split("\\")[-1]
                in broad_principals
                and (a.get("AccessControlType") or "").lower() == "allow"
                and any(
                    right in (a.get("FileSystemRights") or "").lower()
                    for right in ["fullcontrol", "write", "modify"]
                )
            ]
            if flagged_security_dir:
                return False

        # Check LSA registry key is restricted
        lsa_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Acl -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\"
             "Control\\Lsa' | "
             "Select-Object -ExpandProperty Access | "
             "Select-Object IdentityReference, "
             "RegistryRights, AccessControlType | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if lsa_result.returncode == 0 and lsa_result.stdout.strip():
            acls = json.loads(lsa_result.stdout)
            if isinstance(acls, dict):
                acls = [acls]

            flagged_lsa = [
                a for a in acls
                if (a.get("IdentityReference") or "").lower().split("\\")[-1]
                in broad_principals
                and (a.get("AccessControlType") or "").lower() == "allow"
                and any(
                    right in (a.get("RegistryRights") or "").lower()
                    for right in ["fullcontrol", "write", "setvalue"]
                )
            ]
            if flagged_lsa:
                return False

        return True

    except Exception:
        return False


def remote_privileged_exec_ws() -> bool:
    """
    AC.L2-3.1.15c - Remote Execution of Privileged Commands is Authorized
    (Windows Server)
    """
    try:
        winrm_restricted = False
        winrm_source_restricted = False
        audit_configured = False

        broad_principals = {"everyone", "authenticated users", "users"}
        rfc1918_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168."
        )

        # Check WinRM service status
        winrm_svc_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Service WinRM | Select-Object Status | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if winrm_svc_result.returncode == 0 and winrm_svc_result.stdout.strip():
            svc_data = json.loads(winrm_svc_result.stdout)
            status = (svc_data.get("Status") or "").lower()
            if status != "running":
                # WinRM not running means remote execution disabled
                return True

        # Check PS session configurations restricted to named groups
        session_result = subprocess.run(
            ["powershell", "-Command",
             "Get-PSSessionConfiguration | "
             "Select-Object Name, Permission | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if session_result.returncode == 0 and session_result.stdout.strip():
            sessions = json.loads(session_result.stdout)
            if isinstance(sessions, dict):
                sessions = [sessions]
            if sessions:
                flagged_sessions = [
                    s for s in sessions
                    if any(
                        p in (s.get("Permission") or "").lower()
                        for p in broad_principals
                    )
                    and "AccessAllowed" in (s.get("Permission") or "")
                ]
                winrm_restricted = bool(not flagged_sessions)

        # Check WinRM trusted hosts not wildcard
        trusted_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Item WSMan:\\localhost\\Client\\TrustedHosts | "
             "Select-Object Value | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if trusted_result.returncode == 0 and trusted_result.stdout.strip():
            trusted_data = json.loads(trusted_result.stdout)
            trusted_value = (trusted_data.get("Value") or "").strip()
            if trusted_value == "*":
                return False

        # Check WinRM firewall rules restrict to RFC1918
        fw_result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule -DisplayName '*Windows Remote Management*' "
             "-Direction Inbound -Action Allow -Enabled True | "
             "Select-Object DisplayName, "
             "@{N='RemoteAddress';E={"
             "(Get-NetFirewallAddressFilter "
             "-AssociatedNetFirewallRule $_).RemoteAddress}} | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if fw_result.returncode == 0 and fw_result.stdout.strip():
            rules = json.loads(fw_result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
            if rules:
                external_rules = [
                    r for r in rules
                    if not any(
                        str(r.get("RemoteAddress") or "").startswith(p)
                        for p in rfc1918_prefixes
                    )
                    and str(r.get("RemoteAddress") or "").lower()
                    not in {"localsubnet", ""}
                ]
                winrm_source_restricted = bool(not external_rules)

        # Check audit policy captures remote execution events
        # Process Creation and PowerShell script block logging
        audit_result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=30
        )
        if audit_result.returncode == 0:
            output = audit_result.stdout.lower()
            has_process_creation = bool(
                re.search(
                    r"process creation.*?(success|failure)",
                    output
                )
            )
            # Check PowerShell script block logging
            pslog_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty -Path "
                 "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
                 "PowerShell\\ScriptBlockLogging' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object EnableScriptBlockLogging | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            ps_logging = False
            if pslog_result.returncode == 0 and pslog_result.stdout.strip():
                ps_data = json.loads(pslog_result.stdout)
                ps_logging = bool(
                    ps_data.get("EnableScriptBlockLogging", 0) == 1
                )
            audit_configured = bool(has_process_creation or ps_logging)

        return bool(
            winrm_restricted
            and winrm_source_restricted
            and audit_configured
        )

    except Exception:
        return False


def remote_security_info_access_ws() -> bool:
    """
    AC.L2-3.1.15d - Remote Access to Security-Relevant Information is
    Authorized (Windows Server)
    """
    try:
        broad_principals = {"everyone", "authenticated users", "users"}

        # Check SYSVOL share permissions (contains GPO settings)
        sysvol_result = subprocess.run(
            ["powershell", "-Command",
             "Get-SmbShareAccess -Name 'SYSVOL' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object AccountName, AccessRight | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if sysvol_result.returncode == 0 and sysvol_result.stdout.strip():
            acls = json.loads(sysvol_result.stdout)
            if isinstance(acls, dict):
                acls = [acls]
            # SYSVOL needs to be readable by domain members for GP
            # but should not grant Change or Full to broad principals
            flagged_sysvol = [
                a for a in acls
                if (a.get("AccountName") or "").lower().split("\\")[-1]
                in broad_principals
                and (a.get("AccessRight") or "").lower()
                in {"full", "change"}
            ]
            if flagged_sysvol:
                return False

        # Check Security Event Log access is restricted
        evtlog_result = subprocess.run(
            ["powershell", "-Command",
             "Get-Acl -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\"
             "Services\\EventLog\\Security' | "
             "Select-Object -ExpandProperty Access | "
             "Select-Object IdentityReference, "
             "RegistryRights, AccessControlType | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if evtlog_result.returncode == 0 and evtlog_result.stdout.strip():
            acls = json.loads(evtlog_result.stdout)
            if isinstance(acls, dict):
                acls = [acls]

            flagged_evtlog = [
                a for a in acls
                if (a.get("IdentityReference") or "").lower().split("\\")[-1]
                in broad_principals
                and (a.get("AccessControlType") or "").lower() == "allow"
                and any(
                    right in (a.get("RegistryRights") or "").lower()
                    for right in ["fullcontrol", "write", "setvalue"]
                )
            ]
            if flagged_evtlog:
                return False

        # Check AD database path access is restricted
        # NTDS.dit contains all AD security-relevant information
        ntds_result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty -Path "
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' "
             "-ErrorAction SilentlyContinue | "
             "Select-Object 'DSA Database file' | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30
        )
        if ntds_result.returncode == 0 and ntds_result.stdout.strip():
            ntds_data = json.loads(ntds_result.stdout)
            ntds_path = ntds_data.get("DSA Database file", "")
            if ntds_path:
                ntds_dir = "\\".join(
                    str(ntds_path).split("\\")[:-1]
                )
                ntds_acl_result = subprocess.run(
                    ["powershell", "-Command",
                     f"Get-Acl -Path '{ntds_dir}' | "
                     "Select-Object -ExpandProperty Access | "
                     "Select-Object IdentityReference, "
                     "FileSystemRights, AccessControlType | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=30
                )
                if ntds_acl_result.returncode == 0 and \
                        ntds_acl_result.stdout.strip():
                    acls = json.loads(ntds_acl_result.stdout)
                    if isinstance(acls, dict):
                        acls = [acls]

                    flagged_ntds = [
                        a for a in acls
                        if (a.get("IdentityReference") or "")
                        .lower().split("\\")[-1]
                        in broad_principals
                        and (a.get("AccessControlType") or "").lower()
                        == "allow"
                        and any(
                            right in (a.get("FileSystemRights") or "").lower()
                            for right in ["fullcontrol", "write", "modify"]
                        )
                    ]
                    if flagged_ntds:
                        return False

        return True

    except Exception:
        return False


def remote_privileged_exec_lx() -> bool:
    """
    AC.L2-3.1.15c - Remote Execution of Privileged Commands is Authorized
    (Linux/Debian)
    """
    try:
        sudoers_scoped = False
        root_remote_disabled = False
        ssh_exec_restricted = False

        # Check sudoers has no unscoped remote execution entries
        # Get standard users for comparison
        passwd_result = subprocess.run(
            ["awk", "-F:", '$3 >= 1000 && $1 != "nobody" {print $1}',
             "/etc/passwd"],
            capture_output=True, text=True, timeout=10
        )
        if passwd_result.returncode != 0:
            return False

        standard_users = {
            l.strip() for l in passwd_result.stdout.strip().splitlines()
            if l.strip()
        }

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

        # Flag any standard user with unscoped ALL=(ALL) ALL
        unscoped = [
            l for l in active_lines
            if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", l)
            and not l.startswith("%")
            and not l.startswith("root")
            and any(u in l for u in standard_users)
        ]
        sudoers_scoped = bool(not unscoped)

        # Also check sudoers.d
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
                and any(u in l for u in standard_users)
            ]
            if unscoped_d:
                sudoers_scoped = False

        # Check SSH root login is disabled
        sshd_result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True, text=True, timeout=30
        )
        if sshd_result.returncode != 0:
            return False

        output = sshd_result.stdout.lower()

        root_match = re.search(
            r"^permitrootlogin\s+(\S+)", output, re.MULTILINE
        )
        if root_match:
            root_remote_disabled = bool(
                root_match.group(1).lower()
                in {"no", "prohibit-password"}
            )

        # Check SSH does not allow unrestricted TCP forwarding
        # which could be used to tunnel privileged command execution
        tcp_fwd_match = re.search(
            r"^allowtcpforwarding\s+(\S+)", output, re.MULTILINE
        )
        agent_fwd_match = re.search(
            r"^allowagentforwarding\s+(\S+)", output, re.MULTILINE
        )

        tcp_restricted = bool(
            tcp_fwd_match
            and tcp_fwd_match.group(1).lower() in {"no", "local"}
        )
        agent_restricted = bool(
            agent_fwd_match
            and agent_fwd_match.group(1).lower() == "no"
        )

        # Check X11 forwarding is disabled as it enables
        # remote GUI execution of privileged applications
        x11_match = re.search(
            r"^x11forwarding\s+(\S+)", output, re.MULTILINE
        )
        x11_restricted = bool(
            x11_match and x11_match.group(1).lower() == "no"
        )

        ssh_exec_restricted = bool(
            tcp_restricted and agent_restricted and x11_restricted
        )

        return bool(
            sudoers_scoped
            and root_remote_disabled
            and ssh_exec_restricted
        )

    except Exception:
        return False


def remote_security_info_access_lx() -> bool:
    """
    AC.L2-3.1.15d - Remote Access to Security-Relevant Information is
    Authorized (Linux/Debian)
    """
    try:
        flagged_files = []

        # Security-relevant files and their maximum acceptable permissions
        # Format: (path, max_mode_octal, allow_world_read)
        security_files = [
            ("/etc/sudoers", 0o440, False),
            ("/etc/sudoers.d", 0o750, False),
            ("/etc/ssh/sshd_config", 0o600, False),
            ("/etc/ssh/ssh_host_rsa_key", 0o600, False),
            ("/etc/ssh/ssh_host_ecdsa_key", 0o600, False),
            ("/etc/shadow", 0o640, False),
            ("/etc/pam.d", 0o755, False),
            ("/var/log/audit", 0o750, False),
            ("/var/log/audit/audit.log", 0o600, False),
            ("/var/log/auth.log", 0o640, False),
            ("/var/log/secure", 0o600, False),
        ]

        for filepath, max_mode, allow_world_read in security_files:
            stat_result = subprocess.run(
                ["stat", "-c", "%a %U %G", filepath],
                capture_output=True, text=True, timeout=10
            )
            # Skip files that don't exist on this system
            if stat_result.returncode != 0:
                continue

            parts = stat_result.stdout.strip().split()
            if len(parts) < 3:
                continue

            mode_str, owner, group = parts[0], parts[1], parts[2]

            try:
                mode_int = int(mode_str, 8)
            except ValueError:
                continue

            # Check world-writable
            world_writable = bool(mode_int & 0o002)
            if world_writable:
                flagged_files.append(
                    f"{filepath}: world-writable ({mode_str})"
                )
                continue

            # Check world-readable for files that must not be
            if not allow_world_read:
                world_readable = bool(mode_int & 0o004)
                if world_readable:
                    flagged_files.append(
                        f"{filepath}: world-readable ({mode_str})"
                    )
                    continue

            # Check owner is root or a named service account
            insecure_owners = {"nobody", "anonymous", ""}
            if owner.lower() in insecure_owners:
                flagged_files.append(
                    f"{filepath}: insecure owner ({owner})"
                )

        # Check auditd log directory ACLs via getfacl
        acl_result = subprocess.run(
            ["getfacl", "/var/log/audit"],
            capture_output=True, text=True, timeout=10
        )
        if acl_result.returncode == 0 and acl_result.stdout.strip():
            acl_lines = acl_result.stdout.splitlines()
            # Flag any other: entry with read or write permissions
            other_acls = [
                l for l in acl_lines
                if l.startswith("other:") and (
                    "r" in l.split(":")[-1]
                    or "w" in l.split(":")[-1]
                )
            ]
            if other_acls:
                flagged_files.append(
                    "/var/log/audit: permissive ACL for other"
                )

        # Check SSH authorized_keys files are not world-readable
        home_result = subprocess.run(
            ["find", "/home", "-name", "authorized_keys",
             "-perm", "/o+r"],
            capture_output=True, text=True, timeout=30
        )
        if home_result.returncode == 0 and home_result.stdout.strip():
            world_readable_keys = [
                l.strip() for l in home_result.stdout.strip().splitlines()
                if l.strip()
            ]
            flagged_files.extend(
                f"{k}: world-readable authorized_keys"
                for k in world_readable_keys
            )

        return bool(not flagged_files)

    except Exception:
        return False