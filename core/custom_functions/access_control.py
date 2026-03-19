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