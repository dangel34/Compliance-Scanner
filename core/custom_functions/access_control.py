import subprocess


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
    import json
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