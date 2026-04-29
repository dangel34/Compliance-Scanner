# User-based functions

import subprocess

def local_administrators_group():
    """
    Runs: net localgroup administrators

    Returns:
        (bool, str)
        True  -> command executed successfully
        False -> execution error
    """
    try:
        result = subprocess.run(
            ["net", "localgroup", "administrators"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return False, result.stderr.strip()

        output = result.stdout.strip()

        return True, output

    except Exception as e:
        return False, str(e)


def enabled_local_users():
    """
    Lists enabled local user accounts via PowerShell Get-LocalUser.
    wmic was deprecated in Windows 10 21H1 and removed in Windows 11 23H2+.

    Returns:
        (bool, str)
        True  -> command executed successfully; str contains JSON user list
        False -> execution error
    """
    try:
        result = subprocess.run(
            [
                "powershell", "-NonInteractive", "-NoProfile", "-Command",
                "Get-LocalUser | Where-Object {$_.Enabled -eq $true}"
                " | Select-Object Name | ConvertTo-Json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return False, result.stderr.strip()

        return True, result.stdout.strip()

    except Exception as e:
        return False, str(e)