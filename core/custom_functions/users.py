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
    Runs: wmic useraccount where disabled=false get name

    Returns:
        (bool, str)
        True  -> command executed successfully
        False -> execution error
    """
    try:
        result = subprocess.run(
            ["wmic", "useraccount", "where", "disabled=false", "get", "name"],
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