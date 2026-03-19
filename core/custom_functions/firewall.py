# Firewall-based functions

import subprocess


def firewall_enabled():
    """
    Checks if Windows Firewall is enabled on all profiles.
    Returns:
        (bool, str) -> success, output
    """
    try:
        result = subprocess.run(
            "netsh advfirewall show allprofiles",
            capture_output=True,
            text=True,
            shell=True
        )

        output = result.stdout.strip()

        if result.returncode != 0:
            return False, result.stderr.strip()

        # Basic validation: check if all profiles are ON
        if "State ON" in output:
            return True, output
        else:
            return False, output

    except Exception as e:
        return False, str(e)