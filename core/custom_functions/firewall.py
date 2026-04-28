# Firewall-based functions

import re
import subprocess

# netsh advfirewall output uses variable whitespace between "State" and "ON/OFF",
# e.g. "State                                 ON". Match with \s+ not a literal space.
_STATE_ON  = re.compile(r"State\s+ON\b",  re.IGNORECASE)
_STATE_OFF = re.compile(r"State\s+OFF\b", re.IGNORECASE)

_EXPECTED_PROFILES = 3  # Domain, Private, Public


def firewall_enabled():
    """
    Checks if Windows Firewall is enabled on ALL profiles (Domain, Private, Public).
    Returns True only when every profile reports State ON and none report State OFF.
    Returns:
        (bool, str) -> success, output
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout.strip()

        if result.returncode != 0:
            return False, result.stderr.strip()

        on_count  = len(_STATE_ON.findall(output))
        off_count = len(_STATE_OFF.findall(output))

        if on_count >= _EXPECTED_PROFILES and off_count == 0:
            return True, output

        if off_count > 0:
            return (
                False,
                f"{off_count} firewall profile(s) are disabled "
                f"(ON: {on_count}, OFF: {off_count})\n{output}",
            )

        return False, f"Could not confirm all profiles are enabled (ON found: {on_count})\n{output}"

    except Exception as e:
        return False, str(e)