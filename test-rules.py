import os
import json
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULE_PATH = os.path.join(SCRIPT_DIR, "rulesets", "cmmc-rules", "AC.L2-3.1.1.json")

with open(RULE_PATH, encoding="utf-8") as f:
    rule = json.load(f)


def run_command(cmd):
    try:
        if sys.platform == "win32":
            args = ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd]
        else:
            args = ["bash", "-lc", cmd]
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


# Get checks for the chosen OS (keys in check_details use underscores: windows_client, debian, etc.)
os_key = "windows_client"
os_checks = rule.get("check_details", {}).get(os_key, {}).get("checks", [])
for check in os_checks:
    name = check.get("name")
    cmd = check.get("command")
    print(f"Running check: {name}")
    print(f"Command: {cmd}")

    result = run_command(cmd)
    status = "PASS" if result["returncode"] == 0 else "FAIL"
    print(f"Result: {status}")
    print(f"Output:\n{result['stdout']}\n")
    if result["stderr"]:
        print(f"Error:\n{result['stderr']}\n")
    print("-" * 40)