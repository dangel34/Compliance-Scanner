import os
import json
import subprocess
from typing import List, Dict, Any


class RuleRunner:
    """
    Loads the rule via path and executes the checks described in the rule,
    returning a pass or fail along with other information
    """
    def __init__(self, rule_path: str, os_type: str = "windows"):
        self.rule_path = rule_path
        self.os_type = os_type
        self.rule = self._load_rule()

    def _load_rule(self) -> Dict[str, Any]:
        if not os.path.isfile(self.rule_path):
            raise FileNotFoundError(f"Rule file not found: {self.rule_path}")
        with open(self.rule_path, "r") as f:
            return json.load(f)

    @staticmethod
    def run_command(cmd: str) -> Dict[str, Any]:
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

    def get_checks(self) -> List[Dict[str, Any]]:
        # Normalize os_type (windows_client -> windows-client) to match check_details keys
        os_key = self.os_type.replace("_", "-")
        return (
            self.rule
            .get("check_details", {})
            .get(os_key, {})
            .get("checks", [])
        )

    def run_checks(self) -> Dict[str, Any]:
        results = []

        for check in self.get_checks():
            cmd = check.get("command")
            name = check.get("name", "Unnamed Check")

            execution = self.run_command(cmd)
            passed = execution["returncode"] == 0

            results.append({
                "check_name": name,
                "command": cmd,
                "status": "PASS" if passed else "FAIL",
                "returncode": execution["returncode"],
                "stdout": execution["stdout"],
                "stderr": execution["stderr"]
            })

        return {
            "rule_id": self.rule.get("rule_id") or self.rule.get("id"),
            "title": self.rule.get("title"),
            "os": self.os_type,
            "checks_run": len(results),
            "checks": results
        }

if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

    RULE_PATH = os.path.join(PROJECT_ROOT, "rulesets", "cmmc-rules", "AC.L2-3.1.1.json")

    runner = RuleRunner(rule_path=RULE_PATH, os_type="windows_client")
    result = runner.run_checks()

    print(f"Rule ID: {result['rule_id']}")
    print(f"Title: {result['title']}")
    print(f"OS: {result['os']}")
    print(f"Checks Run: {result['checks_run']}")
    print("-" * 50)

    for check in result["checks"]:
        print(f"Check: {check['check_name']}")
        print(f"Status: {check['status']}")
        print(f"Command: {check['command']}")

        if check["stdout"]:
            print("Output:")
            print(check["stdout"])

        if check["stderr"]:
            print("Error:")
            print(check["stderr"])
