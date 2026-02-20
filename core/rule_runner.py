"""
Loads rules (JSON) and runs checks via core scanners. Uses scanner_init for
OS detection and, when applicable, scanner methods for service/file_permissions.
"""
import os
import json
import subprocess
import re
import importlib
from typing import List, Dict, Any, Optional

from scanner_init import os_scan, get_scanner

# Project root (parent of core/)
_core_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_core_dir)


class RuleRunner:
    """
    Loads the rule via path and executes the checks described in the rule,
    returning a pass or fail along with other information. Uses core
    scanner_init for OS detection and scanner for service/file_permissions checks.
    """
    def __init__(self, rule_path: str, os_type: Optional[str] = None, scanner=None):
        self.rule_path = rule_path
        self._scanner = scanner
        if os_type is not None:
            self.os_type = os_type
        else:
            self.os_type = os_scan()
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

    def _get_scanner(self):
        """Use injected scanner or get_scanner() from core"""
        if self._scanner is not None:
            return self._scanner
        return get_scanner()

    def get_checks(self) -> List[Dict[str, Any]]:
        """Normalize os_type (windows_client -> windows-client) to match check_details keys"""
        os_key = self.os_type.replace("_", "-")
        return (
            self.rule
            .get("check_details", {})
            .get(os_key, {})
            .get("checks", [])
        )

    def run_custom_function(self, func_call: str) -> Dict[str, Any]:
        """
        Executes custom python function from core/custom_functions.

        Syntax:
            cs_f(function_name)
            cs_f(module.function_name)
        """
        try:
            match = re.match(r"cs_f\((.*?)\)", func_call)
            if not match:
                raise ValueError("Invalid custom function syntax")

            func_path = match.group(1).strip()

            # allow module.function or just function
            if "." in func_path:
                module_name, func_name = func_path.split(".", 1)
            else:
                module_name = func_path
                func_name = func_path

            module = importlib.import_module(
                f"core.custom_functions.{module_name}"
            )

            func = getattr(module, func_name)

            result = func()

            if isinstance(result, tuple):
                success, output = result
            else:
                success = bool(result)
                output = str(result)

            return {
                "stdout": output,
                "stderr": "",
                "returncode": 0 if success else 1
            }

        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    def run_checks(self) -> Dict[str, Any]:
        results = []
        check_type = self.rule.get("check_type", "command")
        scanner = self._get_scanner()

        for check in self.get_checks():
            name = check.get("name", "Unnamed Check")

            if check_type == "service" and scanner is not None:
                service_name = check.get("service") or check.get("name")
                try:
                    out = scanner.check_service(service_name)
                    results.append({
                        "check_name": name,
                        "command": f"check_service({service_name})",
                        "status": "PASS" if out else "FAIL",
                        "returncode": 0 if out else -1,
                        "stdout": out or "",
                        "stderr": ""
                    })
                except Exception as e:
                    results.append({
                        "check_name": name,
                        "command": f"check_service({service_name})",
                        "status": "FAIL",
                        "returncode": -1,
                        "stdout": "",
                        "stderr": str(e)
                    })
            elif check_type == "file_permissions" and scanner is not None:
                path = check.get("path") or check.get("command")
                try:
                    out = scanner.check_file_permissions(path)
                    results.append({
                        "check_name": name,
                        "command": f"check_file_permissions({path})",
                        "status": "PASS" if out else "FAIL",
                        "returncode": 0 if out else -1,
                        "stdout": out or "",
                        "stderr": ""
                    })
                except Exception as e:
                    results.append({
                        "check_name": name,
                        "command": f"check_file_permissions({path})",
                        "status": "FAIL",
                        "returncode": -1,
                        "stdout": "",
                        "stderr": str(e)
                    })
            else:
                # command (default): run via subprocess to preserve returncode for PASS/FAIL
                cmd = check.get("command")

                if cmd and cmd.startswith("cs_f("):
                    execution = self.run_custom_function(cmd)
                else:
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
    RULE_PATH = os.path.join(_project_root, "rulesets", "cmmc-rules", "AC.L2-3.1.1.json")
    runner = RuleRunner(rule_path=RULE_PATH, os_type=None)
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
