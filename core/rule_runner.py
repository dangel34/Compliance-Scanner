"""
Loads rules (JSON) and runs checks via core scanners. Uses scanner_init for
OS detection and, when applicable, scanner methods for service/file_permissions.
"""
import logging
import os
import json
import subprocess
import re
import importlib
from typing import List, Dict, Any, Optional

_log = logging.getLogger(__name__)

# Project root (parent of core/)
_core_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_core_dir)

from core.scanner_init import os_scan, get_scanner


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
                shell=True,
                timeout=60
            )
            return {
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            _log.warning("Command timed out (60s): %.120s", cmd)
            return {"stdout": "", "stderr": "command timed out", "returncode": -1}
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
        """Gets checks"""
        return (
            self.rule
            .get("check_details", {})
            .get(self.os_type, {})
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
            _log.error("Custom function failed: %s: %s", func_call, e)
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    def _is_na_check(self, check: Dict[str, Any]) -> bool:
        """Return True if this check should be skipped (command is NA)."""
        cmd = check.get("command")
        if cmd is None:
            return True
        return str(cmd).strip().upper() == "NA"

    def run_checks(self) -> Dict[str, Any]:
        results = []
        scanner = self._get_scanner()
        checks_skipped = 0

        for check in self.get_checks():
            name = check.get("name", "Unnamed Check")
            sub_control = check.get("sub_control", "Unnamed Subcontrol")
            check_type = check.get("check_type", "command")

            # Skip NA subcontrols for speed (no executable command)
            if self._is_na_check(check):
                checks_skipped += 1
                continue

            if check_type == "service" and scanner is not None:
                service_name = check.get("service") or check.get("name")
                try:
                    out = scanner.check_service(service_name)
                    results.append({
                        "check_name": name,
                        "sub_control": sub_control,
                        "command": f"check_service({service_name})",
                        "expected_result": check.get("expected_result", ""),
                        "status": "PASS" if out else "FAIL",
                        "returncode": 0 if out else -1,
                        "stdout": out or "",
                        "stderr": ""
                    })
                except Exception as e:
                    results.append({
                        "check_name": name,
                        "sub_control": sub_control,
                        "command": f"check_service({service_name})",
                        "expected_result": check.get("expected_result", ""),
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
                        "sub_control": sub_control,
                        "command": f"check_file_permissions({path})",
                        "expected_result": check.get("expected_result", ""),
                        "status": "PASS" if out else "FAIL",
                        "returncode": 0 if out else -1,
                        "stdout": out or "",
                        "stderr": ""
                    })
                except Exception as e:
                    results.append({
                        "check_name": name,
                        "sub_control": sub_control,
                        "command": f"check_file_permissions({path})",
                        "expected_result": check.get("expected_result", ""),
                        "status": "FAIL",
                        "returncode": -1,
                        "stdout": "",
                        "stderr": str(e)
                    })
            else:
                # command (default): run via OS-appropriate scanner (Windows CMD/PowerShell, Linux bash)
                cmd = check.get("command")

                if cmd and cmd.startswith("cs_f("):
                    execution = self.run_custom_function(cmd)
                else:
                    execution = self.run_command(cmd)

                passed = execution["returncode"] == 0
                results.append({
                    "check_name": name,
                    "sub_control": sub_control,
                    "command": cmd,
                    "expected_result": check.get("expected_result", ""),
                    "status": "PASS" if passed else "FAIL",
                    "returncode": execution["returncode"],
                    "stdout": execution.get("stdout", ""),
                    "stderr": execution.get("stderr", "")
                })

        return {
            "rule_id":     self.rule.get("rule_id") or self.rule.get("id"),
            "title":       self.rule.get("title"),
            "os":          self.os_type,
            "severity":    self.rule.get("severity", ""),
            "remediation": self.rule.get("remediation", ""),
            "checks_run":     len(results),
            "checks_skipped": checks_skipped,
            "checks":         results,
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
