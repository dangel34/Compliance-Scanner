from base_scanner import ScannerTarget
import subprocess


class DebianModule(ScannerTarget):
    def __init__(self):
        ScannerTarget.__init__(self)

    def run_cmd(self, cmd: str) -> dict:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
            )
            return {
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
            }

    def check_service(self, name: str) -> str:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except Exception:
            return ""

    def check_file_permissions(self, path: str) -> str:
        try:
            result = subprocess.run(
                ["stat", "-c", "%a %U %G %n", path],
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except Exception:
            return ""
