from core.scanners.base_scanner import ScannerTarget
import subprocess


class DebianModule(ScannerTarget):
    def __init__(self):
        ScannerTarget.__init__(self)

    def check_service(self, name: str) -> str:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""

    def check_file_permissions(self, path: str) -> str:
        try:
            result = subprocess.run(
                ["stat", "-c", "%a %U %G %n", path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""
