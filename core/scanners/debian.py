from core.scanners.base_scanner import ScannerTarget
import subprocess


class DebianModule(ScannerTarget):
    def check_service(self, name: str) -> str:
        if not name or any(c in name for c in ("'", '"', ";", "\n", "\r", " ")):
            return ""
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
        if not path or any(c in path for c in ("'", '"', "\n", "\r")):
            return ""
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
