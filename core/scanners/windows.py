from base_scanner import ScannerTarget
import subprocess

class WindowsModule(ScannerTarget):
    def __init__(self):
        ScannerTarget.__init__(self)

    def run_cmd(self, cmd: str) -> str:
        result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout.strip()
    def check_service(self, name: str) -> str:
        pass
    def check_file_permissions(self, path: str) -> str:
        pass
