from base_scanner import ScannerTarget
import subprocess


class WindowsModule(ScannerTarget):
    def __init__(self):
        ScannerTarget.__init__(self)

    def run_cmd(self, cmd=str, is_windowless=True) -> str:
        """
        Uses powershell command and returns output (Windowless by default)
        :param cmd: Input command
        :param is_windowless: By default True, makes the powershell headless
        :return:
        """
        if is_windowless:
            result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout.strip()
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NEW_CONSOLE)
            return result.stdout.strip()

    def check_service(self, name: str) -> str:
        pass
    def check_file_permissions(self, path: str) -> str:
        pass