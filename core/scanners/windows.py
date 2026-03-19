from base_scanner import ScannerTarget
import subprocess


class WindowsModule(ScannerTarget):
    def __init__(self):
        ScannerTarget.__init__(self)

    def run_cmd(self, cmd: str, is_windowless: bool = True) -> dict:
        """
        Uses powershell command and returns a result dict (windowless by default).
        :param cmd: Input command
        :param is_windowless: By default True, makes the powershell headless
        :return: {'stdout': str, 'stderr': str, 'returncode': int}
        """
        creation_flag = (
            subprocess.CREATE_NO_WINDOW if is_windowless else subprocess.CREATE_NEW_CONSOLE
        )
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=creation_flag,
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
        pass
    def check_file_permissions(self, path: str) -> str:
        pass