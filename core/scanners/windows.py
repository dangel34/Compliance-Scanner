from core.scanners.base_scanner import ScannerTarget
import subprocess


class WindowsModule(ScannerTarget):
    def __init__(self):
        ScannerTarget.__init__(self)

    def check_service(self, name: str) -> str:
        """
        Queries a Windows service by name using PowerShell and returns its
        status string (e.g. 'Running', 'Stopped'). Returns an empty string
        if the service does not exist or the query fails.
        """
        # Basic sanitization: reject names containing quotes or semicolons
        # to prevent PowerShell injection from malformed rule files.
        if not name or any(c in name for c in ("'", '"', ";", "\n", "\r")):
            return ""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-NoProfile",
                    "-Command",
                    f"Get-Service -Name '{name}' -ErrorAction Stop"
                    " | Select-Object -ExpandProperty Status",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""

    def check_file_permissions(self, path: str) -> str:
        """
        Retrieves the owner and access control entries for a file or directory
        using PowerShell Get-Acl. Returns a formatted string:
            '<Owner> | <Identity>:<Rights>, ...'
        Returns an empty string if the path does not exist or the query fails.
        """
        # Basic sanitization: reject paths containing quote characters or
        # newlines to prevent PowerShell injection from malformed rule files.
        if not path or any(c in path for c in ("'", '"', "\n", "\r")):
            return ""
        ps_cmd = (
            f"$acl = Get-Acl -Path '{path}' -ErrorAction Stop; "
            "$entries = ($acl.Access | ForEach-Object { "
            "    $_.IdentityReference.ToString() + ':' + $_.FileSystemRights.ToString() "
            "}) -join ', '; "
            "$acl.Owner + ' | ' + $entries"
        )
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-NoProfile",
                    "-Command",
                    ps_cmd,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""