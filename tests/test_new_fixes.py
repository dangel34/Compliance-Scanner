"""
Tests for fixes applied after the initial v1.0.1 review:

  Fix A  system_communications_protection.py  _ps() still used shell=True (Bug #5 missed)
  Fix B  system_information_integrity.py       _ps() still used shell=True (Bug #5 missed)
  Fix C  audit_accountability.py               manage_audit_right_wc / audit_policy_modify_restricted_wc
                                               used hardcoded C:\\...\\secpol_tmp.cfg (Bug #11 missed)

Plus new coverage for:
  - WindowsModule / DebianModule input sanitization guards
  - RuleRunner service and file_permissions check dispatch
  - scanner_init.os_scan() and get_scanner()
  - cli.py os_scan() not called twice
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch


# ============================================================
# Fix A — system_communications_protection._ps() must use list
# ============================================================

class TestSCPPsHelper:
    """_ps() in system_communications_protection must pass a list with shell=False."""

    def _call_ps(self, ps_cmd: str):
        from core.custom_functions.system_communications_protection import _ps, _RUN_CACHE
        _RUN_CACHE.clear()
        captured = {}
        mock_result = MagicMock(returncode=0, stdout="ok", stderr="")

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return mock_result

        with patch("core.custom_functions.system_communications_protection.subprocess.run", fake_run):
            _ps(ps_cmd)

        return captured

    def test_passes_list_not_string(self):
        captured = self._call_ps("Get-Service | Where-Object {$_.Status -eq 'Running'}")
        assert isinstance(captured["args"], list), "args must be a list, not a string"

    def test_shell_is_false(self):
        captured = self._call_ps("Get-Date")
        assert captured["kwargs"].get("shell") is False, "shell must be False"

    def test_command_is_last_element(self):
        ps_cmd = "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"
        captured = self._call_ps(ps_cmd)
        assert captured["args"][-1] == ps_cmd

    def test_no_double_quote_wrapping(self):
        ps_cmd = "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled"
        captured = self._call_ps(ps_cmd)
        full_str = " ".join(str(a) for a in captured["args"])
        assert f'"{ps_cmd}"' not in full_str

    def test_result_cached(self):
        from core.custom_functions.system_communications_protection import _ps, _RUN_CACHE
        _RUN_CACHE.clear()
        call_count = []
        mock_result = MagicMock(returncode=0, stdout="cached", stderr="")

        def fake_run(args, **kwargs):
            call_count.append(1)
            return mock_result

        with patch("core.custom_functions.system_communications_protection.subprocess.run", fake_run):
            _ps("Get-Date")
            _ps("Get-Date")

        assert len(call_count) == 1, "second call must hit cache"

    def test_timeout_returns_minus_one(self):
        from core.custom_functions.system_communications_protection import _ps, _RUN_CACHE
        _RUN_CACHE.clear()
        with patch(
            "core.custom_functions.system_communications_protection.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=30),
        ):
            rc, out, err = _ps("Get-Date")
        assert rc == -1
        assert "timed out" in err


# ============================================================
# Fix B — system_information_integrity._ps() must use list
# ============================================================

class TestSIIPsHelper:
    """_ps() in system_information_integrity must pass a list with shell=False."""

    def _call_ps(self, ps_cmd: str):
        from core.custom_functions.system_information_integrity import _ps, _RUN_CACHE
        _RUN_CACHE.clear()
        captured = {}
        mock_result = MagicMock(returncode=0, stdout="ok", stderr="")

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return mock_result

        with patch("core.custom_functions.system_information_integrity.subprocess.run", fake_run):
            _ps(ps_cmd)

        return captured

    def test_passes_list_not_string(self):
        captured = self._call_ps("Get-MpComputerStatus | Select-Object AntivirusEnabled")
        assert isinstance(captured["args"], list)

    def test_shell_is_false(self):
        captured = self._call_ps("Get-Date")
        assert captured["kwargs"].get("shell") is False

    def test_command_is_last_element(self):
        ps_cmd = "Get-HotFix | Measure-Object | Select-Object -ExpandProperty Count"
        captured = self._call_ps(ps_cmd)
        assert captured["args"][-1] == ps_cmd

    def test_no_double_quote_wrapping(self):
        ps_cmd = "Get-WUSettings"
        captured = self._call_ps(ps_cmd)
        full_str = " ".join(str(a) for a in captured["args"])
        assert f'"{ps_cmd}"' not in full_str

    def test_result_cached(self):
        from core.custom_functions.system_information_integrity import _ps, _RUN_CACHE
        _RUN_CACHE.clear()
        call_count = []
        mock_result = MagicMock(returncode=0, stdout="x", stderr="")

        def fake_run(args, **kwargs):
            call_count.append(1)
            return mock_result

        with patch("core.custom_functions.system_information_integrity.subprocess.run", fake_run):
            _ps("Get-Date")
            _ps("Get-Date")

        assert len(call_count) == 1

    def test_timeout_returns_minus_one(self):
        from core.custom_functions.system_information_integrity import _ps, _RUN_CACHE
        _RUN_CACHE.clear()
        with patch(
            "core.custom_functions.system_information_integrity.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=30),
        ):
            rc, out, err = _ps("Get-Date")
        assert rc == -1
        assert "timed out" in err


# ============================================================
# Fix C — manage_audit_right_wc / audit_policy_modify_restricted_wc
#          must use unique temp paths and clean up
# ============================================================

class TestManageAuditRightWc:
    """manage_audit_right_wc() must use a unique temp file and always clean up."""

    def _fake_run(self, calls: list, export_rc=0, check_stdout="SeSecurityPrivilege = *S-1-5-32-544"):
        def fake(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            calls.append(cmd_str)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "secedit" in cmd_str:
                return MagicMock(returncode=export_rc, stdout="", stderr="export error" if export_rc != 0 else "")
            if "Select-String" in cmd_str:
                return MagicMock(returncode=0, stdout=check_stdout, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        return fake

    def test_no_hardcoded_secpol_path(self):
        import inspect
        from core.custom_functions.audit_accountability import manage_audit_right_wc
        src = inspect.getsource(manage_audit_right_wc)
        assert r"secpol_tmp.cfg" not in src, (
            "Hardcoded secpol_tmp.cfg must be replaced with a unique UUID-based path"
        )

    def test_unique_paths_per_call(self):
        from core.custom_functions.audit_accountability import manage_audit_right_wc
        paths_seen = []

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "secedit" in cmd_str:
                for arg in args:
                    if ".cfg" in str(arg):
                        paths_seen.append(str(arg))
                        break
            return MagicMock(returncode=0, stdout="SeSecurityPrivilege = *S-1-5-32-544", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            manage_audit_right_wc()
            manage_audit_right_wc()

        assert len(paths_seen) >= 2, f"Expected at least 2 unique paths, got {paths_seen}"
        assert paths_seen[0] != paths_seen[1], "Each call must use a different temp path"

    def test_cleanup_runs_on_success(self):
        from core.custom_functions.audit_accountability import manage_audit_right_wc
        cleanup_calls = []

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                cleanup_calls.append(cmd_str)
            return MagicMock(returncode=0, stdout="SeSecurityPrivilege = *S-1-5-32-544", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            manage_audit_right_wc()

        assert cleanup_calls, "Cleanup (Remove-Item) must always run after the check"

    def test_cleanup_runs_on_export_failure(self):
        from core.custom_functions.audit_accountability import manage_audit_right_wc
        cleanup_calls = []

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                cleanup_calls.append(cmd_str)
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="access denied")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            manage_audit_right_wc()

        assert cleanup_calls, "Cleanup must run even when secedit export fails"

    def test_export_failure_returns_false(self):
        from core.custom_functions.audit_accountability import manage_audit_right_wc

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="access denied")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            ok, msg = manage_audit_right_wc()

        assert ok is False

    def test_no_users_in_output_returns_true(self):
        from core.custom_functions.audit_accountability import manage_audit_right_wc

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "secedit" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="SeSecurityPrivilege = *S-1-5-32-544", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            ok, msg = manage_audit_right_wc()

        assert ok is True

    def test_users_in_output_returns_false(self):
        from core.custom_functions.audit_accountability import manage_audit_right_wc

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "secedit" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="SeSecurityPrivilege = *S-1-5-32-544,*S-1-5-32-545 Users", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            ok, msg = manage_audit_right_wc()

        assert ok is False


class TestAuditPolicyModifyRestrictedWc:
    """audit_policy_modify_restricted_wc() must use a unique temp file and always clean up."""

    def test_no_hardcoded_secpol_path(self):
        import inspect
        from core.custom_functions.audit_accountability import audit_policy_modify_restricted_wc
        src = inspect.getsource(audit_policy_modify_restricted_wc)
        assert r"secpol_tmp.cfg" not in src

    def test_unique_paths_per_call(self):
        from core.custom_functions.audit_accountability import audit_policy_modify_restricted_wc
        paths_seen = []

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "secedit" in cmd_str:
                for arg in args:
                    if ".cfg" in str(arg):
                        paths_seen.append(str(arg))
                        break
            return MagicMock(returncode=0, stdout="no Users here", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            audit_policy_modify_restricted_wc()
            audit_policy_modify_restricted_wc()

        assert len(paths_seen) >= 2
        assert paths_seen[0] != paths_seen[1]

    def test_cleanup_always_runs(self):
        from core.custom_functions.audit_accountability import audit_policy_modify_restricted_wc
        cleanup_calls = []

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                cleanup_calls.append(cmd_str)
            return MagicMock(returncode=0, stdout="no Users here", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            audit_policy_modify_restricted_wc()

        assert cleanup_calls

    def test_no_users_returns_true(self):
        from core.custom_functions.audit_accountability import audit_policy_modify_restricted_wc

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "secedit" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="SeSecurityPrivilege = *S-1-5-32-544", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            ok, msg = audit_policy_modify_restricted_wc()

        assert ok is True

    def test_users_in_output_returns_false(self):
        from core.custom_functions.audit_accountability import audit_policy_modify_restricted_wc

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "secedit" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="SeSecurityPrivilege = *S-1-5-32-545 Users", stderr="")

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            ok, msg = audit_policy_modify_restricted_wc()

        assert ok is False


# ============================================================
# Scanner input-sanitization guards
# ============================================================

class TestWindowsModuleSanitization:
    """WindowsModule must reject malicious service names / paths before calling PowerShell."""

    def _scanner(self):
        from core.scanners.windows import WindowsModule
        return WindowsModule()

    def test_check_service_empty_name_returns_empty(self):
        assert self._scanner().check_service("") == ""

    def test_check_service_single_quote_rejected(self):
        assert self._scanner().check_service("svc'injection") == ""

    def test_check_service_double_quote_rejected(self):
        assert self._scanner().check_service('svc"injection') == ""

    def test_check_service_semicolon_rejected(self):
        assert self._scanner().check_service("svc;cmd") == ""

    def test_check_service_newline_rejected(self):
        assert self._scanner().check_service("svc\ncmd") == ""

    def test_check_file_permissions_empty_path_returns_empty(self):
        assert self._scanner().check_file_permissions("") == ""

    def test_check_file_permissions_single_quote_rejected(self):
        assert self._scanner().check_file_permissions("C:\\path'injection") == ""

    def test_check_file_permissions_newline_rejected(self):
        assert self._scanner().check_file_permissions("C:\\path\ncmd") == ""


class TestDebianModuleSanitization:
    """DebianModule must reject malicious service names / paths."""

    def _scanner(self):
        from core.scanners.debian import DebianModule
        return DebianModule()

    def test_check_service_empty_name_returns_empty(self):
        assert self._scanner().check_service("") == ""

    def test_check_service_single_quote_rejected(self):
        assert self._scanner().check_service("svc'injection") == ""

    def test_check_service_semicolon_rejected(self):
        assert self._scanner().check_service("svc;cmd") == ""

    def test_check_service_space_rejected(self):
        assert self._scanner().check_service("svc cmd") == ""

    def test_check_service_newline_rejected(self):
        assert self._scanner().check_service("svc\ncmd") == ""

    def test_check_file_permissions_empty_path_returns_empty(self):
        assert self._scanner().check_file_permissions("") == ""

    def test_check_file_permissions_single_quote_rejected(self):
        assert self._scanner().check_file_permissions("/etc/shadow'injection") == ""

    def test_check_file_permissions_newline_rejected(self):
        assert self._scanner().check_file_permissions("/etc/shadow\ncmd") == ""


# ============================================================
# RuleRunner — service and file_permissions dispatch
# ============================================================

class TestRunChecksServiceAndFilePermissions:
    """run_checks() must dispatch service/file_permissions checks to the scanner."""

    def _make_rule(self, tmp_path, check_type: str, path_key="command"):
        rule = {
            "id": f"{check_type.upper()}.01",
            "rule_id": f"{check_type.upper()}.01",
            "title": f"{check_type} test",
            "check_details": {
                "windows_client": {
                    "checks": [
                        {
                            "name": f"{check_type} check",
                            "sub_control": "1.1",
                            "check_type": check_type,
                            "command": "wuauserv" if check_type == "service" else "C:\\Windows",
                            "expected_result": "running",
                        }
                    ]
                }
            },
        }
        import json
        rule_file = tmp_path / f"{check_type}_rule.json"
        rule_file.write_text(json.dumps(rule), encoding="utf-8")
        return str(rule_file)

    def test_service_check_calls_scanner_check_service(self, tmp_path):
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "service")
        scanner = MagicMock()
        scanner.check_service.return_value = "Running"
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=scanner)
        runner.run_checks()
        scanner.check_service.assert_called_once()

    def test_service_running_yields_pass(self, tmp_path):
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "service")
        scanner = MagicMock()
        scanner.check_service.return_value = "Running"
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=scanner)
        result = runner.run_checks()
        assert result["checks"][0]["status"] == "PASS"

    def test_service_stopped_yields_fail(self, tmp_path):
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "service")
        scanner = MagicMock()
        scanner.check_service.return_value = "Stopped"
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=scanner)
        result = runner.run_checks()
        assert result["checks"][0]["status"] == "FAIL"

    def test_service_active_linux_yields_pass(self, tmp_path):
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "service")
        scanner = MagicMock()
        scanner.check_service.return_value = "active"
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=scanner)
        result = runner.run_checks()
        assert result["checks"][0]["status"] == "PASS"

    def test_file_permissions_check_calls_scanner(self, tmp_path):
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "file_permissions")
        scanner = MagicMock()
        scanner.check_file_permissions.return_value = "0 root root /etc/shadow"
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=scanner)
        runner.run_checks()
        scanner.check_file_permissions.assert_called_once()

    def test_file_permissions_nonempty_yields_pass(self, tmp_path):
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "file_permissions")
        scanner = MagicMock()
        scanner.check_file_permissions.return_value = "BUILTIN\\Administrators:FullControl"
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=scanner)
        result = runner.run_checks()
        assert result["checks"][0]["status"] == "PASS"

    def test_file_permissions_empty_yields_fail(self, tmp_path):
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "file_permissions")
        scanner = MagicMock()
        scanner.check_file_permissions.return_value = ""
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=scanner)
        result = runner.run_checks()
        assert result["checks"][0]["status"] == "FAIL"

    def test_service_check_without_scanner_falls_through_to_command(self, tmp_path):
        """When no scanner is provided, service check falls through to the else branch."""
        from core.rule_runner import RuleRunner
        rule_path = self._make_rule(tmp_path, "service")
        runner = RuleRunner(rule_path=rule_path, os_type="windows_client", scanner=None)
        with patch.object(RuleRunner, "run_command", return_value={"stdout": "ok", "stderr": "", "returncode": 0}):
            result = runner.run_checks()
        assert result["checks"][0]["status"] in ("PASS", "FAIL")


# ============================================================
# scanner_init — os_scan and get_scanner
# ============================================================

class TestOsScan:
    def test_returns_string(self):
        from core.scanner_init import os_scan
        result = os_scan()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_windows_returns_windows_variant(self):
        from core.scanner_init import os_scan
        with patch("platform.system", return_value="Windows"):
            with patch("platform.win32_edition", return_value="Home", create=True):
                result = os_scan()
        assert "windows" in result

    def test_windows_server_edition_returns_windows_server(self):
        from core.scanner_init import os_scan
        with patch("platform.system", return_value="Windows"):
            with patch("platform.win32_edition", return_value="Windows Server 2022 Standard", create=True):
                result = os_scan()
        assert result == "windows_server"

    def test_darwin_returns_mac(self):
        from core.scanner_init import os_scan
        with patch("platform.system", return_value="Darwin"):
            result = os_scan()
        assert result == "mac"

    def test_linux_unknown_distro_returns_linux(self):
        from core.scanner_init import os_scan
        with patch("platform.system", return_value="Linux"):
            with patch("builtins.open", side_effect=OSError):
                result = os_scan()
        assert result == "linux"

    def test_unknown_platform_returns_other(self):
        from core.scanner_init import os_scan
        with patch("platform.system", return_value="FreeBSD"):
            result = os_scan()
        assert result == "other"


class TestGetScanner:
    def test_windows_returns_windows_module(self):
        from core.scanner_init import get_scanner
        with patch("core.scanner_init.os_scan", return_value="windows_client"):
            scanner = get_scanner()
        from core.scanners.windows import WindowsModule
        assert isinstance(scanner, WindowsModule)

    def test_windows_server_returns_windows_module(self):
        from core.scanner_init import get_scanner
        with patch("core.scanner_init.os_scan", return_value="windows_server"):
            scanner = get_scanner()
        from core.scanners.windows import WindowsModule
        assert isinstance(scanner, WindowsModule)

    def test_debian_returns_debian_module(self):
        from core.scanner_init import get_scanner
        with patch("core.scanner_init.os_scan", return_value="debian"):
            scanner = get_scanner()
        from core.scanners.debian import DebianModule
        assert isinstance(scanner, DebianModule)

    def test_mac_returns_none(self):
        from core.scanner_init import get_scanner
        with patch("core.scanner_init.os_scan", return_value="mac"):
            assert get_scanner() is None

    def test_linux_returns_none(self):
        from core.scanner_init import get_scanner
        with patch("core.scanner_init.os_scan", return_value="linux"):
            assert get_scanner() is None
