"""
Tests for the eight medium/low-severity bug fixes:

  Bug #5  audit_accountability.py  _ps() used shell=True + string interpolation
  Bug #6  access_control.py        process_identity_wc() missing returncode check
  Bug #7  access_control.py        domain_joined_wc() fragile '.' check
  Bug #8  users.py                 enabled_local_users() used deprecated wmic
  Bug #9  cli.py                   SKIP/PARTIAL/ERROR shown as "False" in text output
  Bug #10 rule_runner.py           cs_f(name) single-token syntax gave cryptic error
  Bug #11 access_control.py        system_access_wc() hardcoded C:\\secpol.cfg race
  Bug #12 report_html.py           dead width:100% CSS declaration
"""
from __future__ import annotations

import json
import re
from io import StringIO
from unittest.mock import MagicMock, call, patch

import pytest


# ============================================================
# Bug #5 — _ps() must NOT use shell=True / string embedding
# ============================================================

class TestPsHelper:
    """_ps() should pass an argument list to subprocess.run with shell=False."""

    def test_passes_list_not_string(self):
        from core.custom_functions.audit_accountability import _ps, _RUN_CACHE
        _RUN_CACHE.clear()

        captured_calls = []
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "ok"
        mock_result.stderr = ""

        def fake_run(args, **kwargs):
            captured_calls.append((args, kwargs))
            return mock_result

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            _ps("Get-Service | Where-Object {$_.Status -eq 'Running'}")

        assert captured_calls, "subprocess.run was never called"
        args, kwargs = captured_calls[0]
        assert isinstance(args, list), "args must be a list, not a string"
        assert kwargs.get("shell") is False, "shell must be False"

    def test_command_is_last_list_element(self):
        """The PowerShell command string is the last element, not embedded in quotes."""
        from core.custom_functions.audit_accountability import _ps, _RUN_CACHE
        _RUN_CACHE.clear()

        ps_cmd = "Get-LocalUser | Where-Object {$_.Enabled}"
        captured = {}
        mock_result = MagicMock(returncode=0, stdout="", stderr="")

        def fake_run(args, **kwargs):
            captured["args"] = args
            return mock_result

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            _ps(ps_cmd)

        assert captured["args"][-1] == ps_cmd, (
            "PowerShell command must be passed as a plain list element, "
            "not embedded inside double-quotes"
        )

    def test_no_double_quote_wrapping(self):
        """Ensure the command is NOT wrapped in 'powershell ... \"{cmd}\"' form."""
        from core.custom_functions.audit_accountability import _ps, _RUN_CACHE
        _RUN_CACHE.clear()

        ps_cmd = 'auditpol /get /category:*'
        captured = {}
        mock_result = MagicMock(returncode=0, stdout="", stderr="")

        def fake_run(args, **kwargs):
            captured["args"] = args
            return mock_result

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            _ps(ps_cmd)

        full_str = " ".join(str(a) for a in captured["args"])
        assert f'"{ps_cmd}"' not in full_str, (
            "Command must NOT be embedded inside double-quotes in the arg list"
        )

    def test_result_cached_by_command(self):
        """Repeated calls with the same command return cached result."""
        from core.custom_functions.audit_accountability import _ps, _RUN_CACHE
        _RUN_CACHE.clear()

        mock_result = MagicMock(returncode=0, stdout="cached", stderr="")
        call_count = []

        def fake_run(args, **kwargs):
            call_count.append(1)
            return mock_result

        with patch("core.custom_functions.audit_accountability.subprocess.run", fake_run):
            r1 = _ps("Get-Date")
            r2 = _ps("Get-Date")

        assert len(call_count) == 1, "second identical call should hit cache"
        assert r1 == r2

    def test_timeout_returns_minus_one(self):
        from core.custom_functions.audit_accountability import _ps, _RUN_CACHE
        import subprocess as sp
        _RUN_CACHE.clear()

        with patch(
            "core.custom_functions.audit_accountability.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="ps", timeout=30),
        ):
            rc, out, err = _ps("Get-Date")

        assert rc == -1
        assert "timed out" in err


# ============================================================
# Bug #6 — process_identity_wc() returncode check + safe parse
# ============================================================

class TestProcessIdentityWc:
    def _call(self, returncode: int, stdout: str):
        from core.custom_functions.access_control import process_identity_wc
        fake = {"returncode": returncode, "stdout": stdout, "stderr": ""}
        with patch("core.custom_functions.access_control.run_command", return_value=fake):
            return process_identity_wc()

    def test_command_failure_returns_false(self):
        result = self._call(1, "")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_invalid_json_returns_false(self):
        result = self._call(0, "not json }{")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_all_services_named_returns_true(self):
        services = [{"Name": "wuauserv", "StartName": "LocalSystem", "State": "Running"}]
        result = self._call(0, json.dumps(services))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is True

    def test_blank_start_name_returns_false(self):
        services = [
            {"Name": "svc1", "StartName": "LocalSystem", "State": "Running"},
            {"Name": "svc2", "StartName": "",             "State": "Running"},
        ]
        result = self._call(0, json.dumps(services))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_single_dict_not_list_handled(self):
        """ConvertTo-Json returns a dict (not list) when exactly one service exists."""
        svc = {"Name": "wuauserv", "StartName": "NT AUTHORITY\\LocalService", "State": "Running"}
        result = self._call(0, json.dumps(svc))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is True


# ============================================================
# Bug #7 — domain_joined_wc() uses PartOfDomain, not "." check
# ============================================================

class TestDomainJoinedWc:
    def _call(self, returncode: int, stdout: str):
        from core.custom_functions.access_control import domain_joined_wc
        fake = {"returncode": returncode, "stdout": stdout, "stderr": ""}
        with patch("core.custom_functions.access_control.run_command", return_value=fake):
            return domain_joined_wc()

    def test_true_output_returns_true(self):
        result = self._call(0, "True")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is True

    def test_false_output_returns_false(self):
        result = self._call(0, "False")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_ip_address_in_output_does_not_pass(self):
        """Old code: '192.168.1.1' contains '.' → passed wrongly. New code must not."""
        result = self._call(0, "192.168.1.1")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_error_output_does_not_pass(self):
        """Old code: 'Error: WORKGROUP.local' contains '.' → passed wrongly."""
        result = self._call(0, "Error: WORKGROUP.local could not be resolved")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_command_failure_returns_false(self):
        result = self._call(1, "")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_uses_partof_domain_command(self):
        """Verify the command queries PartOfDomain, not Domain."""
        from core.custom_functions.access_control import domain_joined_wc
        captured = {}
        fake = {"returncode": 0, "stdout": "True", "stderr": ""}

        def fake_run(cmd):
            captured["cmd"] = cmd
            return fake

        with patch("core.custom_functions.access_control.run_command", fake_run):
            domain_joined_wc()

        assert "PartOfDomain" in captured.get("cmd", ""), (
            "Command must query PartOfDomain, not the Domain field"
        )


# ============================================================
# Bug #8 — enabled_local_users() uses Get-LocalUser, not wmic
# ============================================================

class TestEnabledLocalUsers:
    def test_does_not_invoke_wmic(self):
        """wmic must not be passed as an argument to subprocess.run."""
        from core.custom_functions.users import enabled_local_users
        captured_args = []
        mock_result = MagicMock(returncode=0, stdout="[]", stderr="")

        def fake_run(args, **kwargs):
            captured_args.extend(args if isinstance(args, (list, tuple)) else [args])
            return mock_result

        with patch("core.custom_functions.users.subprocess.run", fake_run):
            enabled_local_users()

        assert "wmic" not in [str(a).lower() for a in captured_args], (
            "wmic must not be passed as a subprocess argument"
        )

    def test_uses_get_local_user(self):
        from core.custom_functions import users
        import inspect
        src = inspect.getsource(users.enabled_local_users)
        assert "Get-LocalUser" in src, "Get-LocalUser must be used instead of wmic"

    def test_success_returns_true_and_output(self):
        from core.custom_functions.users import enabled_local_users
        mock_result = MagicMock(returncode=0, stdout='[{"Name":"Alice"}]', stderr="")
        with patch("core.custom_functions.users.subprocess.run", return_value=mock_result):
            ok, out = enabled_local_users()
        assert ok is True
        assert "Alice" in out

    def test_failure_returns_false(self):
        from core.custom_functions.users import enabled_local_users
        mock_result = MagicMock(returncode=1, stdout="", stderr="access denied")
        with patch("core.custom_functions.users.subprocess.run", return_value=mock_result):
            ok, msg = enabled_local_users()
        assert ok is False

    def test_exception_returns_false(self):
        from core.custom_functions.users import enabled_local_users
        with patch("core.custom_functions.users.subprocess.run", side_effect=OSError("no ps")):
            ok, msg = enabled_local_users()
        assert ok is False
        assert "no ps" in msg


# ============================================================
# Bug #9 — cli text output: correct labels for all statuses
# ============================================================

class TestTextOutputLabels:
    """_print_text_summary must print accurate labels, not "False" for SKIP/etc."""

    def _make_result(self, status: str) -> dict:
        return {
            "rule_id": "X.01",
            "title":   "Test",
            "checks": [
                {"status": status, "check_name": "check one",
                 "command": "echo", "expected_result": "", "returncode": 0,
                 "stdout": "", "stderr": ""},
            ],
        }

    def _capture(self, status: str) -> str:
        import cli
        import io, sys
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            cli._print_text_summary({"p": self._make_result(status)}, detail_mode="status_only")
        finally:
            sys.stdout = old
        return buf.getvalue()

    def test_pass_shows_true(self):
        out = self._capture("PASS")
        assert "True" in out

    def test_fail_shows_false(self):
        out = self._capture("FAIL")
        assert "False" in out

    def test_skip_does_not_show_false(self):
        out = self._capture("SKIP")
        # "False" must NOT appear for a SKIP check
        assert "False" not in out

    def test_partial_does_not_show_false(self):
        out = self._capture("PARTIAL")
        assert "False" not in out

    def test_error_does_not_show_false(self):
        out = self._capture("ERROR")
        assert "False" not in out

    def test_skip_shows_skip_label(self):
        out = self._capture("SKIP")
        assert "Skip" in out

    def test_partial_shows_part_label(self):
        out = self._capture("PARTIAL")
        assert "Part" in out

    def test_error_shows_error_label(self):
        out = self._capture("ERROR")
        assert "Error" in out


# ============================================================
# Bug #10 — cs_f() single-token syntax raises a clear error
# ============================================================

class TestCsFSingleToken:
    def _runner(self, sample_rule_path):
        from core.rule_runner import RuleRunner
        return RuleRunner(rule_path=sample_rule_path, os_type="windows_client")

    def test_no_dot_raises_value_error(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        result = runner.run_custom_function("cs_f(just_function_name)")
        # The ValueError is caught internally; returncode is -1 and stderr has the message
        assert result["returncode"] == -1
        assert "module prefix" in result["stderr"].lower() or "module" in result["stderr"].lower()

    def test_with_module_prefix_still_works(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = (True, "ok")
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(mymod.my_func)")
        assert result["returncode"] == 0

    def test_error_message_is_informative(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        result = runner.run_custom_function("cs_f(oops_no_module)")
        assert "cs_f(" in result["stderr"] or "module" in result["stderr"].lower(), (
            f"Error message should mention module prefix requirement; got: {result['stderr']}"
        )


# ============================================================
# Bug #11 — system_access_wc() uses a unique temp path
# ============================================================

class TestSystemAccessWc:
    """Verify no hardcoded C:\\secpol.cfg path and that cleanup always runs."""

    def test_no_hardcoded_secpol_path(self):
        from core.custom_functions import access_control
        import inspect
        src = inspect.getsource(access_control.system_access_wc)
        assert r"C:\secpol.cfg" not in src, (
            "Hardcoded C:\\secpol.cfg must be replaced with a unique temp path"
        )

    def test_unique_paths_per_call(self):
        """Two simultaneous calls must not use the same cfg path."""
        from core.custom_functions.access_control import system_access_wc
        paths_used = []

        def fake_run(args, **kwargs):
            # Capture the path argument from the secedit export command
            cmd_str = " ".join(str(a) for a in args)
            if "secedit" in cmd_str:
                # Extract the path from the command
                for arg in args:
                    if ".cfg" in str(arg):
                        paths_used.append(arg)
                        break
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("core.custom_functions.access_control.subprocess.run", fake_run):
            system_access_wc()
            system_access_wc()

        assert len(paths_used) >= 2, (
            "Expected at least 2 secedit cfg paths to be captured across two calls "
            f"(got {paths_used})"
        )
        assert paths_used[0] != paths_used[1], (
            "Each call must use a different temp file path to avoid race conditions"
        )

    def test_cleanup_runs_on_success(self):
        """Remove-Item must be called even when the check passes."""
        from core.custom_functions.access_control import system_access_wc
        cleanup_calls = []

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                cleanup_calls.append(cmd_str)
            return MagicMock(returncode=0, stdout="match found", stderr="")

        with patch("core.custom_functions.access_control.subprocess.run", fake_run):
            system_access_wc()

        assert cleanup_calls, "Cleanup (Remove-Item) must always run after the check"

    def test_cleanup_runs_on_failure(self):
        """Remove-Item must also run when the export step fails."""
        from core.custom_functions.access_control import system_access_wc
        cleanup_calls = []

        def fake_run(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "Remove-Item" in cmd_str or "Test-Path" in cmd_str:
                cleanup_calls.append(cmd_str)
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="access denied")

        with patch("core.custom_functions.access_control.subprocess.run", fake_run):
            system_access_wc()

        assert cleanup_calls, "Cleanup must run even when secedit export fails"


# ============================================================
# Bug #12 — report_html.py: no dead width:100% in CSS
# ============================================================

class TestHtmlCss:
    def _get_css(self) -> str:
        from ui.report_html import _CSS
        return _CSS

    def test_no_duplicate_width_in_checks_tbl(self):
        """The checks-tbl rule must not declare width twice."""
        css = self._get_css()
        # Find the .checks-tbl rule block
        match = re.search(r"\.checks-tbl\{([^}]+)\}", css)
        assert match, ".checks-tbl rule not found in CSS"
        rule_body = match.group(1)
        width_declarations = re.findall(r"\bwidth\s*:", rule_body)
        assert len(width_declarations) == 1, (
            f"Expected exactly 1 width declaration in .checks-tbl, "
            f"found {len(width_declarations)}: {rule_body}"
        )

    def test_calc_width_is_present(self):
        """The effective width:calc(100% - 32px) must still be there."""
        css = self._get_css()
        assert "calc(100% - 32px)" in css

    def test_bare_width_100_not_in_checks_tbl(self):
        """width:100% must not appear in .checks-tbl (only calc form is correct)."""
        css = self._get_css()
        match = re.search(r"\.checks-tbl\{([^}]+)\}", css)
        assert match
        rule_body = match.group(1)
        assert "width:100%" not in rule_body.replace(" ", "")


# ============================================================
# local_administrators_group() in users.py
# ============================================================

class TestLocalAdministratorsGroup:
    """local_administrators_group() must use 'net localgroup' and handle errors correctly."""

    def test_success_returns_true_and_output(self):
        from core.custom_functions.users import local_administrators_group
        mock_result = MagicMock(returncode=0, stdout="Administrator\nUser1\n", stderr="")
        with patch("core.custom_functions.users.subprocess.run", return_value=mock_result):
            ok, out = local_administrators_group()
        assert ok is True
        assert "Administrator" in out

    def test_nonzero_returncode_returns_false(self):
        from core.custom_functions.users import local_administrators_group
        mock_result = MagicMock(returncode=1, stdout="", stderr="access denied")
        with patch("core.custom_functions.users.subprocess.run", return_value=mock_result):
            ok, msg = local_administrators_group()
        assert ok is False
        assert "access denied" in msg

    def test_exception_returns_false(self):
        from core.custom_functions.users import local_administrators_group
        with patch("core.custom_functions.users.subprocess.run", side_effect=OSError("no net")):
            ok, msg = local_administrators_group()
        assert ok is False
        assert "no net" in msg

    def test_uses_net_localgroup_command(self):
        from core.custom_functions.users import local_administrators_group
        captured = {}
        mock_result = MagicMock(returncode=0, stdout="", stderr="")

        def fake_run(args, **kwargs):
            captured["args"] = args
            return mock_result

        with patch("core.custom_functions.users.subprocess.run", fake_run):
            local_administrators_group()

        assert "net" in [str(a).lower() for a in captured.get("args", [])], (
            "Must invoke 'net' command"
        )
        assert "localgroup" in [str(a).lower() for a in captured.get("args", [])], (
            "Must use 'localgroup' subcommand"
        )
