"""Tests for core.rule_runner.RuleRunner."""
import pytest
from unittest.mock import patch, MagicMock

from core.rule_runner import RuleRunner


class TestRuleLoading:
    def test_loads_valid_rule(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        assert runner.rule["id"] == "TEST.01"
        assert runner.rule["title"] == "Sample Test Rule"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            RuleRunner(rule_path=str(tmp_path / "nope.json"), os_type="windows_client")

    def test_os_type_stored(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="linux")
        assert runner.os_type == "linux"


class TestGetChecks:
    def test_returns_checks_for_known_os(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        checks = runner.get_checks()
        assert isinstance(checks, list)
        assert len(checks) == 3

    def test_returns_empty_for_unknown_os(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="mac")
        assert runner.get_checks() == []


class TestIsNaCheck:
    def test_na_uppercase(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        assert runner._is_na_check({"command": "NA"}) is True

    def test_na_lowercase(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        assert runner._is_na_check({"command": "na"}) is True

    def test_none_command_is_na(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        assert runner._is_na_check({"command": None}) is True

    def test_real_command_is_not_na(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        assert runner._is_na_check({"command": "echo test"}) is False


class TestRunChecks:
    _PASS = {"stdout": "ok", "stderr": "", "returncode": 0}
    _FAIL = {"stdout": "", "stderr": "err", "returncode": 1}

    def _runner(self, sample_rule_path, os_type="windows_client"):
        return RuleRunner(rule_path=sample_rule_path, os_type=os_type, scanner=MagicMock())

    def test_result_has_required_keys(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        with patch.object(RuleRunner, "run_command", return_value=self._PASS):
            result = runner.run_checks()
        for key in ("rule_id", "title", "os", "checks", "checks_run", "checks_skipped", "checks_policy"):
            assert key in result

    def test_pass_on_zero_returncode(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        with patch.object(RuleRunner, "run_command", return_value=self._PASS):
            result = runner.run_checks()
        automated = [c for c in result["checks"] if c["status"] != "POLICY"]
        assert all(c["status"] == "PASS" for c in automated)

    def test_fail_on_nonzero_returncode(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        with patch.object(RuleRunner, "run_command", return_value=self._FAIL):
            result = runner.run_checks()
        automated = [c for c in result["checks"] if c["status"] != "POLICY"]
        assert all(c["status"] == "FAIL" for c in automated)

    def test_na_checks_counted_as_skipped(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        with patch.object(RuleRunner, "run_command", return_value=self._PASS):
            result = runner.run_checks()
        assert result["checks_skipped"] == 1

    def test_policy_checks_counted(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        with patch.object(RuleRunner, "run_command", return_value=self._PASS):
            result = runner.run_checks()
        assert result["checks_policy"] == 1

    def test_policy_checks_appear_in_checks_list(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        with patch.object(RuleRunner, "run_command", return_value=self._PASS):
            result = runner.run_checks()
        policy = [c for c in result["checks"] if c["status"] == "POLICY"]
        assert len(policy) == 1

    def test_rule_id_populated(self, sample_rule_path):
        runner = self._runner(sample_rule_path)
        with patch.object(RuleRunner, "run_command", return_value=self._PASS):
            result = runner.run_checks()
        assert result["rule_id"] == "TEST.01"


class TestRunCommand:
    """RuleRunner.run_command() — direct execution (not mocked)."""

    def test_returns_required_keys(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        with patch("subprocess.run", return_value=MagicMock(
            stdout="hello\n", stderr="", returncode=0
        )):
            result = runner.run_command("echo hello")
        for key in ("stdout", "stderr", "returncode"):
            assert key in result

    def test_timeout_returns_minus_one(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        import subprocess as sp
        with patch("subprocess.run", side_effect=sp.TimeoutExpired(cmd="x", timeout=60)):
            result = runner.run_command("echo slow")
        assert result["returncode"] == -1
        assert "timed out" in result["stderr"]

    def test_exception_returns_minus_one(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        with patch("subprocess.run", side_effect=OSError("no shell")):
            result = runner.run_command("echo boom")
        assert result["returncode"] == -1
        assert "no shell" in result["stderr"]

    def test_nonzero_returncode_captured(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        with patch("subprocess.run", return_value=MagicMock(
            stdout="", stderr="bad command", returncode=1
        )):
            result = runner.run_command("bad_cmd")
        assert result["returncode"] == 1


class TestRunChecksWithCsF:
    """run_checks() must dispatch cs_f(...) commands through run_custom_function, not run_command."""

    def test_csf_command_dispatched_to_custom_function(self, tmp_path):
        rule = {
            "id": "CSF.01", "rule_id": "CSF.01", "title": "CSF test",
            "check_details": {
                "windows_client": {
                    "checks": [
                        {
                            "name": "custom fn check",
                            "sub_control": "1.1",
                            "check_type": "command",
                            "command": "cs_f(access_control.my_func)",
                            "expected_result": "pass",
                        }
                    ]
                }
            }
        }
        import json
        rule_file = tmp_path / "csf_rule.json"
        rule_file.write_text(json.dumps(rule), encoding="utf-8")

        runner = RuleRunner(rule_path=str(rule_file), os_type="windows_client", scanner=MagicMock())

        custom_fn_called = []

        def fake_custom(func_call):
            custom_fn_called.append(func_call)
            return {"stdout": "ok", "stderr": "", "returncode": 0}

        with patch.object(runner, "run_custom_function", side_effect=fake_custom):
            with patch.object(runner, "run_command") as mock_cmd:
                runner.run_checks()

        assert custom_fn_called, "run_custom_function must be called for cs_f() commands"
        mock_cmd.assert_not_called()


class TestRunCustomFunction:
    def test_tuple_success(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = (True, "looks good")
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(access_control.my_func)")
        assert result["returncode"] == 0
        assert result["stdout"] == "looks good"

    def test_tuple_failure(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = (False, "not compliant")
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(access_control.my_func)")
        assert result["returncode"] == 1

    def test_bool_true_result(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = True
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(access_control.my_func)")
        assert result["returncode"] == 0

    def test_bool_false_result(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = False
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(access_control.my_func)")
        assert result["returncode"] == 1

    def test_invalid_syntax_returns_error(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        result = runner.run_custom_function("not_valid_syntax")
        assert result["returncode"] == -1
