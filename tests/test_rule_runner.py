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


class TestRunCustomFunction:
    def test_tuple_success(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = (True, "looks good")
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(mymod.my_func)")
        assert result["returncode"] == 0
        assert result["stdout"] == "looks good"

    def test_tuple_failure(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = (False, "not compliant")
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(mymod.my_func)")
        assert result["returncode"] == 1

    def test_bool_true_result(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = True
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(mymod.my_func)")
        assert result["returncode"] == 0

    def test_bool_false_result(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        mock_mod = MagicMock()
        mock_mod.my_func.return_value = False
        with patch("importlib.import_module", return_value=mock_mod):
            result = runner.run_custom_function("cs_f(mymod.my_func)")
        assert result["returncode"] == 1

    def test_invalid_syntax_returns_error(self, sample_rule_path):
        runner = RuleRunner(rule_path=sample_rule_path, os_type="windows_client")
        result = runner.run_custom_function("not_valid_syntax")
        assert result["returncode"] == -1
