"""Tests for ui.utils helper functions."""
from ui.utils import _safe_str, get_rule_status, format_os_name


class TestSafeStr:
    def test_strips_ansi_codes(self):
        assert _safe_str("\x1b[31mred\x1b[0m") == "red"

    def test_strips_control_chars(self):
        assert _safe_str("hello\x00world") == "helloworld"

    def test_strips_unicode_controls(self):
        assert _safe_str("hello​world") == "helloworld"

    def test_truncates_at_max_len(self):
        assert len(_safe_str("x" * 1000, max_len=10)) == 10

    def test_none_becomes_empty_string(self):
        assert _safe_str(None) == ""

    def test_normal_string_unchanged(self):
        assert _safe_str("hello world") == "hello world"

    def test_int_coerced_to_string(self):
        assert _safe_str(42) == "42"


class TestGetRuleStatus:
    def test_none_returns_not_run(self):
        assert get_rule_status(None) == "NOT_RUN"

    def test_error_key_returns_error(self):
        assert get_rule_status({"error": "crashed", "checks": []}) == "ERROR"

    def test_empty_checks_returns_skip(self):
        assert get_rule_status({"checks": []}) == "SKIP"

    def test_all_pass_returns_pass(self):
        result = {"checks": [{"status": "PASS"}, {"status": "PASS"}]}
        assert get_rule_status(result) == "PASS"

    def test_all_fail_returns_fail(self):
        result = {"checks": [{"status": "FAIL"}, {"status": "FAIL"}]}
        assert get_rule_status(result) == "FAIL"

    def test_mixed_returns_partial(self):
        result = {"checks": [{"status": "PASS"}, {"status": "FAIL"}]}
        assert get_rule_status(result) == "PARTIAL"

    def test_all_policy_returns_policy(self):
        result = {"checks": [{"status": "POLICY"}]}
        assert get_rule_status(result) == "POLICY"

    def test_policy_excluded_from_pass_calculation(self):
        result = {"checks": [{"status": "PASS"}, {"status": "POLICY"}]}
        assert get_rule_status(result) == "PASS"

    def test_policy_excluded_from_fail_calculation(self):
        result = {"checks": [{"status": "FAIL"}, {"status": "POLICY"}]}
        assert get_rule_status(result) == "FAIL"


class TestFormatOsName:
    def test_underscore_becomes_space(self):
        assert format_os_name("windows_client") == "Windows Client"

    def test_single_word_titlecased(self):
        assert format_os_name("linux") == "Linux"

    def test_windows_server(self):
        assert format_os_name("windows_server") == "Windows Server"
