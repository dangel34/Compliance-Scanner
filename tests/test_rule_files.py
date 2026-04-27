"""Validates every rule file in rulesets/ is well-formed JSON with required fields."""
import json
import os

import pytest

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CMMC_DIR = os.path.join(_PROJECT_ROOT, "rulesets", "CMMC Level 1 & 2")
_SOC2_DIR = os.path.join(_PROJECT_ROOT, "rulesets", "SOC 2")

_SKIP_NAMES = {"rule_schema.json", "rule_template.json"}
_REQUIRED_FIELDS = {
    "id", "control_number", "title", "description",
    "category", "target_os", "check_details", "severity", "remediation", "tags",
}
_VALID_OS_KEYS = {"windows_client", "windows_server", "linux", "debian"}
_VALID_CHECK_TYPES = {"command", "service", "file_permissions", "policy"}
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def _collect(directory: str) -> list[str]:
    if not os.path.isdir(directory):
        return []
    return sorted(
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.endswith(".json") and f not in _SKIP_NAMES
    )


_CMMC_RULES = _collect(_CMMC_DIR)
_SOC2_RULES = _collect(_SOC2_DIR)
_ALL_RULES = _CMMC_RULES + _SOC2_RULES


@pytest.mark.parametrize("path", _ALL_RULES, ids=os.path.basename)
def test_rule_is_valid_json(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, dict)


@pytest.mark.parametrize("path", _ALL_RULES, ids=os.path.basename)
def test_rule_has_required_fields(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    missing = _REQUIRED_FIELDS - data.keys()
    assert not missing, f"Missing fields: {missing}"


@pytest.mark.parametrize("path", _ALL_RULES, ids=os.path.basename)
def test_rule_severity_is_valid(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("severity") in _VALID_SEVERITIES


@pytest.mark.parametrize("path", _ALL_RULES, ids=os.path.basename)
def test_rule_check_details_structure(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    check_details = data.get("check_details", {})
    assert isinstance(check_details, dict), "check_details must be a dict"
    for os_key, os_block in check_details.items():
        assert os_key in _VALID_OS_KEYS, f"Unknown OS key: {os_key}"
        assert "checks" in os_block, f"OS block '{os_key}' missing 'checks'"
        assert isinstance(os_block["checks"], list)
        for check in os_block["checks"]:
            assert "name" in check, f"Check in '{os_key}' missing 'name'"
            assert "command" in check, f"Check in '{os_key}' missing 'command'"
            assert "check_type" in check, f"Check in '{os_key}' missing 'check_type'"
            assert check["check_type"] in _VALID_CHECK_TYPES, (
                f"Invalid check_type '{check['check_type']}' in '{os_key}'"
            )


@pytest.mark.parametrize("path", _ALL_RULES, ids=os.path.basename)
def test_rule_target_os_is_list(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data.get("target_os"), list)
    assert len(data["target_os"]) > 0
