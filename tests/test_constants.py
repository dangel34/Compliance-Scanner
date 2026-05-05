"""
Tests verifying module-level constants extracted to fix SonarQube S1192
(duplicate string literals) across core and ui modules.
"""
from __future__ import annotations


class TestAuditAccountabilityConstants:
    def test_auditd_conf_path(self):
        from core.custom_functions.audit_accountability import _AUDITD_CONF
        assert _AUDITD_CONF == "/etc/audit/auditd.conf"

    def test_auditd_not_found_message(self):
        from core.custom_functions.audit_accountability import _AUDITD_CONF, _AUDITD_NOT_FOUND
        assert _AUDITD_NOT_FOUND == f"auditd.conf not found: {_AUDITD_CONF} does not exist"
        assert "/etc/audit/auditd.conf" in _AUDITD_NOT_FOUND

    def test_not_found_message_references_conf_path(self):
        from core.custom_functions.audit_accountability import _AUDITD_CONF, _AUDITD_NOT_FOUND
        assert _AUDITD_CONF in _AUDITD_NOT_FOUND


class TestConfigurationManagementConstants:
    def test_aide_db_path(self):
        from core.custom_functions.configuration_management import _AIDE_DB
        assert _AIDE_DB == "/var/lib/aide/aide.db"

    def test_not_set_value(self):
        from core.custom_functions.configuration_management import _NOT_SET
        assert _NOT_SET == "not set"

    def test_not_set_is_non_empty_string(self):
        from core.custom_functions.configuration_management import _NOT_SET
        assert isinstance(_NOT_SET, str) and len(_NOT_SET) > 0

    def test_aide_db_is_absolute_path(self):
        from core.custom_functions.configuration_management import _AIDE_DB
        assert _AIDE_DB.startswith("/") and "aide" in _AIDE_DB


class TestIdentificationAuthenticationConstants:
    def test_hklm_policies_system_path(self):
        from core.custom_functions.identification_authentication import _HKLM_POLICIES_SYSTEM
        assert _HKLM_POLICIES_SYSTEM == r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    def test_hklm_path_contains_backslashes(self):
        from core.custom_functions.identification_authentication import _HKLM_POLICIES_SYSTEM
        assert "\\" in _HKLM_POLICIES_SYSTEM
        assert "SOFTWARE" in _HKLM_POLICIES_SYSTEM
        assert "Policies" in _HKLM_POLICIES_SYSTEM


class TestSystemCommunicationsProtectionConstants:
    def test_deny_incoming(self):
        from core.custom_functions.system_communications_protection import _DENY_INCOMING
        assert _DENY_INCOMING == "deny (incoming)"

    def test_ufw_deny_msg(self):
        from core.custom_functions.system_communications_protection import _UFW_DENY_MSG
        assert _UFW_DENY_MSG == "ufw default incoming policy is deny"

    def test_sshd_config_path(self):
        from core.custom_functions.system_communications_protection import _SSHD_CONFIG
        assert _SSHD_CONFIG == "/etc/ssh/sshd_config"

    def test_conf_glob_pattern(self):
        from core.custom_functions.system_communications_protection import _CONF_GLOB
        assert _CONF_GLOB == "*.conf"

    def test_manage_bde_command(self):
        from core.custom_functions.system_communications_protection import _MANAGE_BDE_C
        assert _MANAGE_BDE_C == "manage-bde -status C: 2>nul"

    def test_protection_on_string(self):
        from core.custom_functions.system_communications_protection import _PROTECTION_ON
        assert _PROTECTION_ON == "protection on"


class TestReportCsvConstants:
    def test_col_rule_id(self):
        from ui.report_csv import _COL_RULE_ID
        assert _COL_RULE_ID == "Rule ID"

    def test_col_overall_status(self):
        from ui.report_csv import _COL_OVERALL_STATUS
        assert _COL_OVERALL_STATUS == "Overall Status"

    def test_col_check_num(self):
        from ui.report_csv import _COL_CHECK_NUM
        assert _COL_CHECK_NUM == "Check #"

    def test_col_check_name(self):
        from ui.report_csv import _COL_CHECK_NAME
        assert _COL_CHECK_NAME == "Check Name"

    def test_col_expected(self):
        from ui.report_csv import _COL_EXPECTED
        assert _COL_EXPECTED == "Expected Result"

    def test_col_return_code(self):
        from ui.report_csv import _COL_RETURN_CODE
        assert _COL_RETURN_CODE == "Return Code"

    def test_all_col_constants_in_csv_fields(self):
        from ui.report_csv import (
            _CSV_FIELDS, _COL_RULE_ID, _COL_OVERALL_STATUS,
            _COL_CHECK_NUM, _COL_CHECK_NAME, _COL_EXPECTED, _COL_RETURN_CODE,
        )
        for col in (_COL_RULE_ID, _COL_OVERALL_STATUS, _COL_CHECK_NUM,
                    _COL_CHECK_NAME, _COL_EXPECTED, _COL_RETURN_CODE):
            assert col in _CSV_FIELDS

    def test_csv_field_values_unchanged(self):
        from ui.report_csv import _CSV_FIELDS
        assert "Rule ID" in _CSV_FIELDS
        assert "Overall Status" in _CSV_FIELDS
        assert "Check #" in _CSV_FIELDS
        assert "Check Name" in _CSV_FIELDS
        assert "Expected Result" in _CSV_FIELDS
        assert "Return Code" in _CSV_FIELDS
