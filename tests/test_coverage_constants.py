"""
Tests that exercise the function bodies which contain the module-level
constants extracted during the SonarQube S1192 refactoring.

Importing a module covers its constant-definition lines; these tests
cover the USE SITES inside function bodies so that SonarQube's new-code
coverage metric reflects the constant references being executed.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

MOD_AA  = "core.custom_functions.audit_accountability"
MOD_CM  = "core.custom_functions.configuration_management"
MOD_SCP = "core.custom_functions.system_communications_protection"


def _absent_path():
    """Return a mock Path whose .exists() is False."""
    m = MagicMock()
    m.exists.return_value = False
    return m


# ---------------------------------------------------------------------------
# configuration_management.py — _NOT_SET
# ---------------------------------------------------------------------------

class TestSmbSigningWsNotSet:
    """smb_signing_ws() uses _NOT_SET when RequireSecuritySignature is missing."""

    def _call(self, reg_value):
        with patch(f"{MOD_CM}._reg_get", return_value=reg_value):
            from core.custom_functions.configuration_management import smb_signing_ws
            return smb_signing_ws()

    def test_signing_required_passes(self):
        ok, _ = self._call("1")
        assert ok

    def test_signing_disabled_fails_with_actual_value(self):
        ok, msg = self._call("0")
        assert not ok
        assert "0" in msg

    def test_missing_registry_key_shows_not_set(self):
        ok, msg = self._call("")
        assert not ok
        assert "not set" in msg

    def test_none_registry_key_shows_not_set(self):
        ok, msg = self._call(None)
        assert not ok
        assert "not set" in msg


class TestPasswordPolicyLxNotSet:
    """password_policy_lx() uses _NOT_SET when pwquality settings are absent."""

    def _mock_path(self, exists: bool, content: str = ""):
        m = MagicMock()
        m.exists.return_value = exists
        m.read_text.return_value = content
        return m

    def test_conf_not_found_returns_false(self):
        with patch(f"{MOD_CM}.Path", return_value=self._mock_path(False)):
            from core.custom_functions.configuration_management import password_policy_lx
            ok, msg = password_policy_lx()
        assert not ok
        assert "not found" in msg

    def test_missing_minlen_shows_not_set(self):
        content = "# no minlen setting\nminclass = 4\n"
        with patch(f"{MOD_CM}.Path", return_value=self._mock_path(True, content)):
            from core.custom_functions.configuration_management import password_policy_lx
            ok, msg = password_policy_lx()
        assert not ok
        assert "not set" in msg

    def test_minlen_too_low_shows_value(self):
        content = "minlen = 8\nminclass = 4\n"
        with patch(f"{MOD_CM}.Path", return_value=self._mock_path(True, content)):
            from core.custom_functions.configuration_management import password_policy_lx
            ok, msg = password_policy_lx()
        assert not ok
        assert "8" in msg

    def test_missing_minclass_shows_not_set(self):
        content = "minlen = 14\n# no minclass\n"
        with patch(f"{MOD_CM}.Path", return_value=self._mock_path(True, content)):
            from core.custom_functions.configuration_management import password_policy_lx
            ok, msg = password_policy_lx()
        assert not ok
        assert "not set" in msg

    def test_valid_policy_passes(self):
        content = "minlen = 14\nminclass = 3\n"
        with patch(f"{MOD_CM}.Path", return_value=self._mock_path(True, content)):
            from core.custom_functions.configuration_management import password_policy_lx
            ok, _ = password_policy_lx()
        assert ok


class TestSshHardeningLxNotSet:
    """ssh_hardening_lx() uses _NOT_SET when an expected setting is absent."""

    def _call(self, run_output: str, rc: int = 0):
        with patch(f"{MOD_CM}._run", return_value=(rc, run_output, "")):
            from core.custom_functions.configuration_management import ssh_hardening_lx
            return ssh_hardening_lx()

    def test_sshd_unavailable_fails(self):
        ok, _ = self._call("", rc=1)
        assert not ok

    def test_all_settings_correct_passes(self):
        out = "permitrootlogin no\npermitemptypasswords no\nprotocol 2\n"
        ok, _ = self._call(out)
        assert ok

    def test_missing_setting_shows_not_set(self):
        # Only one setting present → the absent ones use _NOT_SET
        out = "permitrootlogin no\n"
        ok, msg = self._call(out)
        assert not ok
        assert "not set" in msg

    def test_wrong_setting_shows_actual_value(self):
        out = "permitrootlogin yes\npermitemptypasswords no\nprotocol 2\n"
        ok, msg = self._call(out)
        assert not ok
        assert "yes" in msg


# ---------------------------------------------------------------------------
# configuration_management.py — _AIDE_DB
# ---------------------------------------------------------------------------

class TestBaselineConfigExistsLx:
    """baseline_config_exists_lx() uses _AIDE_DB in its return messages."""

    def _make_paths(self, aide=False, oscap=False, ansible=False):
        def factory(p):
            m = MagicMock()
            if str(p) == "/var/lib/aide/aide.db":
                m.exists.return_value = aide
            elif str(p) == "/var/lib/oscap":
                m.exists.return_value = oscap
            elif str(p) == "/etc/ansible":
                m.exists.return_value = ansible
            else:
                m.exists.return_value = False
            return m
        return factory

    def test_aide_db_present_passes(self):
        with patch(f"{MOD_CM}.Path", side_effect=self._make_paths(aide=True)):
            from core.custom_functions.configuration_management import baseline_config_exists_lx
            ok, msg = baseline_config_exists_lx()
        assert ok
        assert "/var/lib/aide/aide.db" in msg

    def test_oscap_dir_present_passes(self):
        with patch(f"{MOD_CM}.Path", side_effect=self._make_paths(oscap=True)):
            from core.custom_functions.configuration_management import baseline_config_exists_lx
            ok, msg = baseline_config_exists_lx()
        assert ok
        assert "oscap" in msg.lower()

    def test_no_baseline_fails(self):
        with patch(f"{MOD_CM}.Path", side_effect=self._make_paths()):
            from core.custom_functions.configuration_management import baseline_config_exists_lx
            ok, _ = baseline_config_exists_lx()
        assert not ok


# ---------------------------------------------------------------------------
# system_communications_protection.py — _DENY_INCOMING / _UFW_DENY_MSG
# ---------------------------------------------------------------------------

class TestUfwDefaultDenyLx:
    """ufw_default_deny_lx() returns _UFW_DENY_MSG when deny (incoming) is present."""

    def _call(self, side_effects):
        with patch(f"{MOD_SCP}._run", side_effect=side_effects):
            from core.custom_functions.system_communications_protection import ufw_default_deny_lx
            return ufw_default_deny_lx()

    def test_ufw_deny_incoming_passes(self):
        ok, msg = self._call([
            (0, "Status: active\nDefault: deny (incoming), allow (outgoing)", ""),
        ])
        assert ok
        assert msg == "ufw default incoming policy is deny"

    def test_firewalld_drop_zone_passes(self):
        ok, msg = self._call([
            (1, "", "ufw not found"),
            (0, "drop", ""),
        ])
        assert ok
        assert "drop" in msg

    def test_no_deny_policy_fails(self):
        ok, _ = self._call([
            (1, "", ""),
            (1, "", ""),
            (1, "", ""),
        ])
        assert not ok


# ---------------------------------------------------------------------------
# system_communications_protection.py — _MANAGE_BDE_C / _PROTECTION_ON
# ---------------------------------------------------------------------------

class TestBitlockerKeyProtectorWc:
    """bitlocker_key_protector_wc() uses _MANAGE_BDE_C and _PROTECTION_ON."""

    def _call(self, rc: int, out: str, err: str = ""):
        with patch(f"{MOD_SCP}._run", return_value=(rc, out, err)):
            from core.custom_functions.system_communications_protection import bitlocker_key_protector_wc
            return bitlocker_key_protector_wc()

    def test_tpm_and_protection_on_passes(self):
        ok, msg = self._call(0, "Protection Status: Protection On\nKey Protectors: TPM")
        assert ok
        assert "TPM" in msg

    def test_protection_on_without_tpm_fails(self):
        ok, msg = self._call(0, "Protection Status:     Protection On\nKey Protectors: Password")
        assert not ok
        assert "TPM" in msg

    def test_protection_off_fails(self):
        ok, msg = self._call(0, "Protection Status: Protection Off")
        assert not ok
        assert "not" in msg.lower() or "off" in msg.lower()

    def test_command_failure_fails(self):
        ok, _ = self._call(1, "", "access denied")
        assert not ok

    def test_empty_output_fails(self):
        ok, _ = self._call(0, "", "")
        assert not ok


# ---------------------------------------------------------------------------
# audit_accountability.py — _AUDITD_CONF / _AUDITD_NOT_FOUND
# Four functions follow the same "conf not found" pattern; one test each.
# ---------------------------------------------------------------------------

class TestAuditdConfNotFound:
    """Exercise the Path(_AUDITD_CONF).exists() == False branch in each function."""

    def _absent(self):
        m = MagicMock()
        m.exists.return_value = False
        return m

    def test_log_retention_lx_conf_missing(self):
        with patch(f"{MOD_AA}.Path", return_value=self._absent()):
            from core.custom_functions.audit_accountability import log_retention_lx
            ok, msg = log_retention_lx()
        assert not ok
        assert "auditd.conf" in msg

    def test_disk_full_action_lx_conf_missing(self):
        with patch(f"{MOD_AA}.Path", return_value=self._absent()):
            from core.custom_functions.audit_accountability import auditd_disk_full_action_lx
            ok, msg = auditd_disk_full_action_lx()
        assert not ok
        assert "auditd.conf" in msg

    def test_space_left_action_lx_conf_missing(self):
        with patch(f"{MOD_AA}.Path", return_value=self._absent()):
            from core.custom_functions.audit_accountability import auditd_space_left_action_lx
            ok, msg = auditd_space_left_action_lx()
        assert not ok
        assert "auditd.conf" in msg

    def test_audit_conf_permissions_lx_conf_missing(self):
        with patch(f"{MOD_AA}.Path", return_value=self._absent()):
            from core.custom_functions.audit_accountability import audit_conf_permissions_lx
            ok, msg = audit_conf_permissions_lx()
        assert not ok
        assert "auditd.conf" in msg


# ---------------------------------------------------------------------------
# configuration_management.py — _AIDE_DB (fim functions)
# ---------------------------------------------------------------------------

class TestFimEnabledLxAideDb:
    """fim_enabled_lx() uses _AIDE_DB in both the found and not-found messages."""

    def _call(self, aide_rc: int, db_exists: bool):
        mock_db = MagicMock()
        mock_db.exists.return_value = db_exists
        with patch(f"{MOD_CM}._run", return_value=(aide_rc, "", "")), \
             patch(f"{MOD_CM}.Path", return_value=mock_db):
            from core.custom_functions.configuration_management import fim_enabled_lx
            return fim_enabled_lx()

    def test_aide_installed_db_present_passes(self):
        ok, msg = self._call(aide_rc=0, db_exists=True)
        assert ok
        assert "/var/lib/aide/aide.db" in msg

    def test_aide_installed_db_missing_fails(self):
        ok, msg = self._call(aide_rc=0, db_exists=False)
        assert not ok
        assert "/var/lib/aide/aide.db" in msg


class TestFimBaselineCurrentLxAideDb:
    """fim_baseline_current_lx() uses _AIDE_DB when the database is absent."""

    def test_db_not_found_fails(self):
        with patch(f"{MOD_CM}.Path", return_value=_absent_path()):
            from core.custom_functions.configuration_management import fim_baseline_current_lx
            ok, msg = fim_baseline_current_lx()
        assert not ok
        assert "/var/lib/aide/aide.db" in msg


# ---------------------------------------------------------------------------
# configuration_management.py — remaining _NOT_SET use-sites
# ---------------------------------------------------------------------------

class TestUacEnabledWcNotSet:
    def test_lua_disabled_shows_not_set(self):
        with patch(f"{MOD_CM}._reg_get", return_value=None):
            from core.custom_functions.configuration_management import uac_enabled_wc
            ok, msg = uac_enabled_wc()
        assert not ok
        assert "not set" in msg

    def test_lua_zero_shows_value(self):
        with patch(f"{MOD_CM}._reg_get", return_value="0"):
            from core.custom_functions.configuration_management import uac_enabled_wc
            ok, msg = uac_enabled_wc()
        assert not ok
        assert "0" in msg


class TestRootAccessRestrictedLxNotSet:
    """root_access_restricted_lx() uses _NOT_SET when PermitRootLogin output is empty."""

    def test_missing_permitrootlogin_shows_not_set(self):
        with patch(f"{MOD_CM}._run", side_effect=[
            (0, "", ""),    # sshd grep returns empty → not disabled
            (1, "", ""),    # sudoers grep fails → not unrestricted
        ]):
            from core.custom_functions.configuration_management import root_access_restricted_lx
            ok, msg = root_access_restricted_lx()
        assert not ok
        assert "not set" in msg


class TestInsecureProtocolsDisabledWcNotSet:
    """insecure_protocols_disabled_wc() uses _NOT_SET for absent SMB1/TLS registry keys."""

    def test_both_keys_absent_shows_not_set(self):
        with patch(f"{MOD_CM}._reg_get", side_effect=[None, None]):
            from core.custom_functions.configuration_management import insecure_protocols_disabled_wc
            ok, msg = insecure_protocols_disabled_wc()
        assert not ok
        assert "not set" in msg

    def test_smb1_absent_tls_disabled(self):
        with patch(f"{MOD_CM}._reg_get", side_effect=[None, "0"]):
            from core.custom_functions.configuration_management import insecure_protocols_disabled_wc
            ok, msg = insecure_protocols_disabled_wc()
        assert not ok
        assert "not set" in msg


class TestRdpControlledWcNotSet:
    """rdp_controlled_wc() uses _NOT_SET when both registry keys are absent."""

    def test_both_keys_absent_shows_not_set(self):
        with patch(f"{MOD_CM}._reg_get", side_effect=[None, None]):
            from core.custom_functions.configuration_management import rdp_controlled_wc
            ok, msg = rdp_controlled_wc()
        assert not ok
        assert "not set" in msg


class TestPsExecutionPolicyWcNotSet:
    """ps_execution_policy_wc() uses _NOT_SET when Get-ExecutionPolicy returns empty."""

    def test_empty_policy_shows_not_set(self):
        with patch(f"{MOD_CM}._ps", return_value=(0, "", "")):
            from core.custom_functions.configuration_management import ps_execution_policy_wc
            ok, msg = ps_execution_policy_wc()
        assert not ok
        assert "not set" in msg

    def test_unrestricted_policy_shows_value(self):
        with patch(f"{MOD_CM}._ps", return_value=(0, "Unrestricted", "")):
            from core.custom_functions.configuration_management import ps_execution_policy_wc
            ok, msg = ps_execution_policy_wc()
        assert not ok
        assert "Unrestricted" in msg
