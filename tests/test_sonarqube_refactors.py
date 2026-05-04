"""
Tests for new helper functions extracted during SonarQube S3776 refactoring.

_normalize_check_outputs() wraps every function whose name ends in _wc/_ws/_lx,
converting its return value to (bool, str).  Bool-returning helpers are tested
via result[0]; list/str-returning helpers are called via __wrapped__ to access
the actual return value.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

MOD = "core.custom_functions.access_control"


def _sp(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _ok(result) -> bool:
    """Extract bool from a possibly-wrapped (bool, str) tuple."""
    return result[0] if isinstance(result, tuple) else result


# ============================================================
# _check_pam_lockout_lx  (returns bool → wrapped to (bool, str))
# ============================================================

class TestCheckPamLockoutLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_pam_lockout_lx
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return _ok(_check_pam_lockout_lx())

    def test_faillock_conf_valid_returns_true(self):
        assert self._call([_sp(0, "deny = 3\nunlock_time = 900\n")]) is True

    def test_faillock_deny_too_high_falls_through(self):
        # deny=10 fails the 1..5 check; falls to grep pam_faillock / pam_tally2
        assert self._call([_sp(0, "deny = 10\nunlock_time = 900\n"), _sp(1), _sp(1)]) is False

    def test_faillock_unlock_too_low_falls_through(self):
        assert self._call([_sp(0, "deny = 3\nunlock_time = 300\n"), _sp(1), _sp(1)]) is False

    def test_faillock_conf_missing_uses_pam_grep(self):
        pam = "/etc/pam.d/sshd:auth required pam_faillock.so preauth deny=3 unlock_time=1800"
        assert self._call([_sp(1), _sp(0, pam)]) is True

    def test_pam_tally2_valid_returns_true(self):
        tally = "/etc/pam.d/common-auth:auth required pam_tally2.so deny=5 unlock_time=900"
        assert self._call([_sp(1), _sp(1), _sp(0, tally)]) is True

    def test_all_missing_returns_false(self):
        assert self._call([_sp(1), _sp(1), _sp(1)]) is False

    def test_commented_conf_lines_ignored(self):
        conf = "# deny = 3\n# unlock_time = 900\n"
        assert self._call([_sp(0, conf), _sp(1), _sp(1)]) is False


# ============================================================
# _get_wireless_interfaces_lx  (returns list → use __wrapped__)
# ============================================================

class TestGetWirelessInterfacesLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _get_wireless_interfaces_lx
        fn = getattr(_get_wireless_interfaces_lx, "__wrapped__", _get_wireless_interfaces_lx)
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return fn()

    def test_iw_dev_single_interface(self):
        out = "phy#0\n\tInterface wlan0\n\t\tifindex 3\n"
        assert self._call([_sp(0, out)]) == ["wlan0"]

    def test_iw_dev_multiple_interfaces(self):
        out = "phy#0\n\tInterface wlan0\nphy#1\n\tInterface wlan1\n"
        result = self._call([_sp(0, out)])
        assert "wlan0" in result and "wlan1" in result

    def test_iw_fails_falls_back_to_iwconfig(self):
        iwconfig = "wlan0     IEEE 802.11  ESSID:\"TestNet\"\n"
        assert self._call([_sp(1), _sp(0, iwconfig)]) == ["wlan0"]

    def test_iw_empty_falls_back_to_iwconfig(self):
        iwconfig = "wlan0     IEEE 802.11  ESSID:\"TestNet\"\n"
        assert self._call([_sp(0, ""), _sp(0, iwconfig)]) == ["wlan0"]

    def test_both_fail_returns_empty(self):
        assert self._call([_sp(1), _sp(1)]) == []

    def test_iwconfig_no_wireless_returns_empty(self):
        assert self._call([_sp(1), _sp(0, "lo        no wireless extensions.\n")]) == []


# ============================================================
# _is_iface_up_lx  (returns bool → wrapped)
# ============================================================

class TestIsIfaceUpLx:
    def _call(self, returncode, stdout):
        from core.custom_functions.access_control import _is_iface_up_lx
        with patch(f"{MOD}.subprocess.run", return_value=_sp(returncode, stdout)):
            return _ok(_is_iface_up_lx("wlan0"))

    def test_iface_up_returns_true(self):
        assert self._call(0, "2: wlan0: <BROADCAST,UP,LOWER_UP> state UP\n") is True

    def test_iface_state_down_returns_false(self):
        assert self._call(0, "2: wlan0: <BROADCAST> state DOWN\n") is False

    def test_command_fails_returns_false(self):
        assert self._call(1, "") is False

    def test_state_down_case_insensitive(self):
        assert self._call(0, "2: wlan0: State Down\n") is False


# ============================================================
# _check_iface_wpa_authorization_lx  (returns str → use __wrapped__)
# ============================================================

class TestCheckIfaceWpaAuthorizationLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_iface_wpa_authorization_lx
        fn = getattr(_check_iface_wpa_authorization_lx, "__wrapped__",
                     _check_iface_wpa_authorization_lx)
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return fn("wlan0")

    def test_wpa_eap_enterprise_returns_empty(self):
        out = "key_mgmt=WPA-EAP\neap=PEAP\npairwise_cipher=CCMP\n"
        assert self._call([_sp(0, out)]) == ""

    def test_ieee8021x_returns_empty(self):
        out = "key_mgmt=IEEE8021X\nieee802.1x enabled\npairwise_cipher=CCMP\n"
        assert self._call([_sp(0, out)]) == ""

    def test_psk_returns_flagged(self):
        out = "key_mgmt=WPA2-PSK\n"
        result = self._call([_sp(0, out)])
        assert "weak auth" in result

    def test_weak_cipher_tkip_returns_flagged(self):
        out = "key_mgmt=WPA-EAP\neap=PEAP\npairwise_cipher=TKIP\n"
        result = self._call([_sp(0, out)])
        assert "weak cipher" in result

    def test_no_eap_no_8021x_returns_flagged(self):
        out = "key_mgmt=WPA-EAP\n"
        result = self._call([_sp(0, out)])
        assert result != ""

    def test_none_key_mgmt_returns_flagged(self):
        out = "key_mgmt=NONE\n"
        result = self._call([_sp(0, out)])
        assert "weak auth" in result

    def test_wpa_cli_fails_iwconfig_open_returns_flagged(self):
        iwconfig = "wlan0  encryption key:off\n"
        result = self._call([_sp(1), _sp(0, iwconfig)])
        assert result != ""

    def test_wpa_cli_fails_iwconfig_also_fails_returns_empty(self):
        assert self._call([_sp(1), _sp(1)]) == ""


# ============================================================
# _check_nm_authorization_lx  (returns list → use __wrapped__)
# ============================================================

class TestCheckNmAuthorizationLx:
    def _call(self, returncode, stdout):
        from core.custom_functions.access_control import _check_nm_authorization_lx
        fn = getattr(_check_nm_authorization_lx, "__wrapped__", _check_nm_authorization_lx)
        with patch(f"{MOD}.subprocess.run", return_value=_sp(returncode, stdout)):
            return fn()

    def test_strong_auth_returns_empty(self):
        assert self._call(0, "Corp WiFi:802-11-wireless:wpa-eap\n") == []

    def test_psk_profile_returns_flagged(self):
        result = self._call(0, "Home Net:802-11-wireless:wpa-psk\n")
        assert len(result) == 1 and "weak or no auth" in result[0]

    def test_no_auth_profile_returns_flagged(self):
        result = self._call(0, "Open Net:802-11-wireless:\n")
        assert len(result) == 1

    def test_non_wireless_profile_ignored(self):
        assert self._call(0, "Ethernet:802-3-ethernet:wpa-psk\n") == []

    def test_command_fails_returns_empty(self):
        assert self._call(1, "") == []

    def test_empty_output_returns_empty(self):
        assert self._call(0, "") == []

    def test_multiple_weak_profiles_all_flagged(self):
        nm_out = "Net1:802-11-wireless:wpa-psk\nNet2:802-11-wireless:none\n"
        assert len(self._call(0, nm_out)) == 2


# ============================================================
# _check_iface_wpa_authentication_lx  (returns list → use __wrapped__)
# ============================================================

class TestCheckIfaceWpaAuthenticationLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_iface_wpa_authentication_lx
        fn = getattr(_check_iface_wpa_authentication_lx, "__wrapped__",
                     _check_iface_wpa_authentication_lx)
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return fn("wlan0")

    def test_strong_eap_peap_returns_empty(self):
        out = "key_mgmt=WPA-EAP\neap=PEAP\n"
        # wpa_cli (1) + two conf-file cat calls (2,3) that both fail
        assert self._call([_sp(0, out), _sp(1), _sp(1)]) == []

    def test_psk_key_mgmt_returns_flagged(self):
        result = self._call([_sp(0, "key_mgmt=WPA-PSK\n")])
        assert len(result) == 1 and "weak key mgmt" in result[0]

    def test_no_eap_method_returns_flagged(self):
        result = self._call([_sp(0, "key_mgmt=WPA-EAP\n")])
        assert len(result) == 1 and "no EAP" in result[0]

    def test_weak_eap_md5_returns_flagged(self):
        result = self._call([_sp(0, "key_mgmt=WPA-EAP\neap=MD5\n")])
        assert len(result) == 1 and "weak EAP" in result[0]

    def test_conf_with_ca_cert_returns_empty(self):
        conf = "network={\n  key_mgmt=WPA-EAP\n  eap=PEAP\n  ca_cert=\"/etc/ssl/ca.pem\"\n}\n"
        # wpa_cli fails → tries two conf paths; first succeeds, second fails
        assert self._call([_sp(1), _sp(0, conf), _sp(1)]) == []

    def test_conf_missing_ca_cert_returns_flagged(self):
        conf = "network={\n  key_mgmt=WPA-EAP\n  eap=PEAP\n}\n"
        result = self._call([_sp(1), _sp(0, conf)])
        assert any("CA" in r for r in result)

    def test_both_fail_returns_empty(self):
        assert self._call([_sp(1), _sp(1), _sp(1)]) == []


# ============================================================
# _check_nm_authentication_lx  (returns list → use __wrapped__)
# ============================================================

class TestCheckNmAuthenticationLx:
    def _call(self, returncode, stdout):
        from core.custom_functions.access_control import _check_nm_authentication_lx
        fn = getattr(_check_nm_authentication_lx, "__wrapped__", _check_nm_authentication_lx)
        with patch(f"{MOD}.subprocess.run", return_value=_sp(returncode, stdout)):
            return fn()

    def test_strong_eap_with_ca_returns_empty(self):
        assert self._call(0, "CorpNet:peap:/etc/ssl/ca.pem\n") == []

    def test_weak_eap_md5_returns_flagged(self):
        result = self._call(0, "Net:md5:/etc/ssl/ca.pem\n")
        assert any("weak EAP" in r for r in result)

    def test_missing_ca_cert_returns_flagged(self):
        result = self._call(0, "Net:peap:--\n")
        assert any("CA cert" in r for r in result)

    def test_command_fails_returns_empty(self):
        assert self._call(1, "") == []

    def test_empty_returns_empty(self):
        assert self._call(0, "") == []


# ============================================================
# _check_iface_cipher_lx  (returns list → use __wrapped__)
# ============================================================

class TestCheckIfaceCipherLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_iface_cipher_lx
        fn = getattr(_check_iface_cipher_lx, "__wrapped__", _check_iface_cipher_lx)
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return fn("wlan0")

    def test_ccmp_pairwise_and_group_returns_empty(self):
        out = "pairwise_cipher=CCMP\ngroup_cipher=CCMP\n"
        # wpa_cli (1) + two conf-file cat calls (2,3) + iw link (4)
        assert self._call([
            _sp(0, out), _sp(1), _sp(1),
            _sp(0, "Connected to 00:11:22:33:44:55"),
        ]) == []

    def test_tkip_pairwise_returns_flagged(self):
        out = "pairwise_cipher=TKIP\n"
        result = self._call([_sp(0, out), _sp(1)])
        assert any("weak pairwise" in r for r in result)

    def test_weak_group_cipher_returns_flagged(self):
        out = "pairwise_cipher=CCMP\ngroup_cipher=TKIP\n"
        result = self._call([_sp(0, out), _sp(1)])
        assert any("weak group" in r for r in result)

    def test_unknown_pairwise_cipher_returns_flagged(self):
        out = "pairwise_cipher=PROPRIETARY\n"
        result = self._call([_sp(0, out), _sp(1)])
        assert any("unknown pairwise" in r for r in result)

    def test_wpa_cli_fails_conf_tkip_returns_flagged(self):
        conf = "network={\n  pairwise=TKIP\n  group=TKIP\n}\n"
        result = self._call([_sp(1), _sp(0, conf), _sp(1), _sp(1)])
        assert any("weak" in r for r in result)

    def test_iw_link_wep_detected(self):
        out = "pairwise_cipher=CCMP\ngroup_cipher=CCMP\n"
        iw_link = "tx bitrate: 54.0 MBit/s\nwep40 encryption active\n"
        # wpa_cli (1) + conf1 fails (2) + conf2 fails (3) + iw link (4)
        result = self._call([_sp(0, out), _sp(1), _sp(1), _sp(0, iw_link)])
        assert any("WEP" in r for r in result)


# ============================================================
# _check_nm_cipher_lx  (returns list → use __wrapped__)
# ============================================================

class TestCheckNmCipherLx:
    def _call(self, returncode, stdout):
        from core.custom_functions.access_control import _check_nm_cipher_lx
        fn = getattr(_check_nm_cipher_lx, "__wrapped__", _check_nm_cipher_lx)
        with patch(f"{MOD}.subprocess.run", return_value=_sp(returncode, stdout)):
            return fn()

    def test_ccmp_returns_empty(self):
        assert self._call(0, "CorpNet:ccmp:ccmp\n") == []

    def test_tkip_pairwise_returns_flagged(self):
        result = self._call(0, "Net:tkip:ccmp\n")
        assert any("weak pairwise" in r for r in result)

    def test_tkip_group_returns_flagged(self):
        result = self._call(0, "Net:ccmp:tkip\n")
        assert any("weak group" in r for r in result)

    def test_command_fails_returns_empty(self):
        assert self._call(1, "") == []

    def test_empty_returns_empty(self):
        assert self._call(0, "") == []


# ============================================================
# _luks_in_devices  (not wrapped — doesn't end in _lx)
# ============================================================

class TestLuksInDevices:
    def _call(self, devices):
        from core.custom_functions.access_control import _luks_in_devices
        return _luks_in_devices(devices)

    def test_crypto_luks_fstype(self):
        assert self._call([{"fstype": "crypto_LUKS", "type": "disk", "children": []}]) is True

    def test_crypt_type(self):
        assert self._call([{"fstype": "", "type": "crypt", "children": []}]) is True

    def test_nested_luks(self):
        devices = [{"fstype": "ext4", "type": "disk",
                    "children": [{"fstype": "crypto_LUKS", "type": "part", "children": []}]}]
        assert self._call(devices) is True

    def test_no_luks_returns_false(self):
        assert self._call([{"fstype": "ext4", "type": "disk", "children": []}]) is False

    def test_empty_returns_false(self):
        assert self._call([]) is False

    def test_none_children_handled(self):
        assert self._call([{"fstype": "ext4", "type": "disk", "children": None}]) is False


# ============================================================
# _find_luks_devices_lx  (returns bool → wrapped)
# ============================================================

class TestFindLuksDevicesLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _find_luks_devices_lx
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return _ok(_find_luks_devices_lx())

    def test_lsblk_json_luks_returns_true(self):
        data = json.dumps({"blockdevices": [
            {"name": "sda", "fstype": "crypto_LUKS", "type": "disk", "children": []}
        ]})
        assert self._call([_sp(0, data), _sp(0, "luks-sda1 (253:0)")]) is True

    def test_lsblk_no_luks_dmsetup_found_returns_true(self):
        data = json.dumps({"blockdevices": [{"name": "sda", "fstype": "ext4", "type": "disk", "children": []}]})
        assert self._call([_sp(0, data), _sp(0, "luks-sda1    (253:0)")]) is True

    def test_dmsetup_no_devices_returns_false(self):
        data = json.dumps({"blockdevices": [{"name": "sda", "fstype": "ext4", "type": "disk", "children": []}]})
        assert self._call([_sp(0, data), _sp(0, "No devices found\n")]) is False

    def test_lsblk_fails_dmsetup_found_returns_true(self):
        assert self._call([_sp(1), _sp(0, "luks-sda1    (253:0)")]) is True

    def test_both_fail_returns_false(self):
        assert self._call([_sp(1), _sp(1)]) is False

    def test_lsblk_invalid_json_falls_through(self):
        assert self._call([_sp(0, "not-json"), _sp(0, "No devices found\n")]) is False


# ============================================================
# _check_luks_cipher_strong_lx  (returns bool → wrapped)
# ============================================================

class TestCheckLuksCipherStrongLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_luks_cipher_strong_lx
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return _ok(_check_luks_cipher_strong_lx())

    def test_aes_xts_cipher_returns_true(self):
        dm = "luks-abc    (253:0)\n"
        status = "cipher: aes-xts-plain64\nkeysize: 512 bits\n"
        assert self._call([_sp(0, dm), _sp(0, status)]) is True

    def test_keysize_256_returns_true(self):
        dm = "luks-abc    (253:0)\n"
        status = "cipher: aes-cbc-essiv:sha256\nkeysize: 256 bits\n"
        assert self._call([_sp(0, dm), _sp(0, status)]) is True

    def test_weak_cipher_returns_false(self):
        dm = "luks-abc    (253:0)\n"
        status = "cipher: des-cbc\nkeysize: 64 bits\n"
        assert self._call([_sp(0, dm), _sp(0, status)]) is False

    def test_dmsetup_fails_returns_false(self):
        assert self._call([_sp(1)]) is False

    def test_dmsetup_empty_returns_false(self):
        assert self._call([_sp(0, "")]) is False

    def test_dmsetup_no_devices_returns_false(self):
        assert self._call([_sp(0, "No devices found\n")]) is False


# ============================================================
# _check_home_encrypted_lx  (returns bool → wrapped)
# ============================================================

class TestCheckHomeEncryptedLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_home_encrypted_lx
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return _ok(_check_home_encrypted_lx())

    def test_dm_mapper_source_returns_true(self):
        assert self._call([_sp(0, "/dev/mapper/home ext4\n")]) is True

    def test_dev_dm_source_returns_true(self):
        assert self._call([_sp(0, "/dev/dm-1 ext4\n")]) is True

    def test_ecryptfs_mount_returns_true(self):
        mount = "ecryptfs on /home type ecryptfs (rw)\n"
        assert self._call([_sp(1), _sp(0, mount)]) is True

    def test_fscrypt_enabled_returns_true(self):
        assert self._call([_sp(1), _sp(0, "tmpfs on /tmp\n"), _sp(0, "encryption enabled\n")]) is True

    def test_ecryptfs_dir_found_returns_true(self):
        assert self._call([_sp(1), _sp(0, "tmpfs\n"), _sp(1), _sp(0, "/home/alice/.ecryptfs\n")]) is True

    def test_no_encryption_returns_false(self):
        assert self._call([_sp(1), _sp(0, "tmpfs\n"), _sp(1), _sp(0, "")]) is False

    def test_findmnt_non_dm_source_falls_through(self):
        # Source doesn't start with /dev/dm- or /dev/mapper/ → falls through to mount
        assert self._call([_sp(0, "/dev/sda1 ext4\n"), _sp(0, "tmpfs\n"), _sp(1), _sp(0, "")]) is False


# ============================================================
# _check_usb_audit_lx  (returns bool → wrapped)
# ============================================================

class TestCheckUsbAuditLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_usb_audit_lx
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return _ok(_check_usb_audit_lx())

    def test_auditd_active_usb_rule_returns_true(self):
        rules = "-a always,exit -F path=/dev/bus/usb -F perm=rwa\n"
        assert self._call([_sp(0, "active\n"), _sp(0, rules)]) is True

    def test_auditd_active_removable_keyword_returns_true(self):
        rules = "-a always,exit -F key=removable\n"
        assert self._call([_sp(0, "active\n"), _sp(0, rules)]) is True

    def test_auditd_active_no_usb_rule_udev_matches_returns_true(self):
        rules = "-a always,exit -F key=network\n"
        udev = "/etc/udev/rules.d/99-usb.rules\n"
        grep = "/etc/udev/rules.d/99-usb.rules\n"
        assert self._call([_sp(0, "active\n"), _sp(0, rules), _sp(0, udev), _sp(0, grep)]) is True

    def test_auditd_inactive_returns_false(self):
        assert self._call([_sp(1, "inactive\n")]) is False

    def test_auditd_active_no_rules_udev_no_match_returns_false(self):
        udev = "/etc/udev/rules.d/70-persistent.rules\n"
        assert self._call([_sp(0, "active\n"), _sp(0, ""), _sp(0, udev), _sp(1)]) is False


# ============================================================
# _check_syslog_usb_lx  (returns bool → wrapped)
# ============================================================

class TestCheckSyslogUsbLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_syslog_usb_lx
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return _ok(_check_syslog_usb_lx())

    def test_syslog_has_usb_entries_returns_true(self):
        # First grep returns 42 entries → returns True after 1 call
        assert self._call([_sp(0, "42\n")]) is True

    def test_all_greps_zero_journal_matches_returns_true(self):
        journal = "May 04 10:00:00 host kernel: usb device attached\n"
        assert self._call([_sp(0, "0\n"), _sp(0, "0\n"), _sp(0, "0\n"), _sp(0, journal)]) is True

    def test_all_fail_returns_false(self):
        assert self._call([_sp(1), _sp(1), _sp(1), _sp(1)]) is False

    def test_all_zero_journal_empty_returns_false(self):
        assert self._call([_sp(0, "0\n"), _sp(0, "0\n"), _sp(0, "0\n"), _sp(0, "")]) is False


# ============================================================
# _check_bluetooth_controlled_lx  (returns bool → wrapped)
# ============================================================

class TestCheckBluetoothControlledLx:
    def _call(self, side_effects):
        from core.custom_functions.access_control import _check_bluetooth_controlled_lx
        with patch(f"{MOD}.subprocess.run", side_effect=side_effects):
            return _ok(_check_bluetooth_controlled_lx())

    def test_bluetooth_inactive_returns_true(self):
        assert self._call([_sp(1, "inactive\n")]) is True

    def test_bluetooth_active_non_discoverable_timeout_returns_true(self):
        conf = "Discoverable = false\nDiscoverableTimeout = 180\n"
        assert self._call([_sp(0, "active\n"), _sp(0, conf)]) is True

    def test_bluetooth_active_discoverable_journal_logged_returns_true(self):
        conf = "Discoverable = true\n"
        journal = "May 04 systemd[1]: Started Bluetooth service\n"
        assert self._call([_sp(0, "active\n"), _sp(0, conf), _sp(0, journal)]) is True

    def test_bluetooth_active_conf_fails_journal_has_entries_returns_true(self):
        journal = "May 04 systemd[1]: Started Bluetooth\n"
        assert self._call([_sp(0, "active\n"), _sp(1), _sp(0, journal)]) is True

    def test_bluetooth_active_no_conf_no_journal_returns_false(self):
        assert self._call([_sp(0, "active\n"), _sp(1), _sp(0, "")]) is False


# ============================================================
# wireless_authorization_lx  (public wrapper, patches helpers)
# ============================================================

class TestWirelessAuthorizationLx:
    def test_no_interfaces_returns_true(self):
        from core.custom_functions.access_control import wireless_authorization_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=[]):
            assert _ok(wireless_authorization_lx()) is True

    def test_all_interfaces_down_returns_true(self):
        from core.custom_functions.access_control import wireless_authorization_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=False), \
             patch(f"{MOD}._check_nm_authorization_lx", return_value=[]):
            assert _ok(wireless_authorization_lx()) is True

    def test_iface_up_no_issues_returns_true(self):
        from core.custom_functions.access_control import wireless_authorization_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=True), \
             patch(f"{MOD}._check_iface_wpa_authorization_lx", return_value=""), \
             patch(f"{MOD}._check_nm_authorization_lx", return_value=[]):
            assert _ok(wireless_authorization_lx()) is True

    def test_iface_flagged_returns_false(self):
        from core.custom_functions.access_control import wireless_authorization_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=True), \
             patch(f"{MOD}._check_iface_wpa_authorization_lx", return_value="wlan0: weak auth"), \
             patch(f"{MOD}._check_nm_authorization_lx", return_value=[]):
            assert _ok(wireless_authorization_lx()) is False

    def test_nm_flagged_returns_false(self):
        from core.custom_functions.access_control import wireless_authorization_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=True), \
             patch(f"{MOD}._check_iface_wpa_authorization_lx", return_value=""), \
             patch(f"{MOD}._check_nm_authorization_lx", return_value=["NM Home: weak"]):
            assert _ok(wireless_authorization_lx()) is False

    def test_exception_returns_false(self):
        from core.custom_functions.access_control import wireless_authorization_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", side_effect=OSError("fail")):
            assert _ok(wireless_authorization_lx()) is False


# ============================================================
# wireless_auth_lx  (public wrapper, patches helpers)
# ============================================================

class TestWirelessAuthLx:
    def test_no_interfaces_returns_true(self):
        from core.custom_functions.access_control import wireless_auth_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=[]):
            assert _ok(wireless_auth_lx()) is True

    def test_iface_up_no_issues_returns_true(self):
        from core.custom_functions.access_control import wireless_auth_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=True), \
             patch(f"{MOD}._check_iface_wpa_authentication_lx", return_value=[]), \
             patch(f"{MOD}._check_nm_authentication_lx", return_value=[]):
            assert _ok(wireless_auth_lx()) is True

    def test_iface_flagged_returns_false(self):
        from core.custom_functions.access_control import wireless_auth_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=True), \
             patch(f"{MOD}._check_iface_wpa_authentication_lx", return_value=["wlan0: no EAP"]), \
             patch(f"{MOD}._check_nm_authentication_lx", return_value=[]):
            assert _ok(wireless_auth_lx()) is False

    def test_exception_returns_false(self):
        from core.custom_functions.access_control import wireless_auth_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", side_effect=RuntimeError("fail")):
            assert _ok(wireless_auth_lx()) is False


# ============================================================
# wireless_encryption_lx  (public wrapper, patches helpers)
# ============================================================

class TestWirelessEncryptionLx:
    def test_no_interfaces_returns_true(self):
        from core.custom_functions.access_control import wireless_encryption_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=[]):
            assert _ok(wireless_encryption_lx()) is True

    def test_strong_cipher_returns_true(self):
        from core.custom_functions.access_control import wireless_encryption_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=True), \
             patch(f"{MOD}._check_iface_cipher_lx", return_value=[]), \
             patch(f"{MOD}._check_nm_cipher_lx", return_value=[]):
            assert _ok(wireless_encryption_lx()) is True

    def test_weak_cipher_returns_false(self):
        from core.custom_functions.access_control import wireless_encryption_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", return_value=["wlan0"]), \
             patch(f"{MOD}._is_iface_up_lx", return_value=True), \
             patch(f"{MOD}._check_iface_cipher_lx", return_value=["wlan0: weak pairwise"]), \
             patch(f"{MOD}._check_nm_cipher_lx", return_value=[]):
            assert _ok(wireless_encryption_lx()) is False

    def test_exception_returns_false(self):
        from core.custom_functions.access_control import wireless_encryption_lx
        with patch(f"{MOD}._get_wireless_interfaces_lx", side_effect=OSError):
            assert _ok(wireless_encryption_lx()) is False


# ============================================================
# mobile_device_monitoring_lx  (public wrapper, patches helpers)
# ============================================================

class TestMobileDeviceMonitoringLx:
    def test_all_ok_returns_true(self):
        from core.custom_functions.access_control import mobile_device_monitoring_lx
        with patch(f"{MOD}._check_usb_audit_lx", return_value=True), \
             patch(f"{MOD}._check_syslog_usb_lx", return_value=True), \
             patch(f"{MOD}._check_bluetooth_controlled_lx", return_value=True):
            assert _ok(mobile_device_monitoring_lx()) is True

    def test_usb_audit_missing_returns_false(self):
        from core.custom_functions.access_control import mobile_device_monitoring_lx
        with patch(f"{MOD}._check_usb_audit_lx", return_value=False), \
             patch(f"{MOD}._check_syslog_usb_lx", return_value=True), \
             patch(f"{MOD}._check_bluetooth_controlled_lx", return_value=True):
            assert _ok(mobile_device_monitoring_lx()) is False

    def test_syslog_missing_returns_false(self):
        from core.custom_functions.access_control import mobile_device_monitoring_lx
        with patch(f"{MOD}._check_usb_audit_lx", return_value=True), \
             patch(f"{MOD}._check_syslog_usb_lx", return_value=False), \
             patch(f"{MOD}._check_bluetooth_controlled_lx", return_value=True):
            assert _ok(mobile_device_monitoring_lx()) is False

    def test_bluetooth_uncontrolled_returns_false(self):
        from core.custom_functions.access_control import mobile_device_monitoring_lx
        with patch(f"{MOD}._check_usb_audit_lx", return_value=True), \
             patch(f"{MOD}._check_syslog_usb_lx", return_value=True), \
             patch(f"{MOD}._check_bluetooth_controlled_lx", return_value=False):
            assert _ok(mobile_device_monitoring_lx()) is False

    def test_exception_returns_false(self):
        from core.custom_functions.access_control import mobile_device_monitoring_lx
        with patch(f"{MOD}._check_usb_audit_lx", side_effect=OSError):
            assert _ok(mobile_device_monitoring_lx()) is False


# ============================================================
# mobile_encryption_lx  (public wrapper, patches helpers)
# ============================================================

class TestMobileEncryptionLx:
    def test_all_ok_returns_true(self):
        from core.custom_functions.access_control import mobile_encryption_lx
        with patch(f"{MOD}._find_luks_devices_lx", return_value=True), \
             patch(f"{MOD}._check_luks_cipher_strong_lx", return_value=True), \
             patch(f"{MOD}._check_home_encrypted_lx", return_value=True):
            assert _ok(mobile_encryption_lx()) is True

    def test_no_luks_returns_false(self):
        from core.custom_functions.access_control import mobile_encryption_lx
        with patch(f"{MOD}._find_luks_devices_lx", return_value=False), \
             patch(f"{MOD}._check_home_encrypted_lx", return_value=True):
            assert _ok(mobile_encryption_lx()) is False

    def test_weak_cipher_returns_false(self):
        from core.custom_functions.access_control import mobile_encryption_lx
        with patch(f"{MOD}._find_luks_devices_lx", return_value=True), \
             patch(f"{MOD}._check_luks_cipher_strong_lx", return_value=False), \
             patch(f"{MOD}._check_home_encrypted_lx", return_value=True):
            assert _ok(mobile_encryption_lx()) is False

    def test_home_not_encrypted_returns_false(self):
        from core.custom_functions.access_control import mobile_encryption_lx
        with patch(f"{MOD}._find_luks_devices_lx", return_value=True), \
             patch(f"{MOD}._check_luks_cipher_strong_lx", return_value=True), \
             patch(f"{MOD}._check_home_encrypted_lx", return_value=False):
            assert _ok(mobile_encryption_lx()) is False

    def test_exception_returns_false(self):
        from core.custom_functions.access_control import mobile_encryption_lx
        with patch(f"{MOD}._find_luks_devices_lx", side_effect=RuntimeError):
            assert _ok(mobile_encryption_lx()) is False

    def test_no_luks_skips_cipher_check(self):
        from core.custom_functions.access_control import mobile_encryption_lx
        cipher_mock = MagicMock(return_value=True)
        with patch(f"{MOD}._find_luks_devices_lx", return_value=False), \
             patch(f"{MOD}._check_luks_cipher_strong_lx", cipher_mock), \
             patch(f"{MOD}._check_home_encrypted_lx", return_value=True):
            mobile_encryption_lx()
        cipher_mock.assert_not_called()


# ============================================================
# logon_attempt_limit_lx  (public wrapper, patches _check_pam_lockout_lx)
# ============================================================

class TestLogonAttemptLimitLx:
    def test_pam_lockout_and_ssh_limited_returns_true(self):
        from core.custom_functions.access_control import logon_attempt_limit_lx
        sshd_out = "maxauthtries 3\nlogingraceperiod 60\n"
        with patch(f"{MOD}._check_pam_lockout_lx", return_value=True), \
             patch(f"{MOD}.subprocess.run", return_value=_sp(0, sshd_out)):
            assert _ok(logon_attempt_limit_lx()) is True

    def test_pam_lockout_fails_returns_false(self):
        from core.custom_functions.access_control import logon_attempt_limit_lx
        sshd_out = "maxauthtries 3\n"
        with patch(f"{MOD}._check_pam_lockout_lx", return_value=False), \
             patch(f"{MOD}.subprocess.run", return_value=_sp(0, sshd_out)):
            assert _ok(logon_attempt_limit_lx()) is False

    def test_ssh_maxauthtries_too_high_returns_false(self):
        from core.custom_functions.access_control import logon_attempt_limit_lx
        sshd_out = "maxauthtries 6\n"
        with patch(f"{MOD}._check_pam_lockout_lx", return_value=True), \
             patch(f"{MOD}.subprocess.run", return_value=_sp(0, sshd_out)):
            assert _ok(logon_attempt_limit_lx()) is False
