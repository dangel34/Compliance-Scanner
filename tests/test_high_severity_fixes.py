"""
Tests for the four high-severity bug fixes:

  Bug #1  report_pdf.py      --page-size LETTER always produced A4
  Bug #2  firewall.py        false positive when only one profile is ON
  Bug #3  _RUN_CACHE         stale results returned across GUI re-scans
  Bug #4  authorized_user_ws passes on any successful AD query
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch



# ============================================================
# Bug #1 — PDF page-size case-insensitive comparison
# ============================================================

class TestPdfPageSize:
    """generate_report_pdf should use the LETTER page size for both
    'LETTER' (CLI argparse) and 'Letter' (GUI segmented button)."""

    def _make_results(self):
        return {
            "fake_path": {
                "rule_id": "TEST.01",
                "title": "Page Size Test",
                "os": "windows_client",
                "checks_run": 1, "checks_skipped": 0, "checks_policy": 0,
                "checks": [{"status": "PASS", "check_name": "c", "sub_control": "s",
                             "command": "echo", "expected_result": "", "returncode": 0,
                             "stdout": "ok", "stderr": ""}],
            }
        }

    def _captured_pagesize(self, page_size_arg: str, tmp_path) -> object:
        """Return the pagesize that SimpleDocTemplate was called with."""
        from ui.report_pdf import generate_report_pdf

        captured = {}

        real_doc = __import__("reportlab.platypus", fromlist=["SimpleDocTemplate"]).SimpleDocTemplate

        def fake_doc(path, **kwargs):
            captured["pagesize"] = kwargs.get("pagesize")
            doc = real_doc(path, **kwargs)
            return doc

        with patch("ui.report_pdf.SimpleDocTemplate", side_effect=fake_doc):
            out = tmp_path / "report.pdf"
            generate_report_pdf(str(out), self._make_results(), page_size=page_size_arg)

        return captured.get("pagesize")

    def test_letter_uppercase_uses_letter_pagesize(self, tmp_path):
        """CLI passes 'LETTER' — must produce a Letter-sized PDF."""
        from reportlab.lib.pagesizes import LETTER
        pagesize = self._captured_pagesize("LETTER", tmp_path)
        assert pagesize == LETTER, f"Expected LETTER pagesize, got {pagesize}"

    def test_letter_mixedcase_uses_letter_pagesize(self, tmp_path):
        """GUI passes 'Letter' — must produce a Letter-sized PDF."""
        from reportlab.lib.pagesizes import LETTER
        pagesize = self._captured_pagesize("Letter", tmp_path)
        assert pagesize == LETTER, f"Expected LETTER pagesize, got {pagesize}"

    def test_a4_uses_a4_pagesize(self, tmp_path):
        """Default 'A4' must produce an A4-sized PDF."""
        from reportlab.lib.pagesizes import A4
        pagesize = self._captured_pagesize("A4", tmp_path)
        assert pagesize == A4, f"Expected A4 pagesize, got {pagesize}"

    def test_unknown_value_defaults_to_a4(self, tmp_path):
        """Any unrecognised value falls back to A4."""
        from reportlab.lib.pagesizes import A4
        pagesize = self._captured_pagesize("legal", tmp_path)
        assert pagesize == A4


# ============================================================
# Bug #2 — Firewall: require ALL profiles to be ON
# ============================================================

class TestFirewallEnabled:
    """firewall_enabled() must return True only when ALL three profiles are ON."""

    def _run(self, stdout: str, returncode: int = 0):
        from core.custom_functions.firewall import firewall_enabled
        mock_result = MagicMock()
        mock_result.stdout = stdout
        mock_result.stderr = ""
        mock_result.returncode = returncode
        with patch("core.custom_functions.firewall.subprocess.run", return_value=mock_result):
            return firewall_enabled()

    # Realistic netsh output with heavy whitespace between State and ON/OFF
    _ALL_ON = (
        "Domain Profile Settings:\n"
        "----------------------------------------------------------------------\n"
        "State                                 ON\n"
        "\n"
        "Private Profile Settings:\n"
        "----------------------------------------------------------------------\n"
        "State                                 ON\n"
        "\n"
        "Public Profile Settings:\n"
        "----------------------------------------------------------------------\n"
        "State                                 ON\n"
    )
    _DOMAIN_OFF = _ALL_ON.replace("Domain Profile Settings:\n---"
                                  "-------------------------------------------------------------------\n"
                                  "State                                 ON",
                                  "Domain Profile Settings:\n---"
                                  "-------------------------------------------------------------------\n"
                                  "State                                 OFF")
    _ALL_OFF = (
        "Domain Profile Settings:\n------\nState                                 OFF\n"
        "Private Profile Settings:\n------\nState                                 OFF\n"
        "Public Profile Settings:\n------\nState                                 OFF\n"
    )
    # Old single-space format (guard against regression if netsh ever changes)
    _SINGLE_SPACE_ALL_ON = (
        "Domain Profile Settings:\nState ON\n"
        "Private Profile Settings:\nState ON\n"
        "Public Profile Settings:\nState ON\n"
    )

    def test_all_profiles_on_returns_true(self):
        ok, _ = self._run(self._ALL_ON)
        assert ok is True

    def test_single_space_format_also_passes(self):
        """Regex must handle 'State ON' (single space) as well as heavy-whitespace form."""
        ok, _ = self._run(self._SINGLE_SPACE_ALL_ON)
        assert ok is True

    def test_one_profile_off_returns_false(self):
        ok, msg = self._run(self._DOMAIN_OFF)
        assert ok is False
        assert "OFF" in msg or "disabled" in msg.lower()

    def test_all_profiles_off_returns_false(self):
        ok, _ = self._run(self._ALL_OFF)
        assert ok is False

    def test_empty_output_returns_false(self):
        ok, _ = self._run("")
        assert ok is False

    def test_command_failure_returns_false(self):
        ok, _ = self._run("", returncode=1)
        assert ok is False

    def test_exception_returns_false(self):
        from core.custom_functions.firewall import firewall_enabled
        with patch("core.custom_functions.firewall.subprocess.run", side_effect=OSError("no netsh")):
            ok, msg = firewall_enabled()
        assert ok is False
        assert "no netsh" in msg


# ============================================================
# Bug #3 — _RUN_CACHE: clear_cache / clear_all_caches
# ============================================================

class TestCacheClear:
    """Each custom-function module exposes clear_cache(); clear_all_caches()
    in __init__ clears every module in one call."""

    def _seed_and_clear(self, module_name: str) -> None:
        import importlib
        mod = importlib.import_module(f"core.custom_functions.{module_name}")
        # Directly write a sentinel into the module's cache
        mod._RUN_CACHE["__test_sentinel__"] = "stale"
        assert "__test_sentinel__" in mod._RUN_CACHE, "seed failed"
        mod.clear_cache()
        assert "__test_sentinel__" not in mod._RUN_CACHE, f"{module_name}: cache not cleared"

    def test_access_control_clear(self):
        self._seed_and_clear("access_control")

    def test_audit_accountability_clear(self):
        self._seed_and_clear("audit_accountability")

    def test_configuration_management_clear(self):
        self._seed_and_clear("configuration_management")

    def test_identification_authentication_clear(self):
        self._seed_and_clear("identification_authentication")

    def test_system_communications_protection_clear(self):
        self._seed_and_clear("system_communications_protection")

    def test_system_information_integrity_clear(self):
        self._seed_and_clear("system_information_integrity")

    def test_clear_all_caches_clears_every_module(self):
        import importlib
        from core.custom_functions import clear_all_caches

        modules = [
            "access_control",
            "audit_accountability",
            "configuration_management",
            "identification_authentication",
            "system_communications_protection",
            "system_information_integrity",
        ]
        for name in modules:
            mod = importlib.import_module(f"core.custom_functions.{name}")
            mod._RUN_CACHE["__sentinel__"] = "stale"

        clear_all_caches()

        for name in modules:
            mod = importlib.import_module(f"core.custom_functions.{name}")
            assert "__sentinel__" not in mod._RUN_CACHE, f"{name}: still has stale cache after clear_all_caches()"

    def test_run_scan_clears_cache_before_scan(self, tmp_path):
        """cli.run_scan() must call clear_all_caches() before executing rules.

        clear_all_caches is imported locally inside run_scan(), so we patch the
        function on its home module (core.custom_functions) rather than on cli.
        """
        import cli
        sentinel_cleared = []

        def fake_clear():
            sentinel_cleared.append(True)

        # Write a trivial rule file so run_scan has something to process
        rule = {
            "id": "CACHE.01", "rule_id": "CACHE.01", "title": "cache test",
            "check_details": {}
        }
        rule_file = tmp_path / "cache_rule.json"
        rule_file.write_text(json.dumps(rule), encoding="utf-8")

        with patch("core.custom_functions.clear_all_caches", fake_clear):
            cli.run_scan([str(rule_file)], max_workers=1)

        assert sentinel_cleared, "run_scan() did not call clear_all_caches()"


# ============================================================
# Bug #4 — authorized_user_ws: validate output, not just exit code
# ============================================================

class TestAuthorizedUserWs:
    """authorized_user_ws() must inspect the returned user list, not just
    return True whenever Get-ADUser exits 0."""

    def _call(self, returncode: int, stdout: str):
        from core.custom_functions.access_control import authorized_user_ws
        fake_result = {"returncode": returncode, "stdout": stdout, "stderr": ""}
        with patch("core.custom_functions.access_control.run_command", return_value=fake_result):
            return authorized_user_ws()

    def _users_json(self, users: list[dict]) -> str:
        return json.dumps(users)

    def test_enabled_named_user_returns_true(self):
        users = [{"Name": "Alice Smith", "Enabled": True}]
        result = self._call(0, self._users_json(users))
        # Result may be bool or (bool, str) depending on _normalize_check_outputs wrapping
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is True

    def test_multiple_enabled_users_returns_true(self):
        users = [
            {"Name": "Alice Smith", "Enabled": True},
            {"Name": "Bob Jones",   "Enabled": True},
        ]
        result = self._call(0, self._users_json(users))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is True

    def test_only_disabled_users_returns_false(self):
        users = [{"Name": "Alice Smith", "Enabled": False}]
        result = self._call(0, self._users_json(users))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_only_guest_returns_false(self):
        """guest is a system account and must not satisfy the check."""
        users = [{"Name": "Guest", "Enabled": True}]
        result = self._call(0, self._users_json(users))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_only_krbtgt_returns_false(self):
        users = [{"Name": "krbtgt", "Enabled": True}]
        result = self._call(0, self._users_json(users))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_system_and_named_user_returns_true(self):
        """A mix of system accounts and a real user should pass."""
        users = [
            {"Name": "Guest",      "Enabled": False},
            {"Name": "krbtgt",     "Enabled": False},
            {"Name": "Alice Smith","Enabled": True},
        ]
        result = self._call(0, self._users_json(users))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is True

    def test_command_failure_returns_false(self):
        result = self._call(1, "")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_invalid_json_returns_false(self):
        result = self._call(0, "not valid json {{{")
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_empty_user_list_returns_false(self):
        result = self._call(0, self._users_json([]))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is False

    def test_single_dict_not_list_handled(self):
        """Get-ADUser returns a dict (not list) when exactly one user exists."""
        user = {"Name": "Solo User", "Enabled": True}
        result = self._call(0, json.dumps(user))
        ok = result[0] if isinstance(result, tuple) else result
        assert ok is True
