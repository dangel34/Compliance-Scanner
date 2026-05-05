"""
Tests for CodeQL security fixes.

Covers:
  - CWE-20 Incomplete URL substring sanitization in pdc_ntp_source_ws()
    (audit_accountability.py) — verifies that lookahead/lookbehind regex
    rejects partial-domain bypass strings that the old 'in' check would accept.
"""
from __future__ import annotations

from unittest.mock import patch

MOD = "core.custom_functions.audit_accountability"


def _ps_result(rc=0, stdout="", stderr=""):
    """Build a mock return value for _ps()."""
    from unittest.mock import MagicMock
    m = MagicMock()
    m.returncode = rc
    m.stdout = stdout
    m.stderr = stderr
    return m


def _call_pdc_ntp(stdout: str, rc: int = 0):
    with patch(f"{MOD}._ps", return_value=(rc, stdout, "")):
        from core.custom_functions.audit_accountability import pdc_ntp_source_ws
        return pdc_ntp_source_ws()


class TestPdcNtpSourceWs:
    # --- happy paths ---

    def test_time_nist_gov_passes(self):
        ok, msg = _call_pdc_ntp("NtpServer time.nist.gov,0x1")
        assert ok

    def test_pool_ntp_org_passes(self):
        ok, msg = _call_pdc_ntp("NtpServer pool.ntp.org,0x8")
        assert ok

    def test_subdomain_of_pool_ntp_org_passes(self):
        ok, msg = _call_pdc_ntp("NtpServer 0.pool.ntp.org,0x8")
        assert ok

    def test_ip_address_passes(self):
        ok, msg = _call_pdc_ntp("NtpServer 192.168.1.1,0x1")
        assert ok

    def test_public_ip_passes(self):
        ok, msg = _call_pdc_ntp("NtpServer 129.6.15.28,0x1")
        assert ok

    # --- bypass attempts that the old `in` check would have accepted ---

    def test_prefix_spoof_rejected(self):
        """'eviltime.nist.gov' embeds the trusted domain as a suffix — must fail."""
        ok, _ = _call_pdc_ntp("NtpServer eviltime.nist.gov,0x1")
        assert not ok

    def test_suffix_spoof_rejected(self):
        """'time.nist.gov.attacker.com' embeds the trusted domain as a prefix — must fail."""
        ok, _ = _call_pdc_ntp("NtpServer time.nist.gov.attacker.com,0x1")
        assert not ok

    def test_embedded_spoof_rejected(self):
        """A server name that contains the trusted string mid-token must fail."""
        ok, _ = _call_pdc_ntp("NtpServer faketime.nist.gov.evil.com,0x1")
        assert not ok

    # --- failure paths ---

    def test_empty_ntpserver_returns_false(self):
        ok, _ = _call_pdc_ntp("")
        assert not ok

    def test_unknown_server_returns_false(self):
        ok, _ = _call_pdc_ntp("NtpServer time.windows.com,0x9")
        assert not ok

    def test_powershell_failure_returns_false(self):
        ok, _ = _call_pdc_ntp("", rc=1)
        assert not ok

    # --- trusted NTP regex constant ---

    def test_trusted_ntp_regex_is_compiled(self):
        from core.custom_functions.audit_accountability import _TRUSTED_NTP_RE
        import re
        assert isinstance(_TRUSTED_NTP_RE, re.Pattern)

    def test_trusted_ntp_regex_matches_exact_domain(self):
        from core.custom_functions.audit_accountability import _TRUSTED_NTP_RE
        assert _TRUSTED_NTP_RE.search("time.nist.gov")
        assert _TRUSTED_NTP_RE.search("pool.ntp.org")

    def test_trusted_ntp_regex_rejects_spoof(self):
        from core.custom_functions.audit_accountability import _TRUSTED_NTP_RE
        assert not _TRUSTED_NTP_RE.search("eviltime.nist.gov")
        assert not _TRUSTED_NTP_RE.search("time.nist.gov.evil.com")
