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

    # --- trusted NTP domains constant ---

    def test_trusted_ntp_domains_is_frozenset(self):
        from core.custom_functions.audit_accountability import _TRUSTED_NTP_DOMAINS
        assert isinstance(_TRUSTED_NTP_DOMAINS, frozenset)

    def test_trusted_ntp_domains_contains_nist(self):
        from core.custom_functions.audit_accountability import _TRUSTED_NTP_DOMAINS
        assert "time.nist.gov" in _TRUSTED_NTP_DOMAINS

    def test_trusted_ntp_domains_contains_ntp_org(self):
        from core.custom_functions.audit_accountability import _TRUSTED_NTP_DOMAINS
        assert "pool.ntp.org" in _TRUSTED_NTP_DOMAINS


class TestIsTrustedNtpHost:
    """Unit tests for the _is_trusted_ntp_host() helper function."""

    def _check(self, token: str) -> bool:
        from core.custom_functions.audit_accountability import _is_trusted_ntp_host
        return _is_trusted_ntp_host(token)

    def test_exact_time_nist_gov(self):
        assert self._check("time.nist.gov")

    def test_exact_pool_ntp_org(self):
        assert self._check("pool.ntp.org")

    def test_subdomain_of_pool_ntp_org(self):
        assert self._check("0.pool.ntp.org")

    def test_flag_suffix_stripped(self):
        """Token 'time.nist.gov,0x1' — comma-suffix must be stripped before check."""
        assert self._check("time.nist.gov,0x1")

    def test_flag_suffix_pool(self):
        assert self._check("pool.ntp.org,0x8")

    def test_prefix_spoof_rejected(self):
        """'eviltime.nist.gov' shares the trusted domain but is not a subdomain."""
        assert not self._check("eviltime.nist.gov")

    def test_suffix_spoof_rejected(self):
        """'time.nist.gov.attacker.com' has the trusted string as a prefix."""
        assert not self._check("time.nist.gov.attacker.com")

    def test_unrelated_domain_rejected(self):
        assert not self._check("time.windows.com")

    def test_empty_token_rejected(self):
        assert not self._check("")

    def test_just_flag_stripped_to_empty(self):
        assert not self._check(",0x1")
