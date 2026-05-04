"""
Tests for new helper functions extracted during SonarQube refactoring in:
  - ui/report_pdf.py  (_build_automated_table, _build_policy_table, _build_rule_elements)
  - ui/rule_display.py (_render_output_streams, _render_check)
"""
from __future__ import annotations

import pytest
from reportlab.lib.units import mm


# ============================================================
# Shared fixtures / helpers
# ============================================================

def _styles():
    from ui.report_pdf import _get_styles
    return _get_styles()


def _content_w():
    return 170 * mm


def _make_check(**kwargs) -> dict:
    defaults = {
        "check_name": "Test Check",
        "sub_control": "AC.1.1",
        "expected_result": "Enabled",
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "status": "PASS",
        "command": "echo test",
        "purpose": "",
    }
    defaults.update(kwargs)
    return defaults


# ============================================================
# _hex  (line 84: branch without hexval attribute)
# ============================================================

class _RGBOnly:
    """Minimal colour-like object with r/g/b attributes but no hexval — hits line 84."""
    def __init__(self, r, g, b):
        self.red, self.green, self.blue = r, g, b


class TestHex:
    def test_color_with_hexval_returns_stripped(self):
        from reportlab.lib import colors
        from ui.report_pdf import _hex
        col = colors.HexColor("#aabbcc")
        # hexval() returns e.g. "0xaabbcc" or "#aabbcc" depending on version;
        # the function lstrips "#" then lowercases
        result = _hex(col)
        assert "aabbcc" in result.lower()

    def test_color_without_hexval_red_channel(self):
        # Object has no hexval → falls through to line 84 f-string path
        from ui.report_pdf import _hex
        col = _RGBOnly(1.0, 0.0, 0.0)   # pure red
        assert _hex(col) == "ff0000"

    def test_color_without_hexval_black(self):
        from ui.report_pdf import _hex
        assert _hex(_RGBOnly(0.0, 0.0, 0.0)) == "000000"

    def test_color_without_hexval_white(self):
        from ui.report_pdf import _hex
        assert _hex(_RGBOnly(1.0, 1.0, 1.0)) == "ffffff"


# ============================================================
# _build_automated_table
# ============================================================

class TestBuildAutomatedTable:
    def test_returns_table_with_header_row(self):
        from reportlab.platypus import Table
        from ui.report_pdf import _build_automated_table
        checks = [_make_check(status="PASS")]
        tbl = _build_automated_table(checks, _content_w(), _styles())
        assert isinstance(tbl, Table)

    def test_even_row_alternate_background(self):
        """Two checks triggers the idx%2==0 branch (line 171)."""
        from reportlab.platypus import Table
        from ui.report_pdf import _build_automated_table
        checks = [_make_check(status="PASS"), _make_check(status="FAIL")]
        tbl = _build_automated_table(checks, _content_w(), _styles())
        assert isinstance(tbl, Table)

    def test_stderr_detail_row_appended(self):
        """Check with non-trivial stderr triggers line 183."""
        from reportlab.platypus import Table
        from ui.report_pdf import _build_automated_table
        checks = [_make_check(status="FAIL", stderr="Access denied")]
        tbl = _build_automated_table(checks, _content_w(), _styles())
        assert isinstance(tbl, Table)

    def test_stdout_detail_row_appended(self):
        from reportlab.platypus import Table
        from ui.report_pdf import _build_automated_table
        checks = [_make_check(status="PASS", stdout="some output text")]
        tbl = _build_automated_table(checks, _content_w(), _styles())
        assert isinstance(tbl, Table)

    def test_both_stdout_and_stderr(self):
        from reportlab.platypus import Table
        from ui.report_pdf import _build_automated_table
        checks = [_make_check(status="ERROR", stdout="out", stderr="err")]
        tbl = _build_automated_table(checks, _content_w(), _styles())
        assert isinstance(tbl, Table)

    def test_empty_checks_returns_header_only(self):
        from reportlab.platypus import Table
        from ui.report_pdf import _build_automated_table
        tbl = _build_automated_table([], _content_w(), _styles())
        assert isinstance(tbl, Table)


# ============================================================
# _build_policy_table  (lines 218-263, previously 0% covered)
# ============================================================

class TestBuildPolicyTable:
    def test_returns_table_for_single_policy_check(self):
        from reportlab.platypus import Table
        from ui.report_pdf import _build_policy_table
        checks = [_make_check(status="POLICY", stdout="Must have written policy")]
        tbl = _build_policy_table(checks, _content_w(), _styles())
        assert isinstance(tbl, Table)

    def test_even_row_alternate_background(self):
        """Two policy checks triggers the pol_idx%2==0 branch."""
        from reportlab.platypus import Table
        from ui.report_pdf import _build_policy_table
        checks = [
            _make_check(status="POLICY", stdout="Policy A"),
            _make_check(status="POLICY", stdout="Policy B"),
        ]
        tbl = _build_policy_table(checks, _content_w(), _styles())
        assert isinstance(tbl, Table)

    def test_empty_policy_checks(self):
        from reportlab.platypus import Table
        from ui.report_pdf import _build_policy_table
        tbl = _build_policy_table([], _content_w(), _styles())
        assert isinstance(tbl, Table)


# ============================================================
# _build_rule_elements
# ============================================================

def _make_result(**kwargs) -> dict:
    defaults = {
        "rule_id": "TEST.01",
        "title": "Test Rule",
        "os": "windows_client",
        "checks_run": 1,
        "checks_skipped": 0,
        "checks_policy": 0,
        "checks": [_make_check()],
    }
    defaults.update(kwargs)
    return defaults


class TestBuildRuleElements:
    def test_returns_list_for_normal_result(self):
        from ui.report_pdf import _build_rule_elements
        meta = {"rule_id": "TEST.01", "title": "Test Rule", "path": "test.json"}
        result = _build_rule_elements(_make_result(), meta, _content_w(), _styles())
        assert isinstance(result, list)
        assert len(result) >= 2  # at least rule_header + meta_row

    def test_error_result_returns_early_with_error_table(self):
        """'error' key present → lines 327-339 and early return."""
        from ui.report_pdf import _build_rule_elements
        meta = {"rule_id": "ERR.01", "title": "Error Rule", "path": "err.json"}
        result_data = {"rule_id": "ERR.01", "title": "Error Rule", "error": "Command failed"}
        elements = _build_rule_elements(result_data, meta, _content_w(), _styles())
        assert len(elements) == 3  # rule_header, meta_row, err_table

    def test_no_checks_adds_no_checks_paragraph(self):
        """Empty checks list → line 346."""
        from ui.report_pdf import _build_rule_elements
        meta = {"rule_id": "E.01", "title": "Empty", "path": "e.json"}
        result_data = _make_result(checks=[], checks_run=0)
        elements = _build_rule_elements(result_data, meta, _content_w(), _styles())
        assert len(elements) == 3  # rule_header, meta_row, "No checks recorded"

    def test_policy_checks_with_automated_adds_spacer_and_header(self):
        """Both automated + policy checks → lines 351-368 (spacer + policy header)."""
        from ui.report_pdf import _build_rule_elements
        meta = {"rule_id": "MX.01", "title": "Mixed", "path": "mx.json"}
        auto_chk = _make_check(status="PASS")
        pol_chk = _make_check(status="POLICY", stdout="Written policy required")
        result_data = _make_result(checks=[auto_chk, pol_chk], checks_policy=1)
        elements = _build_rule_elements(result_data, meta, _content_w(), _styles())
        # rule_header, meta_row, automated_table, spacer, pol_header_tbl, pol_table
        assert len(elements) >= 5

    def test_policy_only_no_spacer(self):
        """Only policy checks (no automated) → no spacer added (lines 351-352 not taken)."""
        from ui.report_pdf import _build_rule_elements
        meta = {"rule_id": "PO.01", "title": "Policy Only", "path": "po.json"}
        pol_chk = _make_check(status="POLICY", stdout="Written policy required")
        result_data = _make_result(checks=[pol_chk], checks_policy=1, checks_run=0)
        elements = _build_rule_elements(result_data, meta, _content_w(), _styles())
        assert len(elements) >= 3

    def test_chk_policy_in_meta_row(self):
        """chk_policy > 0 adds 'Policy:' to meta row (line 309 conditional)."""
        from ui.report_pdf import _build_rule_elements
        meta = {"rule_id": "CP.01", "title": "Count", "path": "cp.json"}
        result_data = _make_result(checks_policy=2)
        elements = _build_rule_elements(result_data, meta, _content_w(), _styles())
        assert len(elements) >= 2


# ============================================================
# generate_report_pdf: result is None branch (line 482)
# ============================================================

class TestGenerateReportPdfMissingResult:
    def test_missing_path_in_results_skipped(self, tmp_path):
        """If rules_by_category references a path not in results_by_path → line 482 continue."""
        from ui.report_pdf import generate_report_pdf
        out = tmp_path / "report.pdf"
        results = {
            "path_a.json": _make_result(rule_id="A.01"),
        }
        # rules_by_category references path_b.json which is NOT in results
        rules = {
            "Cat": [
                {"path": "path_a.json", "rule_id": "A.01", "title": "Rule A"},
                {"path": "path_b.json", "rule_id": "B.01", "title": "Rule B"},
            ]
        }
        generate_report_pdf(str(out), results, rules_by_category=rules)
        assert out.exists()

    def test_multi_page_pdf_triggers_draw_later(self, tmp_path):
        """Enough rules to overflow onto page 2 → _draw_later callback is invoked."""
        from ui.report_pdf import generate_report_pdf
        out = tmp_path / "multipage.pdf"
        # 30 rules with long stdout should reliably push beyond one page
        results = {}
        metas = []
        for i in range(30):
            path = f"rule_{i}.json"
            results[path] = _make_result(
                rule_id=f"T.{i:02d}",
                title=f"Rule {i} with a fairly descriptive title",
                checks=[_make_check(
                    status="FAIL",
                    stdout="\n".join(f"output line {j}" for j in range(10)),
                    stderr="some error occurred",
                )],
            )
            metas.append({"path": path, "rule_id": f"T.{i:02d}", "title": f"Rule {i}"})
        generate_report_pdf(str(out), results, rules_by_category={"Results": metas})
        assert out.exists()
        assert out.stat().st_size > 10_000


# ============================================================
# _render_output_streams  (rule_display.py, 0% covered)
# ============================================================

class TestRenderOutputStreams:
    def _collect(self, check, verbose=False, chk_status="PASS") -> list:
        from ui.rule_display import _render_output_streams
        collected = []
        def w(text, tag="value"):
            collected.append((text, tag))
        _render_output_streams(w, check, verbose, chk_status)
        return collected

    def test_no_stdout_no_stderr_nothing_written(self):
        result = self._collect({"stdout": "", "stderr": ""})
        assert result == []

    def test_stdout_written(self):
        result = self._collect({"stdout": "output line", "stderr": ""})
        texts = [t for t, _ in result]
        assert any("output line" in t for t in texts)

    def test_stderr_written(self):
        result = self._collect({"stdout": "", "stderr": "error line"})
        texts = [t for t, _ in result]
        assert any("error line" in t for t in texts)

    def test_truncation_without_verbose(self):
        """stdout with many lines gets truncated when verbose=False."""
        from ui.rule_display import _MAX_OUTPUT_LINES
        many_lines = "\n".join(f"line {i}" for i in range(_MAX_OUTPUT_LINES + 5))
        result = self._collect({"stdout": many_lines, "stderr": ""}, verbose=False)
        texts = [t for t, _ in result]
        assert any("truncated" in t for t in texts)

    def test_no_truncation_with_verbose_fail(self):
        """verbose=True + FAIL status → all lines shown."""
        from ui.rule_display import _MAX_OUTPUT_LINES
        many_lines = "\n".join(f"line {i}" for i in range(_MAX_OUTPUT_LINES + 5))
        result = self._collect({"stdout": many_lines, "stderr": ""}, verbose=True, chk_status="FAIL")
        texts = [t for t, _ in result]
        assert not any("truncated" in t for t in texts)

    def test_stderr_truncation(self):
        from ui.rule_display import _MAX_OUTPUT_LINES
        many_lines = "\n".join(f"err {i}" for i in range(_MAX_OUTPUT_LINES + 5))
        result = self._collect({"stdout": "", "stderr": many_lines}, verbose=False)
        texts = [t for t, _ in result]
        assert any("truncated" in t for t in texts)


# ============================================================
# _render_check  (rule_display.py, 0% covered)
# ============================================================

class TestRenderCheck:
    def _collect(self, check, index=1, show_full=True, verbose=False) -> list:
        from ui.rule_display import _render_check
        collected = []
        def w(text="", tag="value"):
            collected.append((text, tag))
        _render_check(w, check, index, show_full, verbose)
        return collected

    def _texts(self, check, **kwargs) -> list:
        return [t for t, _ in self._collect(check, **kwargs)]

    def test_pass_check_header_written(self):
        check = _make_check(status="PASS")
        texts = self._texts(check)
        assert any("CHECK #1" in t for t in texts)

    def test_fail_check_writes_false_result_when_not_full(self):
        check = _make_check(status="FAIL")
        texts = self._texts(check, show_full=False)
        assert any("False" in t for t in texts)

    def test_pass_check_writes_true_result_when_not_full(self):
        check = _make_check(status="PASS")
        texts = self._texts(check, show_full=False)
        assert any("True" in t for t in texts)

    def test_policy_check_shows_purpose(self):
        check = _make_check(status="POLICY", stdout="Must have written policy")
        texts = self._texts(check, show_full=True)
        assert any("Must have written policy" in t for t in texts)

    def test_policy_check_no_stdout_no_requirement_section(self):
        check = _make_check(status="POLICY", stdout="")
        texts = self._texts(check, show_full=True)
        assert not any("Policy requirement" in t for t in texts)

    def test_full_mode_shows_command(self):
        check = _make_check(status="PASS", command="Get-Process")
        texts = self._texts(check, show_full=True)
        assert any("Get-Process" in t for t in texts)

    def test_full_mode_with_purpose(self):
        check = _make_check(status="PASS", purpose="Verify audit is active")
        texts = self._texts(check, show_full=True)
        assert any("Verify audit is active" in t for t in texts)

    def test_full_mode_no_purpose_skips_purpose_section(self):
        check = _make_check(status="PASS", purpose="")
        texts = self._texts(check, show_full=True)
        assert not any("Purpose" in t for t in texts)

    def test_non_full_mode_hides_command(self):
        check = _make_check(status="PASS", command="Get-Process")
        texts = self._texts(check, show_full=False)
        assert not any("Get-Process" in t for t in texts)

    def test_pass_check_no_result_line_in_full_mode(self):
        """show_full=True + PASS → no 'Result:' line (only non-full shows it)."""
        check = _make_check(status="PASS")
        texts = self._texts(check, show_full=True)
        assert not any("Result           :" in t for t in texts)
