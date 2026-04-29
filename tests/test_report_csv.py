"""Tests for ui/report_csv.py — generate_report_csv()."""
from __future__ import annotations

import csv
import io


from ui.report_csv import generate_report_csv, _CSV_FIELDS


def _make_result(rule_id="R.01", title="Test Rule", status="PASS", checks=None, error=None):
    result = {
        "rule_id": rule_id,
        "title":   title,
        "os":      "windows_client",
        "checks":  checks if checks is not None else [
            {
                "status":          status,
                "check_name":      "My check",
                "sub_control":     "1.1",
                "expected_result": "pass expected",
                "returncode":      0 if status == "PASS" else 1,
                "stdout":          "output here",
                "stderr":          "",
            }
        ],
    }
    if error:
        result["error"] = error
    return result


class TestCsvFileCreation:
    def test_creates_file(self, tmp_path):
        out = tmp_path / "report.csv"
        generate_report_csv(str(out), {"p": _make_result()})
        assert out.exists()

    def test_file_readable_with_utf8_bom(self, tmp_path):
        out = tmp_path / "report.csv"
        generate_report_csv(str(out), {"p": _make_result()})
        content = out.read_bytes()
        assert content[:3] == b"\xef\xbb\xbf", "File must start with UTF-8 BOM for Excel compatibility"

    def test_empty_results_writes_header_only(self, tmp_path):
        out = tmp_path / "empty.csv"
        generate_report_csv(str(out), {})
        rows = list(csv.DictReader(io.StringIO(out.read_text(encoding="utf-8-sig"))))
        assert rows == []


class TestCsvHeader:
    def test_all_expected_columns_present(self, tmp_path):
        out = tmp_path / "report.csv"
        generate_report_csv(str(out), {"p": _make_result()})
        with open(str(out), encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for col in _CSV_FIELDS:
                assert col in reader.fieldnames, f"Missing column: {col}"

    def test_column_order_matches_csv_fields(self, tmp_path):
        out = tmp_path / "report.csv"
        generate_report_csv(str(out), {"p": _make_result()})
        with open(str(out), encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            assert list(reader.fieldnames) == _CSV_FIELDS


class TestCsvDataRows:
    def _rows(self, tmp_path, results: dict) -> list[dict]:
        out = tmp_path / "report.csv"
        generate_report_csv(str(out), results)
        with open(str(out), encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))

    def test_single_check_produces_one_row(self, tmp_path):
        rows = self._rows(tmp_path, {"p": _make_result()})
        assert len(rows) == 1

    def test_rule_id_in_row(self, tmp_path):
        rows = self._rows(tmp_path, {"p": _make_result(rule_id="AC.01")})
        assert rows[0]["Rule ID"] == "AC.01"

    def test_title_in_row(self, tmp_path):
        rows = self._rows(tmp_path, {"p": _make_result(title="My Rule")})
        assert rows[0]["Title"] == "My Rule"

    def test_status_in_row(self, tmp_path):
        rows = self._rows(tmp_path, {"p": _make_result(status="FAIL")})
        assert rows[0]["Status"] == "FAIL"

    def test_check_number_starts_at_one(self, tmp_path):
        rows = self._rows(tmp_path, {"p": _make_result()})
        assert rows[0]["Check #"] == "1"

    def test_multiple_checks_numbered_sequentially(self, tmp_path):
        checks = [
            {"status": "PASS", "check_name": "c1", "sub_control": "", "expected_result": "",
             "returncode": 0, "stdout": "", "stderr": ""},
            {"status": "FAIL", "check_name": "c2", "sub_control": "", "expected_result": "",
             "returncode": 1, "stdout": "", "stderr": ""},
        ]
        rows = self._rows(tmp_path, {"p": _make_result(checks=checks)})
        assert len(rows) == 2
        assert rows[0]["Check #"] == "1"
        assert rows[1]["Check #"] == "2"

    def test_policy_check_included_in_csv(self, tmp_path):
        checks = [
            {"status": "POLICY", "check_name": "policy check", "sub_control": "",
             "expected_result": "human review", "returncode": None, "stdout": "", "stderr": ""},
        ]
        rows = self._rows(tmp_path, {"p": _make_result(checks=checks)})
        assert len(rows) == 1
        assert rows[0]["Status"] == "POLICY"

    def test_empty_checks_emits_one_placeholder_row(self, tmp_path):
        result = _make_result(checks=[])
        rows = self._rows(tmp_path, {"p": result})
        assert len(rows) == 1
        assert rows[0]["Check #"] == ""
        assert rows[0]["Status"] == ""
        assert rows[0]["Rule ID"] == "R.01"

    def test_overall_status_reflects_rule_status(self, tmp_path):
        rows = self._rows(tmp_path, {"p": _make_result(status="PASS")})
        assert rows[0]["Overall Status"] == "PASS"

    def test_error_field_populated_when_error_present(self, tmp_path):
        result = _make_result(checks=[], error="something crashed")
        rows = self._rows(tmp_path, {"p": result})
        assert "something crashed" in rows[0]["Error"]

    def test_no_error_field_empty_on_clean_result(self, tmp_path):
        rows = self._rows(tmp_path, {"p": _make_result()})
        assert rows[0]["Error"] == ""

    def test_multiple_rules_all_appear(self, tmp_path):
        results = {
            "p1": _make_result(rule_id="R.01"),
            "p2": _make_result(rule_id="R.02"),
        }
        rows = self._rows(tmp_path, results)
        rule_ids = {r["Rule ID"] for r in rows}
        assert "R.01" in rule_ids
        assert "R.02" in rule_ids

    def test_stdout_included_in_row(self, tmp_path):
        checks = [
            {"status": "PASS", "check_name": "c", "sub_control": "", "expected_result": "",
             "returncode": 0, "stdout": "hello output", "stderr": ""},
        ]
        rows = self._rows(tmp_path, {"p": _make_result(checks=checks)})
        assert "hello output" in rows[0]["Stdout"]
