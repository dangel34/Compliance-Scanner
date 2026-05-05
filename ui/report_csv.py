"""
CSV report generation for RuleForge.

Produces a flat CSV where each row represents one check within a rule,
suitable for import into spreadsheet tools or further analysis.
"""
from __future__ import annotations

import csv
from typing import Dict

from ui.utils import RunResult, _safe_str, get_rule_status

_COL_RULE_ID = "Rule ID"
_COL_OVERALL_STATUS = "Overall Status"
_COL_CHECK_NUM = "Check #"
_COL_CHECK_NAME = "Check Name"
_COL_EXPECTED = "Expected Result"
_COL_RETURN_CODE = "Return Code"

_CSV_FIELDS = [
    _COL_RULE_ID, "Title", "OS", _COL_OVERALL_STATUS,
    _COL_CHECK_NUM, _COL_CHECK_NAME, "Subcontrol", "Status",
    _COL_EXPECTED, _COL_RETURN_CODE, "Stdout", "Stderr", "Error",
]


def generate_report_csv(
    save_path: str,
    results_by_path: Dict[str, RunResult],
) -> None:
    """
    Write results to *save_path* as a UTF-8 CSV (BOM-prefixed for Excel
    compatibility). Each check gets its own row; rules with no checks still
    emit one row so nothing is silently omitted.
    """
    with open(save_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        writer.writeheader()

        for result in results_by_path.values():
            rule_id        = _safe_str(result.get("rule_id", ""))
            title          = _safe_str(result.get("title",   ""))
            detected_os    = _safe_str(result.get("os",      ""))
            overall_status = get_rule_status(result)
            error          = _safe_str(result.get("error",   ""))

            checks = result.get("checks", [])
            if not checks:
                writer.writerow({
                    _COL_RULE_ID:         rule_id,
                    "Title":           title,
                    "OS":              detected_os,
                    _COL_OVERALL_STATUS:  overall_status,
                    _COL_CHECK_NUM:         "",
                    _COL_CHECK_NAME:      "",
                    "Subcontrol":      "",
                    "Status":          "",
                    _COL_EXPECTED: "",
                    _COL_RETURN_CODE:     "",
                    "Stdout":          "",
                    "Stderr":          "",
                    "Error":           error,
                })
            else:
                for i, check in enumerate(checks, start=1):
                    writer.writerow({
                        _COL_RULE_ID:         rule_id,
                        "Title":           title,
                        "OS":              detected_os,
                        _COL_OVERALL_STATUS:  overall_status,
                        _COL_CHECK_NUM:         i,
                        _COL_CHECK_NAME:      _safe_str(check.get("check_name",      ""), max_len=256),
                        "Subcontrol":      _safe_str(check.get("sub_control",     ""), max_len=64),
                        "Status":          _safe_str(check.get("status",          ""), max_len=32),
                        _COL_EXPECTED: _safe_str(check.get("expected_result", ""), max_len=256),
                        _COL_RETURN_CODE:     _safe_str(str(check.get("returncode",  "")), max_len=32),
                        "Stdout":          _safe_str(check.get("stdout",          ""), max_len=1024),
                        "Stderr":          _safe_str(check.get("stderr",          ""), max_len=1024),
                        "Error":           error,
                    })
