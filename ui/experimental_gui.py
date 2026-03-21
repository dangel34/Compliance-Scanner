"""
Threading GUI for the Compliance Scanner.

Uses background threads for rule execution so the UI stays responsive.
Similar structure to main_gui.py but with async run behavior.
"""
from __future__ import annotations

import datetime
import json
import os
import sys
import threading
import re
from tkinter import filedialog
from typing import Any, Dict, List, Optional

import customtkinter as ctk

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import KeepTogether

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core import os_scan
from core.rule_runner import RuleRunner

RunResult = Dict[str, Any]


def get_project_root() -> str:
    """
    Return the project root folder (parent of ui/).

    :return: Absolute path to the project root directory.
    """
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def format_os_name(os_name: str) -> str:
    """Format operating system name for display (e.g. windows_client -> Windows Client)."""
    return os_name.replace("_", " ").title()


def discover_rule_files(rules_dir: str) -> Dict[str, List[str]]:
    """
    Find all .json rule files under a directory (recursively), grouped by
    the ``"category"`` field inside each JSON file.

    Rules whose JSON is missing a ``"category"`` field are placed under
    ``"Uncategorised"``.  ``rule_template.json`` is always skipped.

    :param rules_dir: Base directory to search for rule JSON files.
    :return: Dict mapping category name -> sorted list of absolute rule paths.
    """
    categories: Dict[str, List[str]] = {}
    if not os.path.isdir(rules_dir):
        return categories

    for root, _, files in os.walk(rules_dir):
        for name in sorted(files):
            if not name.lower().endswith(".json"):
                continue
            if name.lower() == "rule_template.json":
                continue

            full_path = os.path.join(root, name)

            # Read the category field from the JSON; fall back gracefully.
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                category = str(data.get("category") or "Uncategorised").strip()
                if not category:
                    category = "Uncategorised"
            except Exception:
                category = "Uncategorised"

            categories.setdefault(category, []).append(full_path)

    # Sort rules within each category; sort categories alphabetically,
    # but always push "Uncategorised" to the bottom.
    def _cat_sort_key(cat: str) -> tuple:
        return (cat.lower() == "uncategorised", cat.lower())

    def _natural_key(path: str) -> list:
        """Split a filename into text/int chunks so 3.5.2 sorts before 3.5.10."""
        name = os.path.basename(path)
        return [
            int(chunk) if chunk.isdigit() else chunk.lower()
            for chunk in re.split(r"(\d+)", name)
        ]

    return {
        cat: sorted(paths, key=_natural_key)
        for cat, paths in sorted(categories.items(), key=lambda kv: _cat_sort_key(kv[0]))
    }


def load_rule_metadata(rule_path: str) -> Dict[str, str]:
    """
    Read a rule JSON and extract minimal metadata for the UI.

    :param rule_path: Absolute path to a rule JSON file.
    :return: Dict with path, rule_id, title.
    """
    filename = os.path.basename(rule_path)
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "path": rule_path,
            "rule_id": str(data.get("id") or data.get("rule_id") or filename),
            "title": str(data.get("title") or data.get("control_number") or filename),
        }
    except Exception:
        return {"path": rule_path, "rule_id": filename, "title": filename}


def get_rule_status(result: RunResult) -> str:
    """
    Compute overall status for a rule result.

    If all subcontrols pass -> ``PASS``
    If all subcontrols fail -> ``FAIL``
    If some pass but not all -> ``PARTIAL``
    If the rule has no checks for this OS -> ``SKIP``
    If the rule errored -> ``ERROR``
    If the rule has not been run -> ``NOT_RUN``

    :param result: Rule execution result dictionary.
    :return: One of 'PASS', 'FAIL', 'PARTIAL', 'ERROR', 'SKIP', or 'NOT_RUN'.
    """
    if result is None:
        return "NOT_RUN"
    if "error" in result:
        return "ERROR"
    checks = result.get("checks", [])
    if not checks:
        return "SKIP"

    statuses = [c.get("status") for c in checks]
    if all(s == "PASS" for s in statuses):
        return "PASS"
    if all(s == "FAIL" for s in statuses):
        return "FAIL"
    return "PARTIAL"


def format_rule_details(result: RunResult) -> str:
    """
    Format a RuleRunner result dict as readable text for the details pane.

    :param result: Rule execution result dictionary.
    :return: Multi-line human-readable string.
    """
    if "error" in result:
        return (
            "\n  " + "=" * 66 + "\n"
            f"  ERROR: {result.get('error', 'Unknown error')}\n"
            "  " + "=" * 66 + "\n"
            f"  Rule ID: {result.get('rule_id', '')}\n"
            f"  Title  : {result.get('title', '')}\n"
        )

    status = get_rule_status(result)
    checks_run = result.get("checks_run", 0)
    checks_skipped = result.get("checks_skipped", 0)

    lines: List[str] = [
        "",
        "  " + "=" * 66,
        f"  OVERALL STATUS: {status}",
        "  " + "=" * 66,
        "",
        f"  Rule ID       : {result.get('rule_id', '')}",
        f"  Title         : {result.get('title', '')}",
        f"  OS            : {result.get('os', '')}",
        f"  Checks Run    : {checks_run}",
        f"  Checks Skipped: {checks_skipped} (NA subcontrols)",
        "",
        "  " + "-" * 66,
    ]

    for i, check in enumerate(result.get("checks", []), start=1):
        lines.extend([
            "",
            f"  CHECK #{i}  |  {check.get('check_name', '')}",
            "  " + "-" * 66,
            f"  Subcontrol     : {check.get('sub_control', '')}",
            f"  Status         : {check.get('status', '')}",
            f"  Command Run    : {check.get('command', '')}",
            f"  Expected Result: {check.get('expected_result', '')}",
            f"  Return Code    : {check.get('returncode', '')}",
        ])
        stdout = check.get("stdout", "")
        stderr = check.get("stderr", "")
        if stdout:
            lines.extend(["", "  Command Output (stdout):", "  " + "-" * 40, "  " + stdout.replace("\n", "\n  ")])
        if stderr:
            lines.extend(["", "  Command Error (stderr):", "  " + "-" * 40, "  " + stderr.replace("\n", "\n  ")])
        lines.append("")
        lines.append("  " + "=" * 66)

    return "\n".join(lines) + "\n"


def run_rules_blocking(
    rule_paths: List[str],
    progress_cb: Optional[callable] = None,
) -> Dict[str, RunResult]:
    """
    Run rules synchronously (for use in worker thread).

    :param rule_paths: List of rule JSON paths.
    :param progress_cb: Optional callback (index, total, path) for progress.
    :return: Mapping of path to result dict.
    """
    results: Dict[str, RunResult] = {}
    total = len(rule_paths)
    for i, path in enumerate(rule_paths, start=1):
        if progress_cb:
            progress_cb(i, total, path)
        try:
            r = RuleRunner(rule_path=path, os_type=None).run_checks()
            results[path] = r
        except Exception as e:
            results[path] = {
                "rule_id": os.path.basename(path),
                "title": os.path.basename(path),
                "os": os_scan(),
                "checks_run": 0,
                "checks_skipped": 0,
                "checks": [],
                "error": str(e),
            }
    return results


# PDF report generation

# Colour palette
_COL_PASS    = colors.HexColor("#1a7a3a")
_COL_FAIL    = colors.HexColor("#7a1a1a")
_COL_PARTIAL = colors.HexColor("#7a5c00")
_COL_ERROR   = colors.HexColor("#7a1a1a")
_COL_SKIP    = colors.HexColor("#555555")
_COL_HEADER  = colors.HexColor("#1a1a2e")
_COL_ACCENT  = colors.HexColor("#3b8ed0")
_COL_ROW_ALT = colors.HexColor("#f4f6f8")
_COL_WHITE   = colors.white
_COL_LIGHT   = colors.HexColor("#dee2e6")

_STATUS_COLOR: Dict[str, Any] = {
    "PASS":    _COL_PASS,
    "FAIL":    _COL_FAIL,
    "PARTIAL": _COL_PARTIAL,
    "ERROR":   _COL_ERROR,
    "SKIP":    _COL_SKIP,
    "NOT_RUN": _COL_SKIP,
}

_STATUS_BG: Dict[str, Any] = {
    "PASS":    colors.HexColor("#d4edda"),
    "FAIL":    colors.HexColor("#f8d7da"),
    "PARTIAL": colors.HexColor("#fff3cd"),
    "ERROR":   colors.HexColor("#f8d7da"),
    "SKIP":    colors.HexColor("#e2e3e5"),
    "NOT_RUN": colors.HexColor("#e2e3e5"),
}


def _make_styles() -> Dict[str, ParagraphStyle]:
    """Return a dict of named ParagraphStyles for the report."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=22,
            textColor=_COL_WHITE,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#cccccc"),
            spaceAfter=2,
        ),
        "category": ParagraphStyle(
            "Category",
            parent=base["Heading1"],
            fontSize=13,
            textColor=_COL_HEADER,
            spaceBefore=14,
            spaceAfter=6,
            borderPad=4,
        ),
        "rule_id": ParagraphStyle(
            "RuleID",
            parent=base["Normal"],
            fontSize=10,
            textColor=_COL_HEADER,
            fontName="Helvetica-Bold",
        ),
        "rule_title": ParagraphStyle(
            "RuleTitle",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#444444"),
        ),
        "cell": ParagraphStyle(
            "Cell",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
        ),
        "cell_mono": ParagraphStyle(
            "CellMono",
            parent=base["Normal"],
            fontSize=7.5,
            fontName="Courier",
            leading=10,
        ),
        "cell_label": ParagraphStyle(
            "CellLabel",
            parent=base["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#555555"),
            leading=11,
        ),
        "status_text": ParagraphStyle(
            "StatusText",
            parent=base["Normal"],
            fontSize=8,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "error_text": ParagraphStyle(
            "ErrorText",
            parent=base["Normal"],
            fontSize=8,
            textColor=_COL_FAIL,
            leading=11,
        ),
        "no_checks": ParagraphStyle(
            "NoChecks",
            parent=base["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#888888"),
            leftIndent=8,
        ),
    }


def generate_report_pdf(
    save_path: str,
    results_by_path: Dict[str, RunResult],
    rules_by_category: Dict[str, List[Dict[str, str]]],
) -> None:
    """
    Write a PDF compliance report to *save_path* using reportlab.

    :param save_path: Destination file path (should end in .pdf).
    :param results_by_path: Mapping of rule path -> result dict.
    :param rules_by_category: Mapping of category -> list of rule metadata dicts.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detected_os = format_os_name(os_scan())

    total        = len(results_by_path)
    pass_count   = sum(1 for r in results_by_path.values() if get_rule_status(r) == "PASS")
    fail_count   = sum(1 for r in results_by_path.values() if get_rule_status(r) == "FAIL")
    partial_count= sum(1 for r in results_by_path.values() if get_rule_status(r) == "PARTIAL")
    error_count  = sum(1 for r in results_by_path.values() if get_rule_status(r) == "ERROR")
    skip_count   = sum(1 for r in results_by_path.values() if get_rule_status(r) == "SKIP")

    S = _make_styles()
    page_w, page_h = A4
    margin = 18 * mm
    content_w = page_w - 2 * margin

    story: List[Any] = []

    # Cover / header block                                                 #

    def _draw_header(canvas, doc):
        """Paint the dark header band on the first page only."""
        canvas.saveState()
        canvas.setFillColor(_COL_HEADER)
        canvas.rect(0, page_h - 52 * mm, page_w, 52 * mm, fill=True, stroke=False)
        canvas.restoreState()

    def _draw_later(canvas, doc):
        """No header band on subsequent pages — just a thin accent line at the top."""
        canvas.saveState()
        canvas.setFillColor(_COL_ACCENT)
        canvas.rect(0, page_h - 4 * mm, page_w, 4 * mm, fill=True, stroke=False)
        canvas.restoreState()

    # Spacer to push content below the painted header band
    story.append(Spacer(1, 44 * mm))

    # Title paragraph (drawn on top of the dark band via a Table with bg)
    header_data = [[
        Paragraph("Compliance Scan Report", S["title"]),
    ]]
    header_info = [
        Paragraph(f"Generated : {now}", S["subtitle"]),
        Paragraph(f"OS Detected: {detected_os}", S["subtitle"]),
        Paragraph(
            f"Categories: {len(rules_by_category)}   &nbsp;&nbsp;  Rules evaluated: {total}",
            S["subtitle"],
        ),
    ]
    for p in header_info:
        header_data.append([p])

    header_table = Table(header_data, colWidths=[content_w])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _COL_HEADER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    # Place header at the very top — we abuse a negative spacer trick via
    # absolute positioning by inserting the table before the big spacer.
    # Simpler: just start story with the table; _draw_header colours behind it.
    story.clear()
    story.append(header_table)
    story.append(Spacer(1, 8 * mm))

    # Summary stat cards (single-row table)                               #

    stat_labels  = ["Total", "Pass",      "Fail",      "Partial",       "Skip",      "Error"     ]
    stat_values  = [total,   pass_count,  fail_count,  partial_count,   skip_count,  error_count ]
    stat_colours = [
        _COL_ACCENT, _COL_PASS, _COL_FAIL, _COL_PARTIAL, _COL_SKIP, _COL_ERROR,
    ]

    # Map colour objects back to hex strings for inline XML markup.
    def _hex(col: Any) -> str:
        """Return a 6-digit lowercase hex string (no #) for a reportlab colour."""
        if hasattr(col, "hexval"):
            # HexColor.hexval() returns e.g. '#1a7a3a' — strip the leading #
            return col.hexval().lstrip("#").lower()
        # Fallback for plain Color objects via RGB channels
        r = int(round(col.red   * 255))
        g = int(round(col.green * 255))
        b = int(round(col.blue  * 255))
        return f"{r:02x}{g:02x}{b:02x}"

    def _stat_cell(label: str, value: int, col: Any) -> List:
        return [
            Paragraph(f'<font color="#{_hex(col)}"><b>{value}</b></font>',
                      ParagraphStyle("sv", fontSize=18, alignment=TA_CENTER, leading=22)),
            Paragraph(label,
                      ParagraphStyle("sl", fontSize=7.5, alignment=TA_CENTER,
                                     textColor=colors.HexColor("#666666"))),
        ]

    card_col_w = content_w / len(stat_labels)
    stat_row_top  = [_stat_cell(l, v, c)[0] for l, v, c in zip(stat_labels, stat_values, stat_colours)]
    stat_row_bot  = [_stat_cell(l, v, c)[1] for l, v, c in zip(stat_labels, stat_values, stat_colours)]

    stat_table = Table(
        [stat_row_top, stat_row_bot],
        colWidths=[card_col_w] * len(stat_labels),
        rowHeights=[22, 14],
    )
    stat_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _COL_WHITE),
        ("BOX",           (0, 0), (-1, -1), 0.5, _COL_LIGHT),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, _COL_LIGHT),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        # coloured top border per cell to mimic "stat card" style
        *[("LINEABOVE", (i, 0), (i, 0), 3, stat_colours[i])
          for i in range(len(stat_labels))],
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 6 * mm))

    # Per-category rule detail sections                                    #

    col_label_w  = 32 * mm
    col_value_w  = content_w - col_label_w - 26 * mm  # leave room for status col
    col_status_w = 26 * mm

    for category, metas in rules_by_category.items():
        cat_block: List[Any] = [
            HRFlowable(width="100%", thickness=1.5, color=_COL_ACCENT, spaceAfter=4),
            Paragraph(category, S["category"]),
        ]

        for meta in metas:
            path   = meta["path"]
            result = results_by_path.get(path)
            if result is None:
                continue

            status    = get_rule_status(result)
            status_bg = _STATUS_BG.get(status, colors.HexColor("#eeeeee"))
            status_fg = _STATUS_COLOR.get(status, colors.black)

            rule_id   = result.get("rule_id",  meta["rule_id"])
            title     = result.get("title",    meta["title"])
            chk_run   = result.get("checks_run",    0)
            chk_skip  = result.get("checks_skipped", 0)

            # -- rule header row --
            rule_header = Table(
                [[
                    Paragraph(rule_id,  S["rule_id"]),
                    Paragraph(title,    S["rule_title"]),
                    Paragraph(
                        f'<b>{status}</b>',
                        ParagraphStyle(
                            "RHStatus", fontSize=8, fontName="Helvetica-Bold",
                            alignment=TA_CENTER,
                            textColor=status_fg,
                        ),
                    ),
                ]],
                colWidths=[38 * mm, content_w - 38 * mm - 24 * mm, 24 * mm],
            )
            rule_header.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), status_bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("BOX",           (0, 0), (-1, -1), 0.5, _COL_LIGHT),
            ]))

            meta_row = Table(
                [[
                    Paragraph(
                        f"Checks run: <b>{chk_run}</b> &nbsp;&nbsp; Skipped: <b>{chk_skip}</b>",
                        ParagraphStyle("MetaRow", fontSize=7.5,
                                       textColor=colors.HexColor("#666666")),
                    ),
                ]],
                colWidths=[content_w],
            )
            meta_row.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), _COL_ROW_ALT),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("BOX",           (0, 0), (-1, -1), 0.5, _COL_LIGHT),
            ]))

            rule_elements: List[Any] = [rule_header, meta_row]

            # error banner
            if "error" in result:
                err_table = Table(
                    [[Paragraph(f"Error: {result['error']}", S["error_text"])]],
                    colWidths=[content_w],
                )
                err_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f8d7da")),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                    ("BOX",           (0, 0), (-1, -1), 0.5, _COL_FAIL),
                ]))
                rule_elements.append(err_table)

            # -- checks --
            checks = result.get("checks", [])
            if not checks:
                rule_elements.append(
                    Paragraph("No checks recorded.", S["no_checks"])
                )
            else:
                check_header_row = [
                    Paragraph("<b>#</b>",               S["cell"]),
                    Paragraph("<b>Check Name</b>",      S["cell"]),
                    Paragraph("<b>Subcontrol</b>",      S["cell"]),
                    Paragraph("<b>Expected Result</b>", S["cell"]),
                    Paragraph("<b>Return Code</b>",     S["cell"]),
                    Paragraph("<b>Status</b>",          S["cell"]),
                ]
                check_col_ws = [
                    8 * mm,
                    38 * mm,
                    content_w - 8*mm - 38*mm - 44*mm - 18*mm - 22*mm,
                    44 * mm,
                    18 * mm,
                    22 * mm,
                ]
                check_rows_data = [check_header_row]
                check_style_cmds = [
                    ("BACKGROUND",    (0, 0), (-1, 0),  _COL_HEADER),
                    ("TEXTCOLOR",     (0, 0), (-1, 0),  _COL_WHITE),
                    ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, 0),  7.5),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                    ("INNERGRID",     (0, 0), (-1, -1), 0.25, _COL_LIGHT),
                    ("BOX",           (0, 0), (-1, -1), 0.5,  _COL_LIGHT),
                ]

                for idx, check in enumerate(checks, start=1):
                    row_num   = len(check_rows_data)
                    chk_stat  = check.get("status", "")
                    chk_bg    = _STATUS_BG.get(chk_stat, _COL_WHITE)
                    chk_fg    = _STATUS_COLOR.get(chk_stat, colors.black)

                    check_rows_data.append([
                        Paragraph(str(idx), S["cell"]),
                        Paragraph(check.get("check_name", ""), S["cell"]),
                        Paragraph(check.get("sub_control",  ""), S["cell"]),
                        Paragraph(check.get("expected_result", ""), S["cell"]),
                        Paragraph(str(check.get("returncode", "")), S["cell"]),
                        Paragraph(
                            f'<font color="#{_hex(chk_fg)}"><b>{chk_stat}</b></font>',
                            S["status_text"],
                        ),
                    ])
                    if idx % 2 == 0:
                        check_style_cmds.append(
                            ("BACKGROUND", (0, row_num), (-2, row_num), _COL_ROW_ALT)
                        )
                    # status cell always gets its own background
                    check_style_cmds.append(
                        ("BACKGROUND", (5, row_num), (5, row_num), chk_bg)
                    )

                checks_tbl = Table(check_rows_data, colWidths=check_col_ws, repeatRows=1)
                checks_tbl.setStyle(TableStyle(check_style_cmds))
                rule_elements.append(checks_tbl)

            rule_elements.append(Spacer(1, 4 * mm))
            cat_block.append(KeepTogether(rule_elements[:3]))   # keep header+meta+first element
            cat_block.extend(rule_elements[3:])

        story.extend(cat_block)

    # Build PDF                                                            #

    doc = SimpleDocTemplate(
        save_path,
        pagesize=A4,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=margin,
        title="Compliance Scan Report",
        author="Compliance Scanner",
        subject=f"Scan performed {now} on {detected_os}",
    )
    doc.build(story, onFirstPage=_draw_header, onLaterPages=_draw_later)


# Accordion widget

class AccordionSection:
    """
    A single collapsible category section inside the rules scroll frame.

    Uses a wrapper frame so that both the header and body occupy a single
    grid/pack slot — this prevents stacking-order corruption when toggling
    visibility and eliminates the duplicate-rows bug on refresh.
    """

    def __init__(
        self,
        parent: ctk.CTkScrollableFrame,
        category: str,
        rule_metas: List[Dict[str, str]],
        on_rule_select: callable,
    ):
        self.parent = parent
        self.category = category
        self.rule_metas = rule_metas
        self.on_rule_select = on_rule_select
        self.expanded: bool = False
        self.rule_buttons: Dict[str, ctk.CTkButton] = {}  # path -> button

        # Single wrapper owns ONE pack slot in the scrollable frame.
        self.wrapper = ctk.CTkFrame(parent, fg_color="transparent")
        self.wrapper.pack(fill="x", pady=(4, 0), padx=2)

        # ---- header button (always visible) ----
        self.header_btn = ctk.CTkButton(
            self.wrapper,
            text=self._header_text(),
            anchor="w",
            fg_color=("#3a3a3a", "#2b2b2b"),
            hover_color=("#4a4a4a", "#3b3b3b"),
            text_color=("white", "white"),
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.toggle,
        )
        self.header_btn.pack(fill="x")

        # ---- rules container (shown/hidden inside the same wrapper) ----
        self.body_frame = ctk.CTkFrame(self.wrapper, fg_color="transparent")

        for meta in rule_metas:
            btn = ctk.CTkButton(
                self.body_frame,
                text=meta["rule_id"],
                anchor="w",
                fg_color="transparent",
                text_color=("#1a1a1a", "#e0e0e0"),
                hover_color=("#4a90d9", "#3a7abf"),
                command=lambda p=meta["path"]: on_rule_select(p),
            )
            btn.pack(fill="x", pady=2)
            self.rule_buttons[meta["path"]] = btn

    def _header_text(self) -> str:
        arrow = "▼" if self.expanded else "▶"
        return f"  {arrow}  {self.category}"

    def toggle(self):
        """Show or hide this section's rule buttons."""
        self.expanded = not self.expanded
        self.header_btn.configure(text=self._header_text())
        if self.expanded:
            self.body_frame.pack(fill="x", padx=(12, 0), pady=(0, 2))
        else:
            self.body_frame.pack_forget()

    def set_button_color(self, path: str, status: str, rule_id: str):
        """Update a rule button's colour and label to reflect its run status."""
        btn = self.rule_buttons.get(path)
        if btn is None:
            return
        COLOR_MAP = {
            "PASS":    ("#1f6f43", "#1f6f43"),
            "PARTIAL": ("#d1a800", "#d1a800"),
            "FAIL":    ("#8b1e1e", "#8b1e1e"),
            "ERROR":   ("#8b1e1e", "#8b1e1e"),
        }
        ICON_MAP = {"PASS": "  ✓", "PARTIAL": "  !", "FAIL": "  ✗", "ERROR": "  ✗"}
        icon = ICON_MAP.get(status, "")
        color = COLOR_MAP.get(status, ("transparent", "transparent"))
        # Always white text on coloured backgrounds; restore adaptive colour for transparent
        text_col = ("white", "white") if color != ("transparent", "transparent") else ("#1a1a1a", "#e0e0e0")
        btn.configure(text=f"{rule_id}{icon}", fg_color=color, text_color=text_col)

    def highlight_selected(self, selected_path: str, results_by_path: Dict[str, RunResult]):
        """
        Re-colour all buttons in this section.

        The selected rule gets the blue highlight; others keep their
        status colour (or transparent if not yet run).
        """
        for path, btn in self.rule_buttons.items():
            if path == selected_path:
                btn.configure(fg_color=("#3b8ed0", "#3b8ed0"), text_color=("white", "white"))
                continue
            result = results_by_path.get(path)
            if result:
                status = get_rule_status(result)
                self.set_button_color(path, status, result.get("rule_id", os.path.basename(path)))
            else:
                btn.configure(fg_color="transparent", text_color=("#1a1a1a", "#e0e0e0"))


# Main application

class ComplianceDebugApp(ctk.CTk):
    """
    Debug GUI with background-thread rule execution.
    Keeps the UI responsive while rules run.
    """

    def __init__(self):
        super().__init__()

        self.title("Compliance Scanner (Debug)")
        self.geometry("1000x750")
        self.minsize(900, 650)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # rule metadata: category -> list of meta dicts
        self.rules_by_category: Dict[str, List[Dict[str, str]]] = {}
        # flat list kept for convenience (run-all ordering)
        self.rules: List[Dict[str, str]] = []

        self.results_by_path: Dict[str, RunResult] = {}
        self.selected_rule_path: Optional[str] = None

        # accordion sections: category -> AccordionSection
        self.accordion_sections: Dict[str, AccordionSection] = {}

        self.theme: str = "dark"
        self.running: bool = False
        self.all_rules_run: bool = False  # True only after a full Run All Rules completes
        self.refresh_btn: Optional[ctk.CTkButton] = None
        self.run_all_btn: Optional[ctk.CTkButton] = None
        self.export_btn: Optional[ctk.CTkButton] = None

        self._build_layout()
        self.refresh_rules()

    # Layout

    def _build_layout(self):
        """Create the main window and all widgets."""
        # ---------- TOP ----------
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=(10, 6))

        self.os_label = ctk.CTkLabel(
            top,
            text=f"Operating System Detected: {format_os_name(os_scan())}",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.os_label.pack(side="left", padx=10, pady=8)

        self.theme_button = ctk.CTkButton(
            top,
            text="Switch to Light Mode",
            command=self.toggle_theme,
        )
        self.theme_button.pack(side="right", padx=10, pady=8)

        self.refresh_btn = ctk.CTkButton(
            top, text="Refresh Rules", command=self.refresh_rules
        )
        self.refresh_btn.pack(side="right", padx=10, pady=8)

        # ---------- MAIN ----------
        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=10, pady=6)

        left = ctk.CTkFrame(main, width=320)
        left.pack(side="left", fill="y", padx=(10, 6), pady=10)

        right = ctk.CTkFrame(main)
        right.pack(side="right", fill="both", expand=True, padx=(6, 10), pady=10)

        ctk.CTkLabel(left, text="Rules", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=10, pady=(10, 6)
        )

        self.rules_scroll = ctk.CTkScrollableFrame(left)
        self.rules_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.summary_label = ctk.CTkLabel(
            right,
            text="Summary: (not run yet)",
            font=ctk.CTkFont(size=14, weight="bold"),
            justify="left",
        )
        self.summary_label.pack(anchor="w", padx=10, pady=(10, 6))

        self.details_text = ctk.CTkTextbox(right, wrap="word")
        self.details_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.details_text.insert("1.0", "Run rules to view results.\n")
        self.details_text.configure(state="disabled")

        # ---------- BOTTOM ----------
        bottom = ctk.CTkFrame(self)
        bottom.pack(fill="x", padx=10, pady=(6, 10))

        # Status label on its own row so long filenames never get clipped.
        status_row = ctk.CTkFrame(bottom, fg_color="transparent")
        status_row.pack(fill="x", padx=10, pady=(6, 0))

        self.status_label = ctk.CTkLabel(
            status_row,
            text="Status: Idle",
            anchor="w",
        )
        self.status_label.pack(side="left", fill="x", expand=True)

        # Buttons + progress bar on the row below.
        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(4, 6))

        self.run_all_btn = ctk.CTkButton(
            btn_row, text="Run All Rules", command=self.run_all_rules
        )
        self.run_all_btn.pack(side="left", padx=(0, 5))

        self.run_selected_btn = ctk.CTkButton(
            btn_row,
            text="Run Selected Rule",
            command=self.run_selected_rule,
            state="disabled",
        )
        self.run_selected_btn.pack(side="left", padx=(0, 5))

        self.export_btn = ctk.CTkButton(
            btn_row,
            text="Export Report",
            command=self.export_report,
            state="disabled",
            fg_color=("#2d6a4f", "#1b4332"),
            hover_color=("#40916c", "#2d6a4f"),
        )
        self.export_btn.pack(side="left", padx=(0, 10))

        self.progress_bar = ctk.CTkProgressBar(btn_row)
        self.progress_bar.pack(side="left", fill="x", expand=True)
        self.progress_bar.set(0.0)

    # Helpers

    def toggle_theme(self):
        """Toggle between dark and light appearance modes."""
        if self.theme == "dark":
            self.theme = "light"
            ctk.set_appearance_mode("light")
            self.theme_button.configure(text="Switch to Dark Mode")
        else:
            self.theme = "dark"
            ctk.set_appearance_mode("dark")
            self.theme_button.configure(text="Switch to Light Mode")

    def set_status(self, text: str):
        """Update the bottom status label."""
        self.status_label.configure(text=f"Status: {text}")

    def _update_progress(self, value: float):
        """Update progress bar (thread-safe via after)."""
        if self.progress_bar is not None:
            self.progress_bar.set(value)

    def _all_rule_paths(self) -> List[str]:
        """Return a flat, ordered list of every rule path across all categories."""
        return [m["path"] for m in self.rules]

    def _section_for_path(self, path: str) -> Optional[AccordionSection]:
        """Find which accordion section owns a given rule path."""
        for section in self.accordion_sections.values():
            if path in section.rule_buttons:
                return section
        return None

    # Rule discovery & sidebar rebuild

    def refresh_rules(self):
        """Re-scan rulesets and rebuild the accordion rule list."""
        rules_dir = os.path.join(PROJECT_ROOT, "rulesets")
        categories = discover_rule_files(rules_dir)  # Dict[str, List[str]]

        self.rules_by_category = {}
        self.rules = []
        for category, paths in categories.items():
            metas = [load_rule_metadata(p) for p in paths]
            self.rules_by_category[category] = metas
            self.rules.extend(metas)

        # Clear old accordion widgets by destroying each section's wrapper frame.
        # Using winfo_children() is unreliable on CTkScrollableFrame because it
        # has internal canvas children — iterate our own tracked sections instead.
        for section in self.accordion_sections.values():
            section.wrapper.destroy()
        self.accordion_sections.clear()
        self.results_by_path.clear()
        self._update_progress(0.0)

        # Build one AccordionSection per category
        for category, metas in self.rules_by_category.items():
            section = AccordionSection(
                parent=self.rules_scroll,
                category=category,
                rule_metas=metas,
                on_rule_select=self.select_rule,
            )
            self.accordion_sections[category] = section

        total = len(self.rules)
        cat_count = len(self.rules_by_category)
        self.summary_label.configure(
            text=f"Summary\n- Categories: {cat_count}\n- Total rules: {total}"
        )
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", "Run rules to view results.\n")
        self.details_text.configure(state="disabled")
        self.selected_rule_path = None
        self.all_rules_run = False
        self.run_selected_btn.configure(state="disabled")
        self.set_status("Idle")

    # Rule selection

    def select_rule(self, rule_path: str):
        """Select a rule and show its details if available."""
        self.selected_rule_path = rule_path

        # Re-colour all sections
        for section in self.accordion_sections.values():
            section.highlight_selected(rule_path, self.results_by_path)

        self.run_selected_btn.configure(state="normal")

        result = self.results_by_path.get(rule_path)
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        if result:
            self.details_text.insert("1.0", format_rule_details(result))
        else:
            self.details_text.insert(
                "1.0",
                "Select a rule and click 'Run Selected Rule' to view results.\n",
            )
        self.details_text.configure(state="disabled")
        self.set_status(f"Selected: {os.path.basename(rule_path)}")

    # Run selected rule

    def run_selected_rule(self):
        """Run the selected rule in a background thread."""
        if not self.selected_rule_path:
            self.set_status("No rule selected")
            return

        meta = next((m for m in self.rules if m["path"] == self.selected_rule_path), None)
        if not meta:
            self.set_status("Invalid rule selection")
            return

        if self.running:
            self.set_status("Already running rules")
            return

        self.running = True
        self.set_status("Running selected rule...")
        self._set_controls_enabled(False)
        self._update_progress(0.0)

        def worker():
            try:
                result = RuleRunner(rule_path=meta["path"], os_type=None).run_checks()
            except Exception as e:
                result = {
                    "rule_id": meta["rule_id"],
                    "title": meta["title"],
                    "os": os_scan(),
                    "checks_run": 0,
                    "checks_skipped": 0,
                    "checks": [],
                    "error": str(e),
                }
            self.after(0, lambda: self._on_selected_rule_done(result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_selected_rule_done(self, result: RunResult):
        """Called on main thread when selected rule finishes."""
        self.running = False
        path = self.selected_rule_path
        if not path:
            return

        self.results_by_path[path] = result
        status = get_rule_status(result)

        section = self._section_for_path(path)
        if section:
            section.set_button_color(path, status, result.get("rule_id", os.path.basename(path)))
            # Re-apply selected highlight on top
            section.highlight_selected(path, self.results_by_path)

        self._update_progress(1.0)
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", format_rule_details(result))
        self.details_text.configure(state="disabled")
        self.set_status("Done")
        self._set_controls_enabled(True)

    # Run all rules

    def run_all_rules(self):
        """Run all rules in a background thread."""
        if self.running:
            self.set_status("Already running rules")
            return

        self.running = True
        self.set_status("Running...")
        self._set_controls_enabled(False)
        self._update_progress(0.0)

        rule_paths = self._all_rule_paths()

        def progress_cb(i: int, total: int, _path: str):
            progress = i / total if total else 0
            status_text = f"Running… ({i}/{total})"
            self.after(0, lambda: (self.set_status(status_text), self._update_progress(progress)))

        def worker():
            results = run_rules_blocking(rule_paths, progress_cb=progress_cb)
            self.after(0, lambda: self._on_all_rules_done(results))

        threading.Thread(target=worker, daemon=True).start()

    def _on_all_rules_done(self, results: Dict[str, RunResult]):
        """Called on main thread when all rules finish."""
        self.running = False
        self.results_by_path = results

        pass_count = fail_count = skip_count = 0

        for path, result in results.items():
            status = get_rule_status(result)
            section = self._section_for_path(path)
            if section:
                section.set_button_color(
                    path, status, result.get("rule_id", os.path.basename(path))
                )
            if status == "PASS":
                pass_count += 1
            elif status in ("FAIL", "PARTIAL", "ERROR"):
                fail_count += 1
            else:
                skip_count += 1

        # Re-apply selection highlight if something is selected
        if self.selected_rule_path:
            for section in self.accordion_sections.values():
                section.highlight_selected(self.selected_rule_path, self.results_by_path)

        self.summary_label.configure(
            text=(
                "Summary\n"
                f"- Categories  : {len(self.rules_by_category)}\n"
                f"- Total rules : {len(results)}\n"
                f"- PASS        : {pass_count}\n"
                f"- FAIL/PARTIAL: {fail_count}\n"
                f"- SKIP        : {skip_count}"
            )
        )
        self._update_progress(1.0)
        self.set_status("Done")
        self.all_rules_run = True

        result_to_show = (
            results.get(self.selected_rule_path)
            if self.selected_rule_path
            else next(iter(results.values()), None)
        )
        if result_to_show:
            self.details_text.configure(state="normal")
            self.details_text.delete("1.0", "end")
            self.details_text.insert("1.0", format_rule_details(result_to_show))
            self.details_text.configure(state="disabled")

        self._set_controls_enabled(True)

    # Export report

    def export_report(self):
        """Generate a PDF report and prompt the user to save it."""
        if not self.all_rules_run or not self.results_by_path:
            self.set_status("Run All Rules first before exporting.")
            return

        default_name = (
            f"compliance_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Report", "*.pdf"), ("All Files", "*.*")],
            initialfile=default_name,
            title="Save Compliance Report",
        )
        if not save_path:
            return  # user cancelled

        self.set_status("Generating PDF…")
        self.update_idletasks()
        try:
            generate_report_pdf(save_path, self.results_by_path, self.rules_by_category)
            self.set_status(f"Report saved: {os.path.basename(save_path)}")
        except Exception as exc:
            self.set_status(f"Export failed: {exc}")

    # Shared control enable/disable

    def _set_controls_enabled(self, enabled: bool):
        """Enable or disable interactive controls during a run."""
        state = "normal" if enabled else "disabled"
        if self.run_all_btn is not None:
            self.run_all_btn.configure(state=state)
        if self.refresh_btn is not None:
            self.refresh_btn.configure(state=state)
        if hasattr(self, "theme_button") and self.theme_button is not None:
            self.theme_button.configure(state=state)
        # Run Selected only enabled when something is selected
        if enabled:
            self.run_selected_btn.configure(
                state="normal" if self.selected_rule_path else "disabled"
            )
        else:
            self.run_selected_btn.configure(state="disabled")
        # Export only enabled after a full Run All Rules has completed
        if hasattr(self, "export_btn") and self.export_btn is not None:
            self.export_btn.configure(
                state="normal" if (enabled and self.all_rules_run) else "disabled"
            )


def main():
    """Entry point for the debug GUI."""
    app = ComplianceDebugApp()
    app.mainloop()


if __name__ == "__main__":
    main()