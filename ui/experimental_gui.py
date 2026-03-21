"""
Threading GUI for the Compliance Scanner.

Uses background threads for rule execution so the UI stays responsive.
Similar structure to main_gui.py but with async run behavior.
"""
from __future__ import annotations

import datetime
import html as _html
import json
import os
import sys
import threading
import time
import re
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox
from typing import Any, Dict, List, Optional

import customtkinter as ctk

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import KeepTogether

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)  # append, not insert(0) — avoids shadowing stdlib

from core import os_scan
from core.rule_runner import RuleRunner

RunResult = Dict[str, Any]

# Module-level font cache — created once, reused everywhere

_FONT_NORMAL: Optional[tkfont.Font] = None
_FONT_BOLD:   Optional[tkfont.Font] = None


def _get_fonts() -> tuple:
    """Return (normal_font, bold_font), creating them once per process."""
    global _FONT_NORMAL, _FONT_BOLD
    if _FONT_NORMAL is None:
        _FONT_NORMAL = tkfont.Font(family="Consolas", size=10)
        _FONT_BOLD   = tkfont.Font(family="Consolas", size=10, weight="bold")
    return _FONT_NORMAL, _FONT_BOLD


def format_os_name(os_name: str) -> str:
    return os_name.replace("_", " ").title()


def _safe_str(value: Any, max_len: int = 512) -> str:
    """
    Coerce *value* to a plain string, strip control characters, and cap length.
    Used everywhere user-supplied JSON data is read so that malformed or
    adversarial content cannot propagate into the UI or PDF renderer.
    """
    s = str(value) if value is not None else ""
    # Strip ASCII control characters (except tab/newline which are harmless in text)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    return s[:max_len]


def _escape_xml(value: str) -> str:
    """HTML/XML-escape a string for safe embedding in ReportLab Paragraph markup."""
    return _html.escape(str(value))


def discover_rule_files(rules_dir: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Walk rules_dir, read each JSON once, and return:
        { category: [ {path, rule_id, title}, ... ], ... }

    Security: every discovered path is validated to be inside rules_dir
    (prevents path-traversal attacks via symlinks or crafted filenames).
    """
    categories: Dict[str, List[Dict[str, str]]] = {}
    if not os.path.isdir(rules_dir):
        return categories

    # Resolve once so all comparisons use the canonical absolute path
    rules_dir_real = os.path.realpath(rules_dir)

    for root, _, files in os.walk(rules_dir):
        for name in sorted(files):
            if not name.lower().endswith(".json"):
                continue
            if name.lower() == "rule_template.json":
                continue

            full_path = os.path.join(root, name)

            # Path-traversal guard: resolved path must stay inside rules_dir
            try:
                real_path = os.path.realpath(full_path)
            except OSError:
                continue
            if not real_path.startswith(rules_dir_real + os.sep) and real_path != rules_dir_real:
                continue  # symlink escape or other traversal attempt — skip silently

            try:
                with open(real_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                category = _safe_str(data.get("category") or "Uncategorised") or "Uncategorised"
                rule_id  = _safe_str(data.get("id") or data.get("rule_id") or name)
                title    = _safe_str(data.get("title") or data.get("control_number") or name)
            except json.JSONDecodeError:
                # Malformed JSON — log to stderr and skip, don't silently hide it
                print(f"[WARN] Skipping malformed JSON: {real_path}", file=sys.stderr)
                continue
            except OSError as exc:
                print(f"[WARN] Could not read rule file {real_path}: {exc}", file=sys.stderr)
                continue

            categories.setdefault(category, []).append(
                {"path": real_path, "rule_id": rule_id, "title": title}
            )

    def _cat_sort_key(cat: str) -> tuple:
        return (cat.lower() == "uncategorised", cat.lower())

    def _natural_key(meta: Dict[str, str]) -> list:
        fname = os.path.basename(meta["path"])
        return [
            int(chunk) if chunk.isdigit() else chunk.lower()
            for chunk in re.split(r"(\d+)", fname)
        ]

    return {
        cat: sorted(metas, key=_natural_key)
        for cat, metas in sorted(categories.items(), key=lambda kv: _cat_sort_key(kv[0]))
    }


def get_rule_status(result: RunResult) -> str:
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


# Coloured details renderer

# tag -> (fg_dark, bg_dark, fg_light, bg_light, bold)
_TAG_DEFS: Dict[str, tuple] = {
    "rule_id":        ("#5dade2", None,      "#1a6fa8", None,       True),
    "title":          ("#aab7b8", None,      "#555e65", None,       False),
    "label":          ("#7f8c8d", None,      "#666e75", None,       False),
    "value":          ("#e8e8e8", None,      "#1a1a1a", None,       False),
    "status_pass":    ("#2ecc71", None,      "#1a7a3a", None,       True),
    "status_fail":    ("#e74c3c", None,      "#a01010", None,       True),
    "status_partial": ("#f0c040", None,      "#7a5c00", None,       True),
    "status_skip":    ("#95a5a6", None,      "#555e65", None,       True),
    "status_error":   ("#e74c3c", None,      "#a01010", None,       True),
    "check_header":   ("#ffffff", "#1e3a5f", "#ffffff", "#1e3a5f",  True),
    "divider":        ("#3d5166", None,      "#9baab8", None,       False),
    "stdout_label":   ("#27ae60", None,      "#1a7a3a", None,       True),
    "stderr_label":   ("#e67e22", None,      "#b05010", None,       True),
    "stdout_text":    ("#abebc6", None,      "#1a5c30", None,       False),
    "stderr_text":    ("#f0b27a", None,      "#7a3800", None,       False),
    "error_banner":   ("#e74c3c", "#2c1515", "#cc0000", "#ffe0e0",  True),
    "meta":           ("#85929e", None,      "#666e75", None,       False),
}


def _configure_tags(widget: tk.Text, mode: str = "dark") -> None:
    """
    Apply all named color/font tags to a tk.Text widget.
    Reuses cached Font objects — safe to call on every theme toggle.
    """
    normal_font, bold_font = _get_fonts()
    dark      = mode == "dark"
    widget_bg = widget.cget("bg")

    for tag, (fg_dark, bg_dark, fg_light, bg_light, bold) in _TAG_DEFS.items():
        fg = fg_dark if dark else fg_light
        bg = bg_dark if dark else bg_light
        widget.tag_configure(
            tag,
            foreground=fg,
            background=bg if bg else widget_bg,
            font=bold_font if bold else normal_font,
        )

    widget.tag_configure("check_header", spacing1=8, spacing3=6, lmargin1=4, lmargin2=4)
    widget.tag_configure("divider",      spacing1=2, spacing3=2)


def _status_tag(status: str) -> str:
    return {
        "PASS":    "status_pass",
        "FAIL":    "status_fail",
        "PARTIAL": "status_partial",
        "SKIP":    "status_skip",
        "ERROR":   "status_error",
    }.get(status, "value")


def render_rule_details(widget: tk.Text, result: RunResult) -> None:
    """
    Clear *widget* and write a color-formatted rule result.
    Batches all text into a single list and inserts in one pass per tag
    segment to minimise Tcl round-trips.
    """
    widget.configure(state="normal")
    widget.delete("1.0", "end")

    segments: List[tuple] = []

    def w(text: str, tag: str = "value") -> None:
        segments.append((text, tag))

    if "error" in result:
        w("\n  ERROR\n",                                  "error_banner")
        w(f"\n  {result.get('error', '')}\n",             "stderr_text")
        w(f"\n  Rule ID : {result.get('rule_id', '')}\n", "meta")
        w(f"  Title   : {result.get('title',   '')}\n",   "meta")
    else:
        status     = get_rule_status(result)
        status_tag = _status_tag(status)

        w("\n")
        w(f"  {result.get('rule_id', '')}", "rule_id")
        w("  —  ", "divider")
        w(f"{result.get('title', '')}\n",   "title")
        w("\n")
        w("  Overall status   : ", "label"); w(f"{status}\n",                                           status_tag)
        w("  OS               : ", "label"); w(f"{result.get('os', '')}\n",                             "value")
        w("  Checks run       : ", "label"); w(f"{result.get('checks_run', 0)}\n",                      "value")
        w("  Checks skipped   : ", "label"); w(f"{result.get('checks_skipped', 0)} (NA subcontrols)\n", "value")
        w("\n")

        for i, check in enumerate(result.get("checks", []), start=1):
            chk_status = check.get("status", "")
            chk_tag    = _status_tag(chk_status)

            w(f"  CHECK #{i}  |  {check.get('check_name', '')}\n", "check_header")
            w("  Subcontrol       : ", "label"); w(f"{check.get('sub_control',     '')}\n", "value")
            w("  Status           : ", "label"); w(f"{chk_status}\n",                        chk_tag)
            w("  Command          : ", "label"); w(f"{check.get('command',         '')}\n", "value")
            w("  Expected result  : ", "label"); w(f"{check.get('expected_result', '')}\n", "value")
            w("  Return code      : ", "label"); w(f"{check.get('returncode',      '')}\n", "value")

            stdout = check.get("stdout", "").strip()
            stderr = check.get("stderr", "").strip()
            if stdout:
                w("\n  stdout:\n", "stdout_label")
                for line in stdout.splitlines():
                    w(f"    {line}\n", "stdout_text")
            if stderr:
                w("\n  stderr:\n", "stderr_label")
                for line in stderr.splitlines():
                    w(f"    {line}\n", "stderr_text")

            w("\n")
            w("  " + "─" * 62 + "\n", "divider")
            w("\n")

    # Single-pass insert: merge consecutive same-tag segments to reduce Tcl calls
    if segments:
        merged: List[tuple] = [segments[0]]
        for text, tag in segments[1:]:
            if tag == merged[-1][1]:
                merged[-1] = (merged[-1][0] + text, tag)
            else:
                merged.append((text, tag))
        for text, tag in merged:
            widget.insert("end", text, tag)

    widget.configure(state="disabled")


def render_placeholder(widget: tk.Text, message: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", f"\n  {message}\n", "meta")
    widget.configure(state="disabled")


def run_rules_blocking(
    rule_paths: List[str],
    progress_cb: Optional[callable] = None,
) -> Dict[str, RunResult]:
    results: Dict[str, RunResult] = {}
    total = len(rule_paths)
    for i, path in enumerate(rule_paths, start=1):
        if progress_cb:
            progress_cb(i, total, path)
        try:
            r = RuleRunner(rule_path=path, os_type=None).run_checks()
            results[path] = r
        except Exception as e:
            # Sanitize the error message — raw exception strings can contain
            # full file paths or system details we don't want in the UI/PDF.
            error_msg = _safe_str(type(e).__name__ + ": " + str(e), max_len=256)
            results[path] = {
                "rule_id":        os.path.basename(path),
                "title":          os.path.basename(path),
                "os":             os_scan(),
                "checks_run":     0,
                "checks_skipped": 0,
                "checks":         [],
                "error":          error_msg,
            }
    return results


# PDF report generation

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
    "PASS":    _COL_PASS,    "FAIL":    _COL_FAIL,
    "PARTIAL": _COL_PARTIAL, "ERROR":   _COL_ERROR,
    "SKIP":    _COL_SKIP,    "NOT_RUN": _COL_SKIP,
}
_STATUS_BG: Dict[str, Any] = {
    "PASS":    colors.HexColor("#d4edda"), "FAIL":    colors.HexColor("#f8d7da"),
    "PARTIAL": colors.HexColor("#fff3cd"), "ERROR":   colors.HexColor("#f8d7da"),
    "SKIP":    colors.HexColor("#e2e3e5"), "NOT_RUN": colors.HexColor("#e2e3e5"),
}


def _make_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title":       ParagraphStyle("ReportTitle",    parent=base["Title"],    fontSize=22, textColor=_COL_WHITE, spaceAfter=4),
        "subtitle":    ParagraphStyle("ReportSubtitle", parent=base["Normal"],   fontSize=9,  textColor=colors.HexColor("#cccccc"), spaceAfter=2),
        "category":    ParagraphStyle("Category",       parent=base["Heading1"], fontSize=13, textColor=_COL_HEADER, spaceBefore=14, spaceAfter=6, borderPad=4),
        "rule_id":     ParagraphStyle("RuleID",         parent=base["Normal"],   fontSize=10, textColor=_COL_HEADER, fontName="Helvetica-Bold"),
        "rule_title":  ParagraphStyle("RuleTitle",      parent=base["Normal"],   fontSize=9,  textColor=colors.HexColor("#444444")),
        "cell":        ParagraphStyle("Cell",           parent=base["Normal"],   fontSize=8,  leading=11),
        "cell_mono":   ParagraphStyle("CellMono",       parent=base["Normal"],   fontSize=7.5, fontName="Courier", leading=10),
        "cell_label":  ParagraphStyle("CellLabel",      parent=base["Normal"],   fontSize=8,  textColor=colors.HexColor("#555555"), leading=11),
        "status_text": ParagraphStyle("StatusText",     parent=base["Normal"],   fontSize=8,  fontName="Helvetica-Bold", alignment=TA_CENTER),
        "error_text":  ParagraphStyle("ErrorText",      parent=base["Normal"],   fontSize=8,  textColor=_COL_FAIL, leading=11),
        "no_checks":   ParagraphStyle("NoChecks",       parent=base["Normal"],   fontSize=8,  textColor=colors.HexColor("#888888"), leftIndent=8),
    }


def generate_report_pdf(
    save_path: str,
    results_by_path: Dict[str, RunResult],
    rules_by_category: Dict[str, List[Dict[str, str]]],
) -> None:
    now           = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detected_os   = _escape_xml(format_os_name(os_scan()))  # escape for PDF XML safety
    total         = len(results_by_path)
    pass_count    = sum(1 for r in results_by_path.values() if get_rule_status(r) == "PASS")
    fail_count    = sum(1 for r in results_by_path.values() if get_rule_status(r) == "FAIL")
    partial_count = sum(1 for r in results_by_path.values() if get_rule_status(r) == "PARTIAL")
    error_count   = sum(1 for r in results_by_path.values() if get_rule_status(r) == "ERROR")
    skip_count    = sum(1 for r in results_by_path.values() if get_rule_status(r) == "SKIP")

    S         = _make_styles()
    page_w, page_h = A4
    margin    = 18 * mm
    content_w = page_w - 2 * margin
    story: List[Any] = []

    def _draw_header(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(_COL_HEADER)
        canvas.rect(0, page_h - 52 * mm, page_w, 52 * mm, fill=True, stroke=False)
        canvas.restoreState()

    def _draw_later(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(_COL_ACCENT)
        canvas.rect(0, page_h - 4 * mm, page_w, 4 * mm, fill=True, stroke=False)
        canvas.restoreState()

    header_data = [[Paragraph("Compliance Scan Report", S["title"])]]
    for p in [
        Paragraph(f"Generated : {now}", S["subtitle"]),
        Paragraph(f"OS Detected: {detected_os}", S["subtitle"]),
        Paragraph(f"Categories: {len(rules_by_category)}   &nbsp;&nbsp;  Rules evaluated: {total}", S["subtitle"]),
    ]:
        header_data.append([p])

    header_table = Table(header_data, colWidths=[content_w])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _COL_HEADER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8 * mm))

    stat_labels  = ["Total",      "Pass",     "Fail",     "Partial",      "Skip",     "Error"    ]
    stat_values  = [total,        pass_count, fail_count, partial_count,  skip_count, error_count]
    stat_colours = [_COL_ACCENT,  _COL_PASS,  _COL_FAIL,  _COL_PARTIAL,  _COL_SKIP,  _COL_ERROR ]

    def _hex(col: Any) -> str:
        if hasattr(col, "hexval"):
            return col.hexval().lstrip("#").lower()
        return (
            f"{int(round(col.red * 255)):02x}"
            f"{int(round(col.green * 255)):02x}"
            f"{int(round(col.blue * 255)):02x}"
        )

    def _stat_cell(label: str, value: int, col: Any) -> List:
        return [
            Paragraph(
                f'<font color="#{_hex(col)}"><b>{value}</b></font>',
                ParagraphStyle("sv", fontSize=18, alignment=TA_CENTER, leading=22),
            ),
            Paragraph(
                label,
                ParagraphStyle("sl", fontSize=7.5, alignment=TA_CENTER,
                               textColor=colors.HexColor("#666666")),
            ),
        ]

    card_col_w   = content_w / len(stat_labels)
    stat_row_top = [_stat_cell(l, v, c)[0] for l, v, c in zip(stat_labels, stat_values, stat_colours)]
    stat_row_bot = [_stat_cell(l, v, c)[1] for l, v, c in zip(stat_labels, stat_values, stat_colours)]

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
        *[("LINEABOVE", (i, 0), (i, 0), 3, stat_colours[i]) for i in range(len(stat_labels))],
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 6 * mm))

    for category, metas in rules_by_category.items():
        cat_block: List[Any] = [
            HRFlowable(width="100%", thickness=1.5, color=_COL_ACCENT, spaceAfter=4),
            Paragraph(_escape_xml(category), S["category"]),
        ]

        for meta in metas:
            path   = meta["path"]
            result = results_by_path.get(path)
            if result is None:
                continue

            status    = get_rule_status(result)
            status_bg = _STATUS_BG.get(status, colors.HexColor("#eeeeee"))
            status_fg = _STATUS_COLOR.get(status, colors.black)
            rule_id   = _escape_xml(result.get("rule_id", meta["rule_id"]))
            title     = _escape_xml(result.get("title",   meta["title"]))
            chk_run   = result.get("checks_run",     0)
            chk_skip  = result.get("checks_skipped", 0)

            rule_header = Table(
                [[
                    Paragraph(rule_id, S["rule_id"]),
                    Paragraph(title,   S["rule_title"]),
                    Paragraph(
                        f'<b>{_escape_xml(status)}</b>',
                        ParagraphStyle(
                            "RHStatus", fontSize=8, fontName="Helvetica-Bold",
                            alignment=TA_CENTER, textColor=status_fg,
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

            if "error" in result:
                err_table = Table(
                    [[Paragraph(f"Error: {_escape_xml(result['error'])}", S["error_text"])]],
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

            checks = result.get("checks", [])
            if not checks:
                rule_elements.append(Paragraph("No checks recorded.", S["no_checks"]))
            else:
                check_col_ws = [
                    8 * mm, 38 * mm,
                    content_w - 8*mm - 38*mm - 44*mm - 18*mm - 22*mm,
                    44 * mm, 18 * mm, 22 * mm,
                ]
                check_rows_data = [[
                    Paragraph("<b>#</b>",               S["cell"]),
                    Paragraph("<b>Check Name</b>",      S["cell"]),
                    Paragraph("<b>Subcontrol</b>",      S["cell"]),
                    Paragraph("<b>Expected Result</b>", S["cell"]),
                    Paragraph("<b>Return Code</b>",     S["cell"]),
                    Paragraph("<b>Status</b>",          S["cell"]),
                ]]
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
                    row_num  = len(check_rows_data)
                    chk_stat = check.get("status", "")
                    chk_bg   = _STATUS_BG.get(chk_stat, _COL_WHITE)
                    chk_fg   = _STATUS_COLOR.get(chk_stat, colors.black)

                    check_rows_data.append([
                        Paragraph(str(idx),                                       S["cell"]),
                        Paragraph(_escape_xml(check.get("check_name",      "")), S["cell"]),
                        Paragraph(_escape_xml(check.get("sub_control",     "")), S["cell"]),
                        Paragraph(_escape_xml(check.get("expected_result", "")), S["cell"]),
                        Paragraph(_escape_xml(str(check.get("returncode",  ""))),S["cell"]),
                        Paragraph(
                            f'<font color="#{_hex(chk_fg)}"><b>{_escape_xml(chk_stat)}</b></font>',
                            S["status_text"],
                        ),
                    ])
                    if idx % 2 == 0:
                        check_style_cmds.append(
                            ("BACKGROUND", (0, row_num), (-2, row_num), _COL_ROW_ALT))
                    check_style_cmds.append(
                        ("BACKGROUND", (5, row_num), (5, row_num), chk_bg))

                checks_tbl = Table(check_rows_data, colWidths=check_col_ws, repeatRows=1)
                checks_tbl.setStyle(TableStyle(check_style_cmds))
                rule_elements.append(checks_tbl)

            rule_elements.append(Spacer(1, 4 * mm))
            cat_block.append(KeepTogether(rule_elements[:3]))
            cat_block.extend(rule_elements[3:])

        story.extend(cat_block)

    doc = SimpleDocTemplate(
        save_path, pagesize=A4,
        leftMargin=margin, rightMargin=margin,
        topMargin=margin, bottomMargin=margin,
        title="Compliance Scan Report",
        author="Compliance Scanner",
        subject=f"Scan performed {now} on {detected_os}",
    )
    doc.build(story, onFirstPage=_draw_header, onLaterPages=_draw_later)


# Accordion widget

class AccordionSection:
    # Class-level colour/icon maps — defined once, not per-instance
    _COLOR_MAP = {
        "PASS":    ("#1f6f43", "#1f6f43"),
        "PARTIAL": ("#d1a800", "#d1a800"),
        "FAIL":    ("#8b1e1e", "#8b1e1e"),
        "ERROR":   ("#8b1e1e", "#8b1e1e"),
    }
    _ICON_MAP = {"PASS": "  ✓", "PARTIAL": "  !", "FAIL": "  ✗", "ERROR": "  ✗"}

    def __init__(
        self,
        parent: ctk.CTkScrollableFrame,
        category: str,
        rule_metas: List[Dict[str, str]],
        on_rule_select: callable,
    ):
        self.category       = category
        self.on_rule_select = on_rule_select
        self.expanded: bool = False
        self.rule_buttons: Dict[str, ctk.CTkButton] = {}

        self.wrapper = ctk.CTkFrame(parent, fg_color="transparent")
        self.wrapper.pack(fill="x", pady=(4, 0), padx=2)

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

        self.body_frame = ctk.CTkFrame(self.wrapper, fg_color="transparent")
        # body_frame not packed — starts collapsed

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
        self.expanded = not self.expanded
        self.header_btn.configure(text=self._header_text())
        if self.expanded:
            self.body_frame.pack(fill="x", padx=(12, 0), pady=(0, 2))
        else:
            self.body_frame.pack_forget()

    def set_button_color(self, path: str, status: str, rule_id: str):
        btn = self.rule_buttons.get(path)
        if btn is None:
            return
        icon     = self._ICON_MAP.get(status, "")
        color    = self._COLOR_MAP.get(status, ("transparent", "transparent"))
        text_col = ("white", "white") if color != ("transparent", "transparent") else ("#1a1a1a", "#e0e0e0")
        btn.configure(text=f"{rule_id}{icon}", fg_color=color, text_color=text_col)

    def highlight_selected(self, selected_path: str, results_by_path: Dict[str, RunResult]):
        for path, btn in self.rule_buttons.items():
            if path == selected_path:
                btn.configure(fg_color=("#3b8ed0", "#3b8ed0"), text_color=("white", "white"))
            elif path in results_by_path:
                status = get_rule_status(results_by_path[path])
                self.set_button_color(
                    path, status,
                    results_by_path[path].get("rule_id", os.path.basename(path)),
                )
            else:
                btn.configure(fg_color="transparent", text_color=("#1a1a1a", "#e0e0e0"))


# Main application

class ComplianceDebugApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Compliance Scanner (Debug)")
        self.geometry("1000x750")
        self.minsize(900, 650)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.rules_by_category:  Dict[str, List[Dict[str, str]]] = {}
        self.rules:              List[Dict[str, str]]             = []
        self.results_by_path:    Dict[str, RunResult]             = {}
        self.selected_rule_path: Optional[str]                    = None
        self.accordion_sections: Dict[str, AccordionSection]      = {}

        # Fast reverse-lookup: rule path -> AccordionSection
        self._path_to_section: Dict[str, AccordionSection] = {}

        self.theme:         str  = "dark"
        self.running:       bool = False
        self.all_rules_run: bool = False

        self.refresh_btn: Optional[ctk.CTkButton] = None
        self.run_all_btn: Optional[ctk.CTkButton] = None
        self.export_btn:  Optional[ctk.CTkButton] = None

        self._build_layout()
        self.refresh_rules()

    # ------------------------------------------------------------------
    def _build_layout(self):
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=(10, 6))

        self.os_label = ctk.CTkLabel(
            top,
            text=f"Operating System Detected: {format_os_name(os_scan())}",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.os_label.pack(side="left", padx=10, pady=8)

        self.theme_button = ctk.CTkButton(
            top, text="☽", command=self.toggle_theme,
            width=36, height=36, font=ctk.CTkFont(size=16),
        )
        self.theme_button.pack(side="right", padx=10, pady=8)

        self.refresh_btn = ctk.CTkButton(top, text="Refresh Rules", command=self.refresh_rules)
        self.refresh_btn.pack(side="right", padx=10, pady=8)

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
            right, text="Summary: (not run yet)",
            font=ctk.CTkFont(size=14, weight="bold"), justify="left",
        )
        self.summary_label.pack(anchor="w", padx=10, pady=(10, 6))

        details_frame = ctk.CTkFrame(right, fg_color="transparent")
        details_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.details_text = tk.Text(
            details_frame,
            wrap="word",
            bg="#1e1e1e",
            fg="#e8e8e8",
            insertbackground="#e8e8e8",
            selectbackground="#264f78",
            relief="flat",
            bd=0,
            padx=10,
            pady=8,
            font=("Consolas", 10),
            cursor="arrow",
            state="disabled",
        )
        _configure_tags(self.details_text)

        details_scroll = ctk.CTkScrollbar(details_frame, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scroll.set)
        details_scroll.pack(side="right", fill="y")
        self.details_text.pack(side="left", fill="both", expand=True)

        render_placeholder(self.details_text, "Run rules to view results.")

        bottom = ctk.CTkFrame(self)
        bottom.pack(fill="x", padx=10, pady=(6, 10))

        status_row = ctk.CTkFrame(bottom, fg_color="transparent")
        status_row.pack(fill="x", padx=10, pady=(6, 0))

        self.status_label = ctk.CTkLabel(status_row, text="Status: Idle", anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)

        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(4, 6))

        self.run_all_btn = ctk.CTkButton(btn_row, text="Run All Rules", command=self.run_all_rules)
        self.run_all_btn.pack(side="left", padx=(0, 5))

        self.run_selected_btn = ctk.CTkButton(
            btn_row, text="Run Selected Rule", command=self.run_selected_rule, state="disabled"
        )
        self.run_selected_btn.pack(side="left", padx=(0, 5))

        self.export_btn = ctk.CTkButton(
            btn_row, text="Export Report", command=self.export_report, state="disabled",
            fg_color=("#2d6a4f", "#1b4332"), hover_color=("#40916c", "#2d6a4f"),
        )
        self.export_btn.pack(side="left", padx=(0, 10))

        self.progress_bar = ctk.CTkProgressBar(btn_row)
        self.progress_bar.pack(side="left", fill="x", expand=True)
        self.progress_bar.set(0.0)

    # ------------------------------------------------------------------
    def toggle_theme(self):
        if self.theme == "dark":
            self.theme = "light"
            ctk.set_appearance_mode("light")
            self.theme_button.configure(text="☀")
            self.details_text.configure(bg="#f5f5f5", fg="#1a1a1a")
            _configure_tags(self.details_text, mode="light")
        else:
            self.theme = "dark"
            ctk.set_appearance_mode("dark")
            self.theme_button.configure(text="☽")
            self.details_text.configure(bg="#1e1e1e", fg="#e8e8e8")
            _configure_tags(self.details_text, mode="dark")

    def set_status(self, text: str):
        self.status_label.configure(text=f"Status: {text}")

    def _update_progress(self, value: float):
        if self.progress_bar is not None:
            self.progress_bar.set(value)

    def _all_rule_paths(self) -> List[str]:
        return [m["path"] for m in self.rules]

    def _section_for_path(self, path: str) -> Optional[AccordionSection]:
        """O(1) lookup via reverse-index dict."""
        return self._path_to_section.get(path)

    # ------------------------------------------------------------------
    def refresh_rules(self):
        rules_dir  = os.path.join(PROJECT_ROOT, "rulesets")
        categories = discover_rule_files(rules_dir)

        self.rules_by_category = categories
        self.rules = [m for metas in categories.values() for m in metas]

        for section in self.accordion_sections.values():
            section.wrapper.destroy()
        self.accordion_sections.clear()
        self._path_to_section.clear()
        self.results_by_path.clear()
        self._update_progress(0.0)

        for category, metas in categories.items():
            section = AccordionSection(
                parent=self.rules_scroll,
                category=category,
                rule_metas=metas,
                on_rule_select=self.select_rule,
            )
            self.accordion_sections[category] = section
            for meta in metas:
                self._path_to_section[meta["path"]] = section

        total     = len(self.rules)
        cat_count = len(self.rules_by_category)
        self.summary_label.configure(
            text=f"Summary\n- Categories: {cat_count}\n- Total rules: {total}"
        )
        render_placeholder(self.details_text, "Run rules to view results.")
        self.selected_rule_path = None
        self.all_rules_run      = False
        self.run_selected_btn.configure(state="disabled")
        self.set_status("Idle")

    # ------------------------------------------------------------------
    def select_rule(self, rule_path: str):
        self.selected_rule_path = rule_path

        for section in self.accordion_sections.values():
            section.highlight_selected(rule_path, self.results_by_path)

        self.run_selected_btn.configure(state="normal")

        result = self.results_by_path.get(rule_path)
        if result:
            render_rule_details(self.details_text, result)
        else:
            render_placeholder(
                self.details_text,
                "Select a rule and click 'Run Selected Rule' to view results.",
            )
        self.set_status(f"Selected: {os.path.basename(rule_path)}")

    # ------------------------------------------------------------------
    def run_selected_rule(self):
        if not self.selected_rule_path:
            self.set_status("No rule selected"); return
        meta = next((m for m in self.rules if m["path"] == self.selected_rule_path), None)
        if not meta:
            self.set_status("Invalid rule selection"); return
        if self.running:
            self.set_status("Already running rules"); return

        self.running = True
        self.set_status("Running selected rule...")
        self._set_controls_enabled(False)
        self._update_progress(0.0)

        def worker():
            try:
                result = RuleRunner(rule_path=meta["path"], os_type=None).run_checks()
            except Exception as e:
                # Sanitize error message — same treatment as run_rules_blocking
                error_msg = _safe_str(type(e).__name__ + ": " + str(e), max_len=256)
                result = {
                    "rule_id":        meta["rule_id"],
                    "title":          meta["title"],
                    "os":             os_scan(),
                    "checks_run":     0,
                    "checks_skipped": 0,
                    "checks":         [],
                    "error":          error_msg,
                }
            self.after(0, lambda: self._on_selected_rule_done(result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_selected_rule_done(self, result: RunResult):
        self.running = False
        path = self.selected_rule_path
        if not path:
            return
        self.results_by_path[path] = result
        status  = get_rule_status(result)
        section = self._section_for_path(path)
        if section:
            section.set_button_color(path, status, result.get("rule_id", os.path.basename(path)))
            section.highlight_selected(path, self.results_by_path)
        self._update_progress(1.0)
        render_rule_details(self.details_text, result)
        self.set_status("Done")
        self._set_controls_enabled(True)

    # ------------------------------------------------------------------
    def run_all_rules(self):
        if self.running:
            self.set_status("Already running rules"); return
        self.running = True
        self.set_status("Running...")
        self._set_controls_enabled(False)
        self._update_progress(0.0)
        rule_paths = self._all_rule_paths()

        # Throttle UI updates: only post to main thread when ≥100 ms have
        # elapsed or this is the final rule — avoids flooding the event queue.
        _last_update: List[float] = [0.0]

        def progress_cb(i: int, total: int, _path: str):
            now = time.monotonic()  # time is imported at the top level
            if i == total or (now - _last_update[0]) >= 0.1:
                _last_update[0] = now
                progress    = i / total if total else 0
                status_text = f"Running… ({i}/{total})"
                self.after(0, lambda p=progress, s=status_text:
                           (self.set_status(s), self._update_progress(p)))

        def worker():
            results = run_rules_blocking(rule_paths, progress_cb=progress_cb)
            self.after(0, lambda: self._on_all_rules_done(results))

        threading.Thread(target=worker, daemon=True).start()

    def _on_all_rules_done(self, results: Dict[str, RunResult]):
        self.running         = False
        self.results_by_path = results
        pass_count = fail_count = skip_count = 0

        for path, result in results.items():
            status  = get_rule_status(result)
            section = self._section_for_path(path)
            if section:
                section.set_button_color(
                    path, status,
                    result.get("rule_id", os.path.basename(path)),
                )
            if status == "PASS":
                pass_count += 1
            elif status in ("FAIL", "PARTIAL", "ERROR"):
                fail_count += 1
            else:
                skip_count += 1

        if self.selected_rule_path:
            for section in self.accordion_sections.values():
                section.highlight_selected(self.selected_rule_path, self.results_by_path)

        self.summary_label.configure(text=(
            "Summary\n"
            f"- Categories  : {len(self.rules_by_category)}\n"
            f"- Total rules : {len(results)}\n"
            f"- PASS        : {pass_count}\n"
            f"- FAIL/PARTIAL: {fail_count}\n"
            f"- SKIP        : {skip_count}"
        ))
        self._update_progress(1.0)
        self.set_status("Done")
        self.all_rules_run = True

        result_to_show = (
            results.get(self.selected_rule_path)
            if self.selected_rule_path
            else next(iter(results.values()), None)
        )
        if result_to_show:
            render_rule_details(self.details_text, result_to_show)

        self._set_controls_enabled(True)

    # ------------------------------------------------------------------
    def export_report(self):
        if not self.all_rules_run or not self.results_by_path:
            self.set_status("Run All Rules first before exporting."); return

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
            return

        # Validate the chosen path: enforce .pdf extension and confirm the
        # target directory is writable before starting the background thread.
        if not save_path.lower().endswith(".pdf"):
            save_path += ".pdf"
        save_dir = os.path.dirname(os.path.abspath(save_path)) or "."
        if not os.path.isdir(save_dir) or not os.access(save_dir, os.W_OK):
            messagebox.showerror(
                "Export Error",
                f"Cannot write to directory:\n{save_dir}",
            )
            return

        self.set_status("Generating PDF…")
        self._set_controls_enabled(False)
        self._update_progress(0.0)
        self.update_idletasks()

        results_snapshot  = dict(self.results_by_path)
        category_snapshot = dict(self.rules_by_category)

        def worker():
            try:
                generate_report_pdf(save_path, results_snapshot, category_snapshot)
                self.after(0, lambda: (
                    self._update_progress(1.0),
                    self.set_status(f"Report saved: {os.path.basename(save_path)}"),
                    self._set_controls_enabled(True),
                ))
            except Exception as exc:
                err_msg = _safe_str(type(exc).__name__ + ": " + str(exc), max_len=200)
                self.after(0, lambda m=err_msg: (
                    self._update_progress(0.0),
                    self.set_status(f"Export failed: {m}"),
                    self._set_controls_enabled(True),
                ))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    def _set_controls_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        if self.run_all_btn:
            self.run_all_btn.configure(state=state)
        if self.refresh_btn:
            self.refresh_btn.configure(state=state)
        if hasattr(self, "theme_button") and self.theme_button:
            self.theme_button.configure(state=state)
        if enabled:
            self.run_selected_btn.configure(
                state="normal" if self.selected_rule_path else "disabled")
        else:
            self.run_selected_btn.configure(state="disabled")
        if hasattr(self, "export_btn") and self.export_btn:
            self.export_btn.configure(
                state="normal" if (enabled and self.all_rules_run) else "disabled")


def main():
    app = ComplianceDebugApp()
    app.mainloop()


if __name__ == "__main__":
    main()