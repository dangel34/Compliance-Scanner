"""
PDF report generation for RuleForge.
"""
from __future__ import annotations

import datetime
from collections import Counter
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, LETTER
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

from ui.utils import RunResult, _escape_xml, format_os_name, get_rule_status

# Imported after utils ensures PROJECT_ROOT is on sys.path
from core import os_scan

# ---------------------------------------------------------------------------
# Color constants
# ---------------------------------------------------------------------------

_COL_PASS    = colors.HexColor("#1a7a3a")
_COL_FAIL    = colors.HexColor("#7a1a1a")   # also used for ERROR
_COL_PARTIAL = colors.HexColor("#8a6d1d")
_COL_SKIP    = colors.HexColor("#555555")
_COL_POLICY  = colors.HexColor("#5b21b6")
_COL_HEADER  = colors.HexColor("#34495e")
_COL_ACCENT  = colors.HexColor("#3b8ed0")
_COL_ROW_ALT = colors.HexColor("#eef2f5")
_COL_WHITE   = colors.white
_COL_LIGHT   = colors.HexColor("#dee2e6")
_COL_UNKNOWN = colors.HexColor("#eeeeee")   # fallback for unmapped statuses

_STATUS_COLOR: Dict[str, Any] = {
    "PASS":    _COL_PASS,
    "FAIL":    _COL_FAIL,
    "PARTIAL": _COL_PARTIAL,
    "ERROR":   _COL_FAIL,    # same shade as FAIL
    "SKIP":    _COL_SKIP,
    "NOT_RUN": _COL_SKIP,
    "POLICY":  _COL_POLICY,
}
_STATUS_BG: Dict[str, Any] = {
    "PASS":    colors.HexColor("#d4edda"),
    "FAIL":    colors.HexColor("#f8d7da"),
    "PARTIAL": colors.HexColor("#fff3cd"),
    "ERROR":   colors.HexColor("#f8d7da"),  # same as FAIL
    "SKIP":    colors.HexColor("#e2e3e5"),
    "NOT_RUN": colors.HexColor("#e2e3e5"),
    "POLICY":  colors.HexColor("#ede9fe"),
}

# ---------------------------------------------------------------------------
# Module-level paragraph styles for the summary stat cards.
# Creating these inside a function that's called per-stat wastes allocations.
# ---------------------------------------------------------------------------
_STAT_VALUE_STYLE = ParagraphStyle(
    "StatValue", fontSize=18, alignment=TA_CENTER, leading=22
)
_STAT_LABEL_STYLE = ParagraphStyle(
    "StatLabel", fontSize=7.5, alignment=TA_CENTER,
    textColor=colors.HexColor("#666666"),
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hex(col: Any) -> str:
    if hasattr(col, "hexval"):
        return col.hexval().lstrip("#").lower()
    return (
        f"{int(round(col.red   * 255)):02x}"
        f"{int(round(col.green * 255)):02x}"
        f"{int(round(col.blue  * 255)):02x}"
    )


# Styles are stateless — build once and reuse across every export.
_PDF_STYLES: Optional[Dict[str, ParagraphStyle]] = None


def _get_styles() -> Dict[str, ParagraphStyle]:
    global _PDF_STYLES
    if _PDF_STYLES is not None:
        return _PDF_STYLES
    base = getSampleStyleSheet()
    _PDF_STYLES = {
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
    return _PDF_STYLES


# Single-word outputs that carry no diagnostic value in the report.
# Detail rows whose entire content matches one of these are suppressed.
_TRIVIAL_OUTPUT = frozenset({"true", "false", "0", "1", "yes", "no"})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report_pdf(
    save_path: str,
    results_by_path: Dict[str, RunResult],
    rules_by_category: Optional[Dict[str, List[Dict[str, str]]]] = None,
    page_size: str = "A4",
) -> None:
    if rules_by_category is None:
        rules_by_category = {
            "Results": [
                {"path": path, "rule_id": r.get("rule_id", path), "title": r.get("title", "")}
                for path, r in results_by_path.items()
            ]
        }

    now         = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detected_os = _escape_xml(format_os_name(os_scan()))

    # Single pass over results to compute all counts
    counts: Counter = Counter(get_rule_status(r) for r in results_by_path.values())
    total         = len(results_by_path)
    pass_count    = counts["PASS"]
    fail_count    = counts["FAIL"]
    partial_count = counts["PARTIAL"]
    error_count   = counts["ERROR"]
    skip_count    = counts["SKIP"]
    policy_count  = counts["POLICY"]

    S              = _get_styles()
    psize          = LETTER if page_size.upper() == "LETTER" else A4
    page_w, page_h = psize
    margin         = 18 * mm
    content_w      = page_w - 2 * margin
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

    header_data = [
        [Paragraph("Compliance Scan Report", S["title"])],
        [Paragraph(f"Generated : {now}", S["subtitle"])],
        [Paragraph(f"OS Detected: {detected_os}", S["subtitle"])],
        [Paragraph(f"Categories: {len(rules_by_category)}   &nbsp;&nbsp;  Rules evaluated: {total}", S["subtitle"])],
    ]
    header_table = Table(header_data, colWidths=[content_w])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _COL_HEADER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8 * mm))

    stat_labels  = ["Total",      "Pass",       "Fail",      "Partial",       "Skip",      "Error",      "Policy"     ]
    stat_values  = [total,        pass_count,   fail_count,  partial_count,   skip_count,  error_count,  policy_count ]
    stat_colours = [_COL_ACCENT,  _COL_PASS,    _COL_FAIL,   _COL_PARTIAL,    _COL_SKIP,   _COL_FAIL,    _COL_POLICY  ]

    # Build both rows in a single pass — previously called _stat_cell() twice per stat
    stat_row_top = []
    stat_row_bot = []
    for label, value, col in zip(stat_labels, stat_values, stat_colours):
        stat_row_top.append(Paragraph(
            f'<font color="#{_hex(col)}"><b>{value}</b></font>',
            _STAT_VALUE_STYLE,
        ))
        stat_row_bot.append(Paragraph(label, _STAT_LABEL_STYLE))

    card_col_w = content_w / len(stat_labels)
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
            status_bg = _STATUS_BG.get(status, _COL_UNKNOWN)
            status_fg = _STATUS_COLOR.get(status, colors.black)
            rule_id   = _escape_xml(result.get("rule_id", meta["rule_id"]))
            title     = _escape_xml(result.get("title",   meta["title"]))
            chk_run    = result.get("checks_run",     0)
            chk_skip   = result.get("checks_skipped", 0)
            chk_policy = result.get("checks_policy",  0)

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
                        f"Checks run: <b>{chk_run}</b> &nbsp;&nbsp; Skipped: <b>{chk_skip}</b>"
                        + (f" &nbsp;&nbsp; Policy: <b>{chk_policy}</b>" if chk_policy else ""),
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
            automated_checks = [c for c in checks if c.get("status") != "POLICY"]
            policy_checks    = [c for c in checks if c.get("status") == "POLICY"]

            if not checks:
                rule_elements.append(Paragraph("No checks recorded.", S["no_checks"]))
            else:
                # ── Automated checks table ─────────────────────────────────
                # Cols: # | Check Name | Subcontrol | Expected Result | RC | Status
                if automated_checks:
                    aut_cols = [
                        8 * mm, 48 * mm, 18 * mm,
                        content_w - 8*mm - 48*mm - 18*mm - 14*mm - 22*mm,
                        14 * mm, 22 * mm,
                    ]
                    aut_rows = [[
                        Paragraph("<b>#</b>",               S["cell"]),
                        Paragraph("<b>Check Name</b>",      S["cell"]),
                        Paragraph("<b>Subcontrol</b>",      S["cell"]),
                        Paragraph("<b>Expected Result</b>", S["cell"]),
                        Paragraph("<b>RC</b>",              S["cell"]),
                        Paragraph("<b>Status</b>",          S["cell"]),
                    ]]
                    aut_style = [
                        ("BACKGROUND",    (0, 0), (-1, 0),  _COL_HEADER),
                        ("TEXTCOLOR",     (0, 0), (-1, 0),  _COL_WHITE),
                        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                        ("FONTSIZE",      (0, 0), (-1, 0),  8.5),
                        ("TOPPADDING",    (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
                        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                        ("INNERGRID",     (0, 0), (-1, -1), 0.25, _COL_LIGHT),
                        ("BOX",           (0, 0), (-1, -1), 0.5,  _COL_LIGHT),
                    ]

                    for idx, check in enumerate(automated_checks, start=1):
                        row_num  = len(aut_rows)
                        chk_stat = check.get("status", "")
                        chk_bg   = _STATUS_BG.get(chk_stat, _COL_WHITE)
                        chk_fg   = _STATUS_COLOR.get(chk_stat, colors.black)

                        aut_rows.append([
                            Paragraph(str(idx),                                         S["cell"]),
                            Paragraph(_escape_xml(check.get("check_name",    "")),      S["cell"]),
                            Paragraph(_escape_xml(check.get("sub_control",   "")),      S["cell"]),
                            Paragraph(_escape_xml(check.get("expected_result", "")),    S["cell"]),
                            Paragraph(_escape_xml(str(check.get("returncode", ""))),    S["cell"]),
                            Paragraph(
                                f'<font color="#{_hex(chk_fg)}"><b>{_escape_xml(chk_stat)}</b></font>',
                                S["status_text"],
                            ),
                        ])
                        if idx % 2 == 0:
                            aut_style.append(("BACKGROUND", (0, row_num), (-2, row_num), _COL_ROW_ALT))
                        aut_style.append(("BACKGROUND", (5, row_num), (5, row_num), chk_bg))

                        # Output detail row — only shown when the output carries real
                        # diagnostic value. Single-word boolean/numeric outputs (e.g.
                        # "True", "False", "0") are suppressed as they clutter the report.
                        stdout = check.get("stdout", "").strip()
                        stderr = check.get("stderr", "").strip()
                        stdout_useful = stdout and stdout.lower() not in _TRIVIAL_OUTPUT
                        stderr_useful = stderr and stderr.lower() not in _TRIVIAL_OUTPUT
                        if stdout_useful or stderr_useful:
                            parts = []
                            if stdout_useful:
                                parts.append(f"<b>Output:</b> {_escape_xml(stdout[:400])}")
                            if stderr_useful:
                                parts.append(f"<b>Error:</b> {_escape_xml(stderr[:300])}")
                            detail_row = len(aut_rows)
                            detail_bg  = (
                                colors.HexColor("#fff0f0") if chk_stat in ("FAIL", "ERROR")
                                else colors.HexColor("#f0fff4") if chk_stat == "PASS"
                                else _COL_ROW_ALT
                            )
                            aut_rows.append([
                                Paragraph("", S["cell"]),
                                Paragraph("  ".join(parts), S["cell_mono"]),
                                Paragraph("", S["cell"]),
                                Paragraph("", S["cell"]),
                                Paragraph("", S["cell"]),
                                Paragraph("", S["cell"]),
                            ])
                            aut_style.append(("SPAN",           (1, detail_row), (5, detail_row)))
                            aut_style.append(("BACKGROUND",     (0, detail_row), (-1, detail_row), detail_bg))
                            aut_style.append(("LEFTPADDING",    (1, detail_row), (1, detail_row), 8))
                            aut_style.append(("BOTTOMPADDING",  (0, detail_row), (-1, detail_row), 6))

                    aut_tbl = Table(aut_rows, colWidths=aut_cols, repeatRows=1)
                    aut_tbl.setStyle(TableStyle(aut_style))
                    rule_elements.append(aut_tbl)

                # ── Policy checks table ────────────────────────────────────
                # Separate table with "Policy Requirement" column in place of
                # Expected Result + RC — policy checks have no executable command.
                if policy_checks:
                    if automated_checks:
                        rule_elements.append(Spacer(1, 2 * mm))

                    pol_header_tbl = Table(
                        [[Paragraph(
                            "Policy Requirements",
                            ParagraphStyle("PolSectionLabel", fontSize=8,
                                           fontName="Helvetica-Bold", textColor=_COL_WHITE),
                        )]],
                        colWidths=[content_w],
                    )
                    pol_header_tbl.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), _COL_POLICY),
                        ("TOPPADDING",    (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                    ]))
                    rule_elements.append(pol_header_tbl)

                    pol_cols = [
                        8 * mm, 48 * mm, 18 * mm,
                        content_w - 8*mm - 48*mm - 18*mm - 22*mm,
                        22 * mm,
                    ]
                    pol_rows = [[
                        Paragraph("<b>#</b>",                  S["cell"]),
                        Paragraph("<b>Check Name</b>",         S["cell"]),
                        Paragraph("<b>Subcontrol</b>",         S["cell"]),
                        Paragraph("<b>Policy Requirement</b>", S["cell"]),
                        Paragraph("<b>Status</b>",             S["cell"]),
                    ]]
                    _POL_GRID  = colors.HexColor("#d8b4fe")
                    _POL_ALT   = colors.HexColor("#f5f0ff")
                    _POL_ST_BG = colors.HexColor("#ede9fe")
                    pol_style = [
                        ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#3d1a6e")),
                        ("TEXTCOLOR",     (0, 0), (-1, 0),  _COL_WHITE),
                        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                        ("FONTSIZE",      (0, 0), (-1, 0),  8.5),
                        ("TOPPADDING",    (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
                        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                        ("INNERGRID",     (0, 0), (-1, -1), 0.25, _POL_GRID),
                        ("BOX",           (0, 0), (-1, -1), 0.5,  _COL_POLICY),
                    ]

                    for pol_idx, check in enumerate(policy_checks, start=1):
                        pol_row = len(pol_rows)
                        purpose = _escape_xml(check.get("stdout", "") or "")
                        pol_rows.append([
                            Paragraph(str(pol_idx), S["cell"]),
                            Paragraph(_escape_xml(check.get("check_name",  "")), S["cell"]),
                            Paragraph(_escape_xml(check.get("sub_control", "")), S["cell"]),
                            Paragraph(purpose,                                   S["cell"]),
                            Paragraph(
                                f'<font color="#{_hex(_COL_POLICY)}"><b>POLICY</b></font>',
                                S["status_text"],
                            ),
                        ])
                        if pol_idx % 2 == 0:
                            pol_style.append(("BACKGROUND", (0, pol_row), (-2, pol_row), _POL_ALT))
                        pol_style.append(("BACKGROUND", (4, pol_row), (4, pol_row), _POL_ST_BG))

                    pol_tbl = Table(pol_rows, colWidths=pol_cols, repeatRows=1)
                    pol_tbl.setStyle(TableStyle(pol_style))
                    rule_elements.append(pol_tbl)

            rule_elements.append(Spacer(1, 4 * mm))
            cat_block.append(KeepTogether(rule_elements[:3]))
            cat_block.extend(rule_elements[3:])

        story.extend(cat_block)

    doc = SimpleDocTemplate(
        save_path, pagesize=psize,
        leftMargin=margin, rightMargin=margin,
        topMargin=margin, bottomMargin=margin,
        title="Compliance Scan Report",
        author="RuleForge",
        subject=f"Scan performed {now} on {detected_os}",
    )
    doc.build(story, onFirstPage=_draw_header, onLaterPages=_draw_later)
