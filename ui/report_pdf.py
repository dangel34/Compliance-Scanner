"""
PDF report generation for the Compliance Scanner.
"""
from __future__ import annotations

import datetime
from collections import Counter
from typing import Any, Dict, List

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
}
_STATUS_BG: Dict[str, Any] = {
    "PASS":    colors.HexColor("#d4edda"),
    "FAIL":    colors.HexColor("#f8d7da"),
    "PARTIAL": colors.HexColor("#fff3cd"),
    "ERROR":   colors.HexColor("#f8d7da"),  # same as FAIL
    "SKIP":    colors.HexColor("#e2e3e5"),
    "NOT_RUN": colors.HexColor("#e2e3e5"),
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report_pdf(
    save_path: str,
    results_by_path: Dict[str, RunResult],
    rules_by_category: Dict[str, List[Dict[str, str]]],
) -> None:
    now         = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detected_os = _escape_xml(format_os_name(os_scan()))

    # Single pass over results to compute all counts
    counts: Counter = Counter(get_rule_status(r) for r in results_by_path.values())
    total        = len(results_by_path)
    pass_count   = counts["PASS"]
    fail_count   = counts["FAIL"]
    partial_count= counts["PARTIAL"]
    error_count  = counts["ERROR"]
    skip_count   = counts["SKIP"]

    S              = _make_styles()
    page_w, page_h = A4
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

    stat_labels  = ["Total",      "Pass",       "Fail",      "Partial",       "Skip",      "Error"     ]
    stat_values  = [total,        pass_count,   fail_count,  partial_count,   skip_count,  error_count ]
    stat_colours = [_COL_ACCENT,  _COL_PASS,    _COL_FAIL,   _COL_PARTIAL,    _COL_SKIP,   _COL_FAIL   ]

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
                    ("FONTSIZE",      (0, 0), (-1, 0),  8.5),
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
                        Paragraph(str(idx),                                        S["cell"]),
                        Paragraph(_escape_xml(check.get("check_name",      "")),   S["cell"]),
                        Paragraph(_escape_xml(check.get("sub_control",     "")),   S["cell"]),
                        Paragraph(_escape_xml(check.get("expected_result", "")),   S["cell"]),
                        Paragraph(_escape_xml(str(check.get("returncode",  ""))),  S["cell"]),
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
