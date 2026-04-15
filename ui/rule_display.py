"""
Rule display rendering for the RuleForge UI.

Renders rule results and rule metadata previews into a tk.Text widget
using named color/font tags.
"""
from __future__ import annotations

import json
import os
import tkinter as tk
import tkinter.font as tkfont
from typing import Any, Dict, List, Optional

from ui.utils import RunResult, _safe_str, format_os_name, get_rule_status

# Imported after utils ensures PROJECT_ROOT is on sys.path
from core import os_scan

# ---------------------------------------------------------------------------
# Module-level constants — computed once, never repeated
# ---------------------------------------------------------------------------

# OS is fixed for the lifetime of the process; cache it now
_DETECTED_OS: str = os_scan()

# Divider line used in both render functions
_DIVIDER = "  " + "─" * 62 + "\n"

# Cap on stdout/stderr lines rendered into the text widget.
# Prevents the widget from slowing to a crawl on high-verbosity command output.
_MAX_OUTPUT_LINES = 80

# Status -> tag name mapping; dict literal created once, not per-call
_STATUS_TAG_MAP: Dict[str, str] = {
    "PASS":    "status_pass",
    "FAIL":    "status_fail",
    "PARTIAL": "status_partial",
    "SKIP":    "status_skip",
    "ERROR":   "status_error",
    "POLICY":  "status_policy",
}

# ---------------------------------------------------------------------------
# Font cache — created once per process, reused on every theme toggle
# ---------------------------------------------------------------------------

_FONT_NORMAL: Optional[tkfont.Font] = None
_FONT_BOLD:   Optional[tkfont.Font] = None


def _get_fonts() -> tuple:
    global _FONT_NORMAL, _FONT_BOLD
    if _FONT_NORMAL is None:
        _FONT_NORMAL = tkfont.Font(family="Consolas", size=10)
        _FONT_BOLD   = tkfont.Font(family="Consolas", size=10, weight="bold")
    return _FONT_NORMAL, _FONT_BOLD


# ---------------------------------------------------------------------------
# Tag definitions  tag -> (fg_dark, bg_dark, fg_light, bg_light, bold)
# ---------------------------------------------------------------------------

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
    "status_policy":  ("#a78bfa", None,      "#5b21b6", None,       True),
    "policy_label":   ("#c4b5fd", None,      "#6d28d9", None,       True),
    "policy_text":    ("#ddd6fe", None,      "#4c1d95", None,       False),
    "check_header":   ("#ffffff", "#1e3a5f", "#ffffff", "#1e3a5f",  True),
    "divider":        ("#3d5166", None,      "#9baab8", None,       False),
    "stdout_label":   ("#27ae60", None,      "#1a7a3a", None,       True),
    "stderr_label":   ("#e67e22", None,      "#b05010", None,       True),
    "stdout_text":    ("#abebc6", None,      "#1a5c30", None,       False),
    "stderr_text":    ("#f0b27a", None,      "#7a3800", None,       False),
    "error_banner":      ("#e74c3c", "#2c1515", "#cc0000", "#ffe0e0",  True),
    "meta":              ("#85929e", None,      "#666e75", None,       False),
    "remediation_label": ("#f39c12", None,      "#9a5c00", None,       True),
    "remediation_text":  ("#f8c471", None,      "#7a4500", None,       False),
}


def _configure_tags(widget: tk.Text, mode: str = "dark") -> None:
    """
    Apply all named color/font tags to a tk.Text widget.
    Safe to call on every theme toggle — reuses cached Font objects.
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
    return _STATUS_TAG_MAP.get(status, "value")


# ---------------------------------------------------------------------------
# Internal helper: merge consecutive same-tag segments and insert into widget
# ---------------------------------------------------------------------------

def _flush(widget: tk.Text, segments: List[tuple]) -> None:
    if not segments:
        return
    merged: List[tuple] = [segments[0]]
    for text, tag in segments[1:]:
        if tag == merged[-1][1]:
            merged[-1] = (merged[-1][0] + text, tag)
        else:
            merged.append((text, tag))
    for text, tag in merged:
        widget.insert("end", text, tag)


# ---------------------------------------------------------------------------
# Public render functions
# ---------------------------------------------------------------------------

def render_placeholder(widget: tk.Text, message: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", f"\n  {message}\n", "meta")
    widget.configure(state="disabled")


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
        w("  Severity         : ", "label"); w(f"{result.get('severity', '') or '—'}\n",               "value")
        w("  OS               : ", "label"); w(f"{result.get('os', '')}\n",                             "value")
        w("  Checks run       : ", "label"); w(f"{result.get('checks_run', 0)}\n",                      "value")
        w("  Checks skipped   : ", "label"); w(f"{result.get('checks_skipped', 0)} (NA subcontrols)\n", "value")
        policy_count = result.get("checks_policy", 0)
        if policy_count:
            w("  Policy checks    : ", "label"); w(f"{policy_count} (require human review)\n", "status_policy")

        remediation = _safe_str(result.get("remediation", ""), max_len=2048).strip()
        if remediation and status in ("FAIL", "PARTIAL", "ERROR"):
            w("\n")
            w(_DIVIDER, "divider")
            w("  Remediation\n", "remediation_label")
            for line in remediation.splitlines():
                w(f"  {line}\n", "remediation_text")

        w("\n")

        for i, check in enumerate(result.get("checks", []), start=1):
            chk_status = check.get("status", "")
            chk_tag    = _status_tag(chk_status)

            w(f"  CHECK #{i}  |  {check.get('check_name', '')}\n", "check_header")
            w("  Subcontrol       : ", "label"); w(f"{check.get('sub_control', '')}\n", "value")
            w("  Status           : ", "label"); w(f"{chk_status}\n", chk_tag)

            if chk_status == "POLICY":
                purpose = check.get("stdout", "").strip()  # purpose stored in stdout field
                if purpose:
                    w("\n  Policy requirement:\n", "policy_label")
                    for line in purpose.splitlines():
                        w(f"    {line}\n", "policy_text")
            else:
                w("  Command          : ", "label"); w(f"{check.get('command',         '')}\n", "value")
                w("  Expected result  : ", "label"); w(f"{check.get('expected_result', '')}\n", "value")
                w("  Return code      : ", "label"); w(f"{check.get('returncode',      '')}\n", "value")

                stdout = check.get("stdout", "").strip()
                stderr = check.get("stderr", "").strip()
                if stdout:
                    w("\n  stdout:\n", "stdout_label")
                    lines = stdout.splitlines()
                    for line in lines[:_MAX_OUTPUT_LINES]:
                        w(f"    {line}\n", "stdout_text")
                    if len(lines) > _MAX_OUTPUT_LINES:
                        w(f"    … {len(lines) - _MAX_OUTPUT_LINES} more lines truncated\n", "meta")
                if stderr:
                    w("\n  stderr:\n", "stderr_label")
                    lines = stderr.splitlines()
                    for line in lines[:_MAX_OUTPUT_LINES]:
                        w(f"    {line}\n", "stderr_text")
                    if len(lines) > _MAX_OUTPUT_LINES:
                        w(f"    … {len(lines) - _MAX_OUTPUT_LINES} more lines truncated\n", "meta")

            w("\n")
            w(_DIVIDER, "divider")
            w("\n")

    _flush(widget, segments)
    widget.configure(state="disabled")


def render_rule_info(widget: tk.Text, rule_path: str) -> None:
    """
    Display a read-only preview of a rule's metadata for the detected OS,
    styled to match render_rule_details.
    """
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        render_placeholder(widget, "Could not load rule file.")
        return

    widget.configure(state="normal")
    widget.delete("1.0", "end")

    segments: List[tuple] = []

    def w(text: str, tag: str = "value") -> None:
        segments.append((text, tag))

    rule_id     = _safe_str(data.get("id") or data.get("control_number") or os.path.basename(rule_path))
    title       = _safe_str(data.get("title", ""))
    description = _safe_str(data.get("description", ""), max_len=1024)
    severity    = _safe_str(data.get("severity", ""))
    remediation = _safe_str(data.get("remediation", ""), max_len=2048).strip()

    w("\n")
    w(f"  {rule_id}", "rule_id")
    w("  —  ", "divider")
    w(f"{title}\n", "title")
    w("\n")
    w("  Description      : ", "label"); w(f"{description}\n" if description else "—\n", "value")
    w("  Severity         : ", "label"); w(f"{severity}\n"    if severity    else "—\n", "value")
    w("  OS               : ", "label"); w(f"{format_os_name(_DETECTED_OS)}\n",          "value")

    if remediation:
        w("\n")
        w(_DIVIDER, "divider")
        w("  Remediation\n", "remediation_label")
        for line in remediation.splitlines():
            w(f"  {line}\n", "remediation_text")

    w("\n")

    check_details: Dict[str, Any] = data.get("check_details", {})
    os_block = check_details.get(_DETECTED_OS, {}) if isinstance(check_details, dict) else {}
    checks   = os_block.get("checks", [])           if isinstance(os_block, dict)     else []

    if not checks:
        w(f"  No checks defined for {format_os_name(_DETECTED_OS)}.\n", "meta")
    else:
        for i, check in enumerate(checks, start=1):
            name        = _safe_str(check.get("name") or check.get("check_name", ""))
            sub_control = _safe_str(check.get("sub_control", ""))
            purpose     = _safe_str(check.get("purpose", ""), max_len=512)

            w(f"  CHECK #{i}  |  {name}\n", "check_header")
            w("  Subcontrol       : ", "label"); w(f"{sub_control}\n", "value")
            w("  Purpose          : ", "label"); w(f"{purpose}\n" if purpose else "—\n", "value")
            w("\n")
            w(_DIVIDER, "divider")
            w("\n")

    w("  Run this rule to see results.\n", "meta")

    _flush(widget, segments)
    widget.configure(state="disabled")
