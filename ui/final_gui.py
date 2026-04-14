"""
Compliance Scanner — main GUI entry point.

Handles layout, threading, accordion rule list, and scan orchestration.
Rendering and export logic live in the ui sub-modules:
  ui/rule_display.py  — tk.Text widget rendering
  ui/report_pdf.py    — PDF generation
  ui/report_csv.py    — CSV generation
  ui/utils.py         — shared helpers and PROJECT_ROOT setup
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import re
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Any, Dict, List, Optional

import customtkinter as ctk

# Ensure PROJECT_ROOT is on sys.path before any ui.* or core.* imports.
# This is needed when final_gui.py is run directly as a script.
def _bootstrap_path() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
_bootstrap_path()
del _bootstrap_path

from ui.utils import PROJECT_ROOT, RunResult, _safe_str, format_os_name, get_rule_status, setup_logging

_log = logging.getLogger(__name__)
from ui.rule_display import _configure_tags, render_placeholder, render_rule_details, render_rule_info
from ui.report_pdf import generate_report_pdf
from ui.report_csv import generate_report_csv

from core import os_scan
from core.rule_runner import RuleRunner


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def _fmt_duration(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


# ---------------------------------------------------------------------------
# Rule discovery helpers — defined at module level so they are not
# recreated on every call to discover_rule_files()
# ---------------------------------------------------------------------------

def _cat_sort_key(cat: str) -> tuple:
    return (cat.lower() == "uncategorised", cat.lower())


def _natural_key(meta: Dict[str, str]) -> list:
    fname = os.path.basename(meta["path"])
    return [
        int(chunk) if chunk.isdigit() else chunk.lower()
        for chunk in re.split(r"(\d+)", fname)
    ]


# ---------------------------------------------------------------------------
# Rule discovery
# ---------------------------------------------------------------------------

_RULE_SCHEMA: Optional[Dict[str, Any]] = None
_RULE_SCHEMA_LOADED: bool = False


def _load_rule_schema() -> Optional[Dict[str, Any]]:
    global _RULE_SCHEMA, _RULE_SCHEMA_LOADED
    if _RULE_SCHEMA_LOADED:
        return _RULE_SCHEMA
    _RULE_SCHEMA_LOADED = True
    schema_path = os.path.join(PROJECT_ROOT, "rulesets", "rule_schema.json")
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            _RULE_SCHEMA = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning("Could not load rule_schema.json: %s", exc)
    return _RULE_SCHEMA


def _validate_rule(data: Dict[str, Any]) -> List[str]:
    try:
        import jsonschema
    except ImportError:
        return []
    schema = _load_rule_schema()
    if schema is None:
        return []
    try:
        jsonschema.validate(data, schema)
        return []
    except jsonschema.ValidationError as exc:
        return [exc.message]
    except jsonschema.SchemaError as exc:
        _log.warning("rule_schema.json is itself invalid: %s", exc.message)
        return []


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

    rules_dir_real = os.path.realpath(rules_dir)

    for root, _, files in os.walk(rules_dir):
        for name in sorted(files):
            if not name.lower().endswith(".json"):
                continue
            if name.lower() in ("rule_template.json", "rule_schema.json"):
                continue

            full_path = os.path.join(root, name)
            try:
                real_path = os.path.realpath(full_path)
            except OSError:
                continue
            if not real_path.startswith(rules_dir_real + os.sep) and real_path != rules_dir_real:
                continue

            try:
                with open(real_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for err in _validate_rule(data):
                    _log.warning("Schema validation error in %s: %s", real_path, err)
                category = _safe_str(data.get("category") or "Uncategorised") or "Uncategorised"
                rule_id  = _safe_str(data.get("id") or data.get("rule_id") or name)
                title    = _safe_str(data.get("title") or data.get("control_number") or name)
                severity = _safe_str(data.get("severity", ""))
            except json.JSONDecodeError:
                _log.warning("Skipping malformed JSON: %s", real_path)
                continue
            except OSError as exc:
                _log.warning("Could not read rule file %s: %s", real_path, exc)
                continue

            categories.setdefault(category, []).append(
                {"path": real_path, "rule_id": rule_id, "title": title,
                 "severity": severity, "category": category}
            )

    return {
        cat: sorted(metas, key=_natural_key)
        for cat, metas in sorted(categories.items(), key=lambda kv: _cat_sort_key(kv[0]))
    }


# ---------------------------------------------------------------------------
# Blocking rule runner (called from background thread)
# ---------------------------------------------------------------------------

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
            error_msg = _safe_str(type(e).__name__ + ": " + str(e), max_len=256)
            _log.error("Rule execution error: %s: %s", os.path.basename(path), error_msg)
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


# ---------------------------------------------------------------------------
# Accordion widget
# ---------------------------------------------------------------------------

class AccordionSection:
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
        self.body_frame.columnconfigure(0, weight=1)

        for row, meta in enumerate(rule_metas):
            btn = ctk.CTkButton(
                self.body_frame,
                text=meta["rule_id"],
                anchor="w",
                fg_color="transparent",
                text_color=("#1a1a1a", "#e0e0e0"),
                hover_color=("#4a90d9", "#3a7abf"),
                command=lambda p=meta["path"]: on_rule_select(p),
            )
            btn.grid(row=row, column=0, sticky="ew", pady=2)
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
        color    = self._COLOR_MAP.get(status)
        fg_color = color if color is not None else "transparent"
        text_col = ("white", "white") if color is not None else ("#1a1a1a", "#e0e0e0")
        btn.configure(text=f"{rule_id}{icon}", fg_color=fg_color, text_color=text_col)

    def apply_filter(self, visible_paths: set) -> bool:
        """
        Show only the rule buttons whose path is in visible_paths.
        Uses grid_remove/grid so positions are preserved when rules reappear.
        Returns True if at least one button is visible.
        """
        any_visible = False
        for path, btn in self.rule_buttons.items():
            if path in visible_paths:
                btn.grid()
                any_visible = True
            else:
                btn.grid_remove()
        return any_visible

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


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

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
        self._path_to_section:   Dict[str, AccordionSection]      = {}

        self.theme:         str  = "dark"
        self.running:       bool = False
        self.all_rules_run: bool = False

        self._filter_category: str = "All"
        self._filter_severity: str = "All"
        self._filter_category_menu: Optional[ctk.CTkOptionMenu] = None
        self._filter_severity_menu: Optional[ctk.CTkOptionMenu] = None

        self.refresh_btn:    Optional[ctk.CTkButton] = None
        self.run_all_btn:    Optional[ctk.CTkButton] = None
        self.export_btn:     Optional[ctk.CTkButton] = None
        self.export_csv_btn: Optional[ctk.CTkButton] = None

        # Summary dashboard widgets — populated in _build_summary_panel()
        self._stat_count_labels: Dict[str, ctk.CTkLabel] = {}
        self._score_bar:         Optional[ctk.CTkProgressBar] = None
        self._score_label:       Optional[ctk.CTkLabel]       = None
        self._summary_meta:      Optional[ctk.CTkLabel]       = None

        self._build_layout()
        self.refresh_rules()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Keyboard shortcuts
        self.bind("<Control-r>", lambda _e: self.run_all_rules())
        self.bind("<Control-e>", lambda _e: self.export_report())
        self.bind("<F5>",        lambda _e: self.refresh_rules())

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

        self.refresh_btn = ctk.CTkButton(top, text="Refresh Rules (F5)", command=self.refresh_rules)
        self.refresh_btn.pack(side="right", padx=10, pady=8)

        ctk.CTkButton(
            top, text="About", command=self._show_about,
            width=70, fg_color="transparent",
            border_width=1,
            border_color=("#444444", "#888888"),
            text_color=("#1a1a1a", "#e0e0e0"),
            hover_color=("#d0d0d0", "#3a3a3a"),
        ).pack(side="right", padx=(0, 4), pady=8)

        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=10, pady=6)

        left = ctk.CTkFrame(main, width=320)
        left.pack(side="left", fill="y", padx=(10, 6), pady=10)

        right = ctk.CTkFrame(main)
        right.pack(side="right", fill="both", expand=True, padx=(6, 10), pady=10)

        ctk.CTkLabel(left, text="Rules", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=10, pady=(10, 4)
        )

        filter_row = ctk.CTkFrame(left, fg_color="transparent")
        filter_row.pack(fill="x", padx=10, pady=(0, 4))
        filter_row.columnconfigure(0, weight=1)
        filter_row.columnconfigure(1, weight=1)

        self._filter_category_menu = ctk.CTkOptionMenu(
            filter_row,
            values=["All"],
            command=self._on_category_filter,
            width=130,
            font=ctk.CTkFont(size=11),
            dynamic_resizing=False,
        )
        self._filter_category_menu.grid(row=0, column=0, sticky="ew", padx=(0, 3))

        self._filter_severity_menu = ctk.CTkOptionMenu(
            filter_row,
            values=["All", "Critical", "High", "Medium", "Low"],
            command=self._on_severity_filter,
            width=130,
            font=ctk.CTkFont(size=11),
            dynamic_resizing=False,
        )
        self._filter_severity_menu.grid(row=0, column=1, sticky="ew", padx=(3, 0))

        self.rules_scroll = ctk.CTkScrollableFrame(left)
        self.rules_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._build_summary_panel(right)

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

        # Row 1: run buttons (left) — status label (centre, expands) — export buttons (right)
        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(8, 4))

        self.run_all_btn = ctk.CTkButton(btn_row, text="Run All Rules (Ctrl+R)", command=self.run_all_rules, width=175)
        self.run_all_btn.pack(side="left", padx=(0, 6))

        self.run_selected_btn = ctk.CTkButton(
            btn_row, text="Run Selected Rule", command=self.run_selected_rule, state="disabled", width=140
        )
        self.run_selected_btn.pack(side="left", padx=(0, 6))

        self.export_csv_btn = ctk.CTkButton(
            btn_row, text="Export CSV", command=self.export_csv, state="disabled", width=120,
            fg_color=("#1a4a6b", "#0f2d45"), hover_color=("#2167a0", "#1a4a6b"),
        )
        self.export_csv_btn.pack(side="right", padx=(6, 0))

        self.export_btn = ctk.CTkButton(
            btn_row, text="Export PDF", command=self.export_report, state="disabled", width=120,
            fg_color=("#2d6a4f", "#1b4332"), hover_color=("#40916c", "#2d6a4f"),
        )
        self.export_btn.pack(side="right", padx=(0, 6))

        self.status_label = ctk.CTkLabel(btn_row, text="Status: Idle", anchor="center",
                                         font=ctk.CTkFont(size=12))
        self.status_label.pack(side="left", fill="x", expand=True)

        # Row 2: progress bar (full width) — percentage (right)
        progress_row = ctk.CTkFrame(bottom, fg_color="transparent")
        progress_row.pack(fill="x", padx=10, pady=(0, 8))

        self.progress_label = ctk.CTkLabel(progress_row, text="0%", width=36, anchor="e",
                                           font=ctk.CTkFont(size=11))
        self.progress_label.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(progress_row, height=14)
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.progress_bar.set(0.0)

    # ------------------------------------------------------------------
    def _build_summary_panel(self, parent: ctk.CTkFrame) -> None:
        """
        Build the visual compliance summary dashboard that sits above the
        rule details pane.  The panel contains five stat cards (Total, Pass,
        Fail, Partial, Skip) and a compliance score bar.  All mutable widgets
        are stored on self so _update_summary_display() can update them later.
        """
        outer = ctk.CTkFrame(parent, fg_color="transparent")
        outer.pack(fill="x", padx=10, pady=(10, 4))

        # Title row — title on the left, meta (categories / rules) on the right
        title_row = ctk.CTkFrame(outer, fg_color="transparent")
        title_row.pack(fill="x")

        ctk.CTkLabel(
            title_row, text="Compliance Summary",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(side="left")

        self._summary_meta = ctk.CTkLabel(
            title_row, text="",
            font=ctk.CTkFont(size=11), anchor="e",
        )
        self._summary_meta.pack(side="right")

        # Stat cards — each card shows a large count and a status label
        #   (bg_dark, bg_light)        (fg_dark, fg_light)
        card_defs = [
            ("total",   "Total",   ("#3d3d3d", "#d4d4d4"), ("#e0e0e0", "#1a1a1a")),
            ("pass",    "Pass",    ("#1a4a2a", "#b8eacc"), ("#2ecc71", "#1a7a3a")),
            ("fail",    "Fail",    ("#4a1a1a", "#f0c8c8"), ("#e74c3c", "#a01010")),
            ("partial", "Partial", ("#4a3800", "#f0dfaa"), ("#f0c040", "#7a5c00")),
            ("skip",    "Skip",    ("#2e2e2e", "#d0d0d0"), ("#95a5a6", "#555e65")),
        ]

        cards_row = ctk.CTkFrame(outer, fg_color="transparent")
        cards_row.pack(fill="x", pady=(6, 0))

        for key, label_text, bg, fg in card_defs:
            card = ctk.CTkFrame(cards_row, fg_color=bg, corner_radius=8)
            card.pack(side="left", expand=True, fill="x", padx=3)

            count_lbl = ctk.CTkLabel(
                card, text="—",
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color=fg,
            )
            count_lbl.pack(pady=(8, 0))

            ctk.CTkLabel(
                card, text=label_text,
                font=ctk.CTkFont(size=10),
                text_color=fg,
            ).pack(pady=(0, 8))

            self._stat_count_labels[key] = count_lbl

        # Score row — label left, percentage right, bar below
        score_row = ctk.CTkFrame(outer, fg_color="transparent")
        score_row.pack(fill="x", pady=(10, 0))

        ctk.CTkLabel(
            score_row, text="Compliance Score",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(side="left")

        self._score_label = ctk.CTkLabel(
            score_row, text="—",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self._score_label.pack(side="right")

        self._score_bar = ctk.CTkProgressBar(outer, height=14)
        self._score_bar.pack(fill="x", pady=(4, 6))
        self._score_bar.set(0.0)

    def _update_summary_display(
        self,
        total: int          = 0,
        pass_count: int     = 0,
        fail_count: int     = 0,
        partial_count: int  = 0,
        skip_count: int     = 0,
        error_count: int    = 0,
        cat_count: int      = 0,
        checks_passed: int  = 0,
        checks_total: int   = 0,
    ) -> None:
        """Refresh every widget in the summary dashboard with new counts."""
        if self._summary_meta is not None:
            self._summary_meta.configure(
                text=f"{cat_count} {'category' if cat_count == 1 else 'categories'}  |  {total} rules"
            )

        combined_fail = fail_count + error_count
        if self._stat_count_labels:
            self._stat_count_labels["total"].configure(text=str(total))
            self._stat_count_labels["pass"].configure(text=str(pass_count))
            self._stat_count_labels["fail"].configure(text=str(combined_fail))
            self._stat_count_labels["partial"].configure(text=str(partial_count))
            self._stat_count_labels["skip"].configure(text=str(skip_count))

        # Score is based on individual subcontrols (checks), not rules.
        # checks_total is the number of checks that actually ran (skipped checks excluded).
        if checks_total > 0:
            ratio    = checks_passed / checks_total
            pct_text = f"{int(ratio * 100)}%"
        else:
            ratio    = 0.0
            pct_text = "—"

        if self._score_label is not None:
            self._score_label.configure(text=pct_text)
        if self._score_bar is not None:
            self._score_bar.set(ratio)

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
            self.progress_label.configure(text=f"{int(value * 100)}%")

    def _all_rule_paths(self) -> List[str]:
        """Return paths for all rules that pass the active category/severity filters."""
        cat_filter = self._filter_category
        sev_filter = self._filter_severity
        return [
            m["path"] for m in self.rules
            if (cat_filter == "All" or m.get("category", "") == cat_filter)
            and (sev_filter == "All" or m.get("severity", "") == sev_filter)
        ]

    def _section_for_path(self, path: str) -> Optional[AccordionSection]:
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

        # Rebuild category dropdown with current rule set
        cat_names = ["All"] + sorted(categories.keys())
        if self._filter_category_menu:
            self._filter_category_menu.configure(values=cat_names)
            self._filter_category_menu.set("All")
        if self._filter_severity_menu:
            self._filter_severity_menu.set("All")
        self._filter_category = "All"
        self._filter_severity = "All"

        total     = len(self.rules)
        cat_count = len(self.rules_by_category)
        _log.info("Rules loaded: %d rules across %d categories", total, cat_count)
        self._update_summary_display(total=total, cat_count=cat_count)
        render_placeholder(self.details_text, "Run rules to view results.")
        self.selected_rule_path = None
        self.all_rules_run      = False
        self.run_selected_btn.configure(state="disabled")
        self.set_status("Idle")

    # ------------------------------------------------------------------
    def _on_category_filter(self, value: str):
        self._filter_category = value
        self._apply_filters()

    def _on_severity_filter(self, value: str):
        self._filter_severity = value
        self._apply_filters()

    def _apply_filters(self):
        """
        Compute the set of rule paths that match the active category and
        severity filters, then show/hide accordion buttons accordingly.
        Sections whose every rule is filtered out are hidden entirely.
        Sections are always re-packed in their original insertion order so
        the category list never jumbles after a filter change.
        """
        cat_filter = self._filter_category
        sev_filter = self._filter_severity

        visible: set = set()
        for meta in self.rules:
            cat_match = (cat_filter == "All" or meta.get("category", "") == cat_filter)
            sev_match = (sev_filter == "All" or meta.get("severity", "") == sev_filter)
            if cat_match and sev_match:
                visible.add(meta["path"])

        # Re-pack all section wrappers in insertion order, hiding empty ones
        for section in self.accordion_sections.values():
            section.wrapper.pack_forget()

        for section in self.accordion_sections.values():
            has_visible = section.apply_filter(visible)
            if has_visible:
                section.wrapper.pack(fill="x", pady=(4, 0), padx=2)

        visible_count = len(visible)
        total_count   = len(self.rules)
        if visible_count == total_count:
            self.set_status("Idle")
        else:
            self.set_status(f"Filter active: {visible_count} of {total_count} rules shown")

    # ------------------------------------------------------------------
    def select_rule(self, rule_path: str):
        self.selected_rule_path = rule_path

        for section in self.accordion_sections.values():
            section.highlight_selected(rule_path, self.results_by_path)

        if not self.running:
            self.run_selected_btn.configure(state="normal")

        result = self.results_by_path.get(rule_path)
        if result:
            render_rule_details(self.details_text, result)
        else:
            render_rule_info(self.details_text, rule_path)

        if not self.running:
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
        _log.info("Scan started: %d rules (category=%s, severity=%s)",
                  len(rule_paths), self._filter_category, self._filter_severity)

        _last_update: List[float] = [0.0]
        _scan_start:  List[float] = [time.monotonic()]

        def progress_cb(i: int, total: int, _path: str):
            now = time.monotonic()
            if i == total or (now - _last_update[0]) >= 0.1:
                _last_update[0] = now
                progress  = i / total if total else 0
                completed = i - 1
                elapsed   = now - _scan_start[0]
                if completed > 0 and i < total:
                    rate        = elapsed / completed
                    remaining   = (total - completed) * rate
                    status_text = f"Running… ({i}/{total}) — ~{_fmt_duration(remaining)} remaining"
                else:
                    status_text = f"Running… ({i}/{total})"
                self.after(0, lambda p=progress, s=status_text:
                           (self.set_status(s), self._update_progress(p)))

        def worker():
            results = run_rules_blocking(rule_paths, progress_cb=progress_cb)
            elapsed = time.monotonic() - _scan_start[0]
            self.after(0, lambda r=results, e=elapsed: self._on_all_rules_done(r, e))

        threading.Thread(target=worker, daemon=True).start()

    def _on_all_rules_done(self, results: Dict[str, RunResult], elapsed: float = 0.0):
        self.running         = False
        self.results_by_path = results
        pass_count = fail_count = partial_count = skip_count = error_count = 0
        checks_passed = checks_total = 0

        # Single pass: update button colours and tally rule + subcontrol counts
        for path, result in results.items():
            status  = get_rule_status(result)
            section = self._section_for_path(path)
            if section:
                section.set_button_color(path, status, result.get("rule_id", os.path.basename(path)))
            if status == "PASS":
                pass_count += 1
            elif status == "FAIL":
                fail_count += 1
            elif status == "PARTIAL":
                partial_count += 1
            elif status == "ERROR":
                error_count += 1
            else:
                skip_count += 1

            # Tally individual subcontrol (check) results for the score
            for check in result.get("checks", []):
                checks_total += 1
                if check.get("status") == "PASS":
                    checks_passed += 1

        if self.selected_rule_path:
            for section in self.accordion_sections.values():
                section.highlight_selected(self.selected_rule_path, results)

        self._update_summary_display(
            total          = len(results),
            pass_count     = pass_count,
            fail_count     = fail_count,
            partial_count  = partial_count,
            skip_count     = skip_count,
            error_count    = error_count,
            cat_count      = len(self.rules_by_category),
            checks_passed  = checks_passed,
            checks_total   = checks_total,
        )
        _log.info(
            "Scan complete in %s. Pass=%d Fail=%d Partial=%d Skip=%d Error=%d",
            _fmt_duration(elapsed), pass_count, fail_count, partial_count, skip_count, error_count,
        )
        self._update_progress(1.0)
        self.set_status(f"Done  ({_fmt_duration(elapsed)} total)")
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
    def _run_export(
        self,
        ext: str,
        filetypes: list,
        dialog_title: str,
        busy_status: str,
        success_prefix: str,
        worker_fn: callable,
    ) -> None:
        """
        Common save-dialog → path-validation → background-thread pattern
        shared by all export actions.
        """
        if not self.all_rules_run or not self.results_by_path:
            self.set_status("Run All Rules first before exporting.")
            return

        default_name = f"compliance_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        save_path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=filetypes,
            initialfile=default_name,
            title=dialog_title,
        )
        if not save_path:
            return

        if not save_path.lower().endswith(ext):
            save_path += ext
        save_dir = os.path.dirname(os.path.abspath(save_path)) or "."
        if not os.path.isdir(save_dir) or not os.access(save_dir, os.W_OK):
            messagebox.showerror("Export Error", f"Cannot write to directory:\n{save_dir}")
            return

        self.set_status(busy_status)
        self._set_controls_enabled(False)
        self._update_progress(0.0)
        self.update_idletasks()

        def worker():
            try:
                worker_fn(save_path)
                _log.info("Export saved: %s", save_path)
                self.after(0, lambda: (
                    self._update_progress(1.0),
                    self.set_status(f"{success_prefix}: {os.path.basename(save_path)}"),
                    self._set_controls_enabled(True),
                ))
            except Exception as exc:
                err_msg = _safe_str(type(exc).__name__ + ": " + str(exc), max_len=200)
                _log.error("Export failed: %s", err_msg)
                self.after(0, lambda m=err_msg: (
                    self._update_progress(0.0),
                    self.set_status(f"Export failed: {m}"),
                    self._set_controls_enabled(True),
                ))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    def export_report(self):
        results_snapshot  = dict(self.results_by_path)
        category_snapshot = dict(self.rules_by_category)
        self._run_export(
            ext=".pdf",
            filetypes=[("PDF Report", "*.pdf"), ("All Files", "*.*")],
            dialog_title="Save Compliance Report",
            busy_status="Generating PDF…",
            success_prefix="Report saved",
            worker_fn=lambda p: generate_report_pdf(p, results_snapshot, category_snapshot),
        )

    # ------------------------------------------------------------------
    def export_csv(self):
        results_snapshot = dict(self.results_by_path)
        self._run_export(
            ext=".csv",
            filetypes=[("CSV File", "*.csv"), ("All Files", "*.*")],
            dialog_title="Save CSV Report",
            busy_status="Generating CSV…",
            success_prefix="CSV saved",
            worker_fn=lambda p: generate_report_csv(p, results_snapshot),
        )

    # ------------------------------------------------------------------
    def _show_about(self) -> None:
        """Open a small modal dialog with project and team information."""
        win = ctk.CTkToplevel(self)
        win.title("About")
        win.resizable(False, False)
        win.grab_set()   # modal — blocks interaction with the main window

        # Center over the parent window
        self.update_idletasks()
        px = self.winfo_x() + self.winfo_width()  // 2
        py = self.winfo_y() + self.winfo_height() // 2
        win.geometry(f"420x340+{px - 210}+{py - 170}")

        pad = {"padx": 24, "pady": (0, 6)}

        ctk.CTkLabel(
            win, text="Compliance Scanner",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(pady=(24, 4))

        ctk.CTkLabel(
            win, text="Version 1.0",
            font=ctk.CTkFont(size=13),
        ).pack(**pad)

        ctk.CTkFrame(win, height=1, fg_color=("#cccccc", "#444444")).pack(
            fill="x", padx=24, pady=10
        )

        ctk.CTkLabel(
            win, text="CMMC Level 2 Compliance Scanner",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(**pad)

        ctk.CTkLabel(
            win,
            text=(
                "Scans Windows, Linux, and Debian systems against\n"
                "CMMC Level 2 control requirements and generates\n"
                "detailed PDF and CSV compliance reports."
            ),
            font=ctk.CTkFont(size=11),
            justify="center",
        ).pack(**pad)

        ctk.CTkFrame(win, height=1, fg_color=("#cccccc", "#444444")).pack(
            fill="x", padx=24, pady=10
        )

        ctk.CTkLabel(
            win,
            text="Derek Angelini   |   Connor McBee   |   Melanie Fox",
            font=ctk.CTkFont(size=11),
        ).pack(**pad)

        ctk.CTkLabel(
            win, text="Mercyhurst University",
            font=ctk.CTkFont(size=11),
        ).pack(padx=24, pady=(0, 16))

        ctk.CTkButton(
            win, text="Close", command=win.destroy, width=100,
        ).pack(pady=(4, 20))

        win.bind("<Escape>", lambda _e: win.destroy())

    # ------------------------------------------------------------------
    def _on_closing(self):
        """
        Called when the user clicks the window close button. If a scan is
        currently running, ask for confirmation before exiting so the user
        does not lose in-progress results by accident. Background threads
        are daemonized and will terminate with the process.
        """
        if self.running:
            confirmed = messagebox.askyesno(
                "Scan In Progress",
                "A scan is currently running. Closing now will cancel it and any "
                "results collected so far will be lost.\n\nClose anyway?",
                icon="warning",
            )
            if not confirmed:
                return
            _log.warning("Application closed by user while scan was in progress")
        self.destroy()

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
        export_state = "normal" if (enabled and self.all_rules_run) else "disabled"
        if hasattr(self, "export_btn") and self.export_btn:
            self.export_btn.configure(state=export_state)
        if hasattr(self, "export_csv_btn") and self.export_csv_btn:
            self.export_csv_btn.configure(state=export_state)


def main():
    setup_logging()
    _log.info("Application started. OS: %s", os_scan())
    app = ComplianceDebugApp()
    app.mainloop()
    _log.info("Application exited")


if __name__ == "__main__":
    main()
