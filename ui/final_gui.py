"""
RuleForge — main GUI entry point.

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


_NATURAL_SORT_RE = re.compile(r"(\d+)")


def _natural_key(meta: Dict[str, str]) -> list:
    fname = os.path.basename(meta["path"])
    return [
        int(chunk) if chunk.isdigit() else chunk.lower()
        for chunk in _NATURAL_SORT_RE.split(fname)
    ]


# ---------------------------------------------------------------------------
# Rule discovery
# ---------------------------------------------------------------------------

_RULE_SCHEMA: Optional[Dict[str, Any]] = None
_RULE_SCHEMA_LOADED: bool = False
_RULE_VALIDATOR: Optional[Any] = None
_RULE_VALIDATOR_READY: bool = False
_RULE_VALIDATION_CACHE: Dict[tuple[str, int], List[str]] = {}


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
    global _RULE_VALIDATOR, _RULE_VALIDATOR_READY
    try:
        import jsonschema
    except ImportError:
        return []
    if not _RULE_VALIDATOR_READY:
        _RULE_VALIDATOR_READY = True
        schema = _load_rule_schema()
        if schema is not None:
            try:
                _RULE_VALIDATOR = jsonschema.Draft7Validator(schema)
            except jsonschema.SchemaError as exc:
                _log.warning("rule_schema.json is itself invalid: %s", exc.message)
                _RULE_VALIDATOR = None
    if _RULE_VALIDATOR is None:
        return []
    try:
        errors = sorted(_RULE_VALIDATOR.iter_errors(data), key=lambda e: e.path)
        if not errors:
            return []
        return [e.message for e in errors]
    except jsonschema.ValidationError as exc:
        # Defensive fallback for jsonschema API compatibility.
        return [exc.message]
    except Exception as exc:
        _log.warning("Schema validation failed unexpectedly: %s", exc)
        return []


def discover_rule_files(rules_dir: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Walk rules_dir, read each JSON once, and return:
        { category: [ {path, rule_id, title}, ... ], ... }

    Security: every discovered path is validated to be inside rules_dir
    (prevents path-traversal attacks via symlinks or crafted filenames).
    """
    folders: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
    if not os.path.isdir(rules_dir):
        return folders

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
                rel = os.path.relpath(real_path, rules_dir_real)
            except ValueError:
                rel = name
            rel_parts = rel.split(os.sep)
            folder_label = rel_parts[0] if len(rel_parts) > 1 else "_root_"

            try:
                with open(real_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                mtime_ns = os.stat(real_path).st_mtime_ns
                cache_key = (real_path, mtime_ns)
                cached_errors = _RULE_VALIDATION_CACHE.get(cache_key)
                if cached_errors is None:
                    cached_errors = _validate_rule(data)
                    _RULE_VALIDATION_CACHE[cache_key] = cached_errors
                for err in cached_errors:
                    _log.warning("Schema validation error in %s: %s", real_path, err)
                category = _safe_str(data.get("category") or "Uncategorised") or "Uncategorised"
                rule_id = _safe_str(data.get("id") or data.get("rule_id") or name)
                title = _safe_str(data.get("title") or data.get("control_number") or name)
                severity = _safe_str(data.get("severity", ""))
            except json.JSONDecodeError:
                _log.warning("Skipping malformed JSON: %s", real_path)
                continue
            except OSError as exc:
                _log.warning("Could not read rule file %s: %s", real_path, exc)
                continue

            (
                folders
                .setdefault(folder_label, {})
                .setdefault(category, [])
                .append({
                    "path": real_path, "rule_id": rule_id, "title": title,
                    "severity": severity, "category": category, "folder": folder_label,
                })
            )

    return {
        folder: {
            cat: sorted(metas, key=_natural_key)
            for cat, metas in sorted(cats.items(), key=lambda kv: _cat_sort_key(kv[0]))
        }
        for folder, cats in sorted(folders.items(), key=lambda kv: kv[0].lower())
    }


# ---------------------------------------------------------------------------
# Blocking rule runner (called from background thread)
# ---------------------------------------------------------------------------

def run_rules_blocking(
    rule_paths: List[str],
    progress_cb:  Optional[callable] = None,
    result_cb:    Optional[callable] = None,
    cancel_event: Optional[threading.Event] = None,
) -> Dict[str, RunResult]:
    results: Dict[str, RunResult] = {}
    total = len(rule_paths)
    for i, path in enumerate(rule_paths, start=1):
        if cancel_event and cancel_event.is_set():
            break
        if progress_cb:
            progress_cb(i, total, path)
        try:
            r = RuleRunner(rule_path=path, os_type=None).run_checks()
        except Exception as e:
            error_msg = _safe_str(type(e).__name__ + ": " + str(e), max_len=256)
            _log.error("Rule execution error: %s: %s", os.path.basename(path), error_msg)
            r = {
                "rule_id":        os.path.basename(path),
                "title":          os.path.basename(path),
                "os":             os_scan(),
                "checks_run":     0,
                "checks_skipped": 0,
                "checks_policy":  0,
                "checks":         [],
                "error":          error_msg,
            }
        results[path] = r
        if result_cb:
            result_cb(path, r)
    return results


# ---------------------------------------------------------------------------
# Accordion widget
# ---------------------------------------------------------------------------
class FolderSection:
    """
    A collapsible top-level group in the left sidebar that holds one or more
    AccordionSection widgets.  The header shows the folder name; clicking it
    collapses/expands all the category sections inside.
    """

    def __init__(
        self,
        parent: ctk.CTkScrollableFrame,
        folder_label: str,
    ):
        self.folder_label      = folder_label
        self.expanded: bool    = True
        self.accordion_sections: Dict[str, "AccordionSection"] = {}

        display_name = folder_label if folder_label != "_root_" else "General"

        self.wrapper = ctk.CTkFrame(parent, fg_color="transparent")
        self.wrapper.pack(fill="x", pady=(8, 0), padx=2)

        self.header_btn = ctk.CTkButton(
            self.wrapper,
            text=self._header_text(display_name),
            anchor="w",
            fg_color=("#1e3a5f", "#152844"),
            hover_color=("#2a4f7a", "#1e3a5f"),
            text_color=("white", "white"),
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.toggle,
        )
        self.header_btn.pack(fill="x")

        self.body_frame = ctk.CTkFrame(self.wrapper, fg_color="transparent")
        self.body_frame.pack(fill="x", padx=(10, 0))

        self._display_name = display_name

    def _header_text(self, name: Optional[str] = None) -> str:
        arrow = "▼" if self.expanded else "▶"
        label = name or self._display_name
        return f"  {arrow}  📁  {label}"

    def toggle(self):
        self.expanded = not self.expanded
        self.header_btn.configure(text=self._header_text())
        if self.expanded:
            self.body_frame.pack(fill="x", padx=(10, 0))
        else:
            self.body_frame.pack_forget()

    def apply_filter(self, visible_paths: set) -> bool:
        """
        Propagate filter to every child AccordionSection.
        Re-packs visible sections in original order; hides empty ones.
        Returns True if at least one rule button is visible.
        """
        any_visible = False
        for section in self.accordion_sections.values():
            section.wrapper.pack_forget()
        for section in self.accordion_sections.values():
            has_visible = section.apply_filter(visible_paths)
            if has_visible:
                section.wrapper.pack(fill="x", pady=(4, 0), padx=2)
                any_visible = True
        return any_visible


class AccordionSection:
    _COLOR_MAP = {
        "PASS":    ("#1f6f43", "#1f6f43"),
        "PARTIAL": ("#d1a800", "#d1a800"),
        "FAIL":    ("#8b1e1e", "#8b1e1e"),
        "ERROR":   ("#8b1e1e", "#8b1e1e"),
        "POLICY":  ("#4a2a7a", "#4a2a7a"),
    }
    _ICON_MAP = {"PASS": "  ✓", "PARTIAL": "  !", "FAIL": "  ✗", "ERROR": "  ✗", "POLICY": "  ⊙"}

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
# Settings defaults
# ---------------------------------------------------------------------------

_SETTINGS_DEFAULTS: Dict[str, Any] = {
    "theme":                   "dark",
    "default_export_dir":      "",
    "auto_expand_categories":  False,
    "pdf_page_size":           "A4",
}


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class ComplianceDebugApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("RuleForge")
        self.geometry("1200x820")
        self.minsize(1000, 720)

        self._settings: Dict[str, Any] = self._load_settings()
        ctk.set_appearance_mode(self._settings["theme"])
        ctk.set_default_color_theme("blue")

        self.rules_by_category:  Dict[str, List[Dict[str, str]]] = {}
        self.rules:              List[Dict[str, str]]             = []
        self.results_by_path:    Dict[str, RunResult]             = {}
        self.selected_rule_path: Optional[str]                    = None
        self.accordion_sections: Dict[str, AccordionSection]      = {}
        self._path_to_section:   Dict[str, AccordionSection]      = {}
        self.folder_sections:      Dict[str, FolderSection]      = {}
        self._results_frame:       Optional[ctk.CTkFrame]        = None
        self._settings_frame:      Optional[ctk.CTkFrame]        = None
        self._results_tab_btn:     Optional[ctk.CTkButton]       = None
        self._settings_tab_btn:    Optional[ctk.CTkButton]       = None

        self.theme:         str  = self._settings["theme"]
        self.running:       bool = False
        self.all_rules_run: bool = False

        self._filter_category: str = "All"
        self._filter_severity: str = "All"
        self._filter_category_menu: Optional[ctk.CTkOptionMenu] = None
        self._filter_severity_menu: Optional[ctk.CTkOptionMenu] = None

        self.refresh_btn:    Optional[ctk.CTkButton] = None
        self.run_all_btn:    Optional[ctk.CTkButton] = None
        self.stop_btn:       Optional[ctk.CTkButton] = None
        self.export_btn:     Optional[ctk.CTkButton] = None
        self.export_csv_btn: Optional[ctk.CTkButton] = None

        self._cancel_event = threading.Event()
        self._custom_rules_dirs: List[str] = []

        # Summary dashboard widgets — populated in _build_summary_panel()
        self._stat_count_labels: Dict[str, ctk.CTkLabel] = {}
        self._score_bar:         Optional[ctk.CTkProgressBar] = None
        self._score_label:       Optional[ctk.CTkLabel]       = None
        self._summary_meta:      Optional[ctk.CTkLabel]       = None
        self._summary_counts:    Dict[str, int]               = {}

        self._build_layout()
        self._reset_summary_counts()
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

        ctk.CTkButton(
            top, text="Rule Format", command=self._show_rule_format,
            width=100, fg_color="transparent",
            border_width=1,
            border_color=("#444444", "#888888"),
            text_color=("#1a1a1a", "#e0e0e0"),
            hover_color=("#d0d0d0", "#3a3a3a"),
        ).pack(side="right", padx=(0, 4), pady=8)

        ctk.CTkButton(
            top, text="Load Rules", command=self._load_custom_rules,
            width=100, fg_color="transparent",
            border_width=1,
            border_color=("#444444", "#888888"),
            text_color=("#1a1a1a", "#e0e0e0"),
            hover_color=("#d0d0d0", "#3a3a3a"),
        ).pack(side="right", padx=(0, 4), pady=8)

        # Pack bottom BEFORE main so Tkinter reserves its space first.
        # If main (expand=True) is packed first it consumes all remaining height.
        bottom = ctk.CTkFrame(self)
        bottom.pack(side="bottom", fill="x", padx=10, pady=(6, 10))

        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=10, pady=6)

        left = ctk.CTkFrame(main, width=320)
        left.pack(side="left", fill="y", padx=(10, 6), pady=10)

        right = ctk.CTkFrame(main)
        right.pack(side="right", fill="both", expand=True, padx=(6, 10), pady=10)

        # Manual tab bar — two styled buttons that show/hide content frames
        _tab_bar = ctk.CTkFrame(right, fg_color=("#d8dde2", "#2b2b2b"), height=40)
        _tab_bar.pack(fill="x", padx=0, pady=(0, 0))
        _tab_bar.pack_propagate(False)

        self._results_tab_btn = ctk.CTkButton(
            _tab_bar, text="Results", command=self._show_results_tab,
            width=110, height=30, corner_radius=6,
            fg_color=("#3b8ed0", "#1f6aa5"), text_color="white",
            hover_color=("#3b8ed0", "#1f6aa5"),
        )
        self._results_tab_btn.pack(side="left", padx=(8, 4), pady=5)

        self._settings_tab_btn = ctk.CTkButton(
            _tab_bar, text="Settings", command=self._show_settings_tab,
            width=110, height=30, corner_radius=6,
            fg_color="transparent", text_color=("#444444", "#cccccc"),
            hover_color=("#c0c8d0", "#3a3a3a"),
        )
        self._settings_tab_btn.pack(side="left", padx=(0, 4), pady=5)

        # Two content frames — only one is packed at a time
        self._results_frame = ctk.CTkFrame(right, fg_color="transparent")
        self._results_frame.pack(fill="both", expand=True)

        self._settings_frame = ctk.CTkFrame(right, fg_color="transparent")
        # _settings_frame is NOT packed here; _show_settings_tab packs it

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

        self._build_summary_panel(self._results_frame)

        details_frame = ctk.CTkFrame(self._results_frame, fg_color="transparent")
        details_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        _text_bg = "#1e1e1e" if self.theme == "dark" else "#f5f5f5"
        _text_fg = "#e8e8e8" if self.theme == "dark" else "#1a1a1a"
        self.details_text = tk.Text(
            details_frame,
            wrap="word",
            bg=_text_bg,
            fg=_text_fg,
            insertbackground=_text_fg,
            selectbackground="#264f78",
            relief="flat",
            bd=0,
            padx=10,
            pady=8,
            font=("Consolas", 10),
            cursor="arrow",
            state="disabled",
        )
        _configure_tags(self.details_text, mode=self.theme)

        details_scroll = ctk.CTkScrollbar(details_frame, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scroll.set)
        details_scroll.pack(side="right", fill="y")
        self.details_text.pack(side="left", fill="both", expand=True)

        render_placeholder(self.details_text, "Run rules to view results.")

        # Row 1: run buttons (bottom frame already created and packed above main) (left) — status label (centre, expands) — export buttons (right)
        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(8, 4))

        self.run_all_btn = ctk.CTkButton(btn_row, text="Run All Rules (Ctrl+R)", command=self.run_all_rules, width=175)
        self.run_all_btn.pack(side="left", padx=(0, 6))

        self.run_selected_btn = ctk.CTkButton(
            btn_row, text="Run Selected Rule", command=self.run_selected_rule, state="disabled", width=140
        )
        self.run_selected_btn.pack(side="left", padx=(0, 6))

        self.stop_btn = ctk.CTkButton(
            btn_row, text="Stop", command=self._stop_scan, width=80,
            fg_color="#8B0000", hover_color="#6B0000",
        )
        # Stop button is only shown while a scan is running

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

        self._build_settings_panel(self._settings_frame)

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
            ("policy",  "Policy",  ("#2d1a4a", "#e8d5ff"), ("#a78bfa", "#5b21b6")),
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

    # ------------------------------------------------------------------
    def _load_settings(self) -> Dict[str, Any]:
        path = os.path.join(PROJECT_ROOT, "settings.json")
        result = dict(_SETTINGS_DEFAULTS)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.items():
                if k in result:
                    result[k] = v
        except (OSError, json.JSONDecodeError):
            pass
        return result

    def _save_settings(self) -> None:
        path = os.path.join(PROJECT_ROOT, "settings.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._settings, f, indent=2)
        except OSError as exc:
            _log.warning("Could not save settings: %s", exc)

    # ------------------------------------------------------------------
    def _build_settings_panel(self, parent: ctk.CTkFrame) -> None:
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=4, pady=(4, 0))

        def section_header(text: str) -> None:
            ctk.CTkLabel(
                scroll, text=text,
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w",
            ).pack(anchor="w", padx=8, pady=(18, 2))
            ctk.CTkFrame(scroll, height=1, fg_color=("#cccccc", "#444444")).pack(
                fill="x", padx=8, pady=(0, 8)
            )

        def setting_row(label_text: str) -> ctk.CTkFrame:
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=6)
            ctk.CTkLabel(row, text=label_text, anchor="w", width=220,
                         font=ctk.CTkFont(size=12)).pack(side="left")
            return row

        # ── Appearance ────────────────────────────────────────────────
        section_header("Appearance")

        row = setting_row("Theme")
        self._settings_theme_menu = ctk.CTkOptionMenu(
            row, values=["Dark", "Light"], width=120,
        )
        self._settings_theme_menu.set("Dark" if self.theme == "dark" else "Light")
        self._settings_theme_menu.pack(side="left")

        # ── Export ────────────────────────────────────────────────────
        section_header("Export")

        row = setting_row("Default export folder")
        self._settings_export_entry = ctk.CTkEntry(
            row, width=220, placeholder_text="(same as last save location)",
        )
        if self._settings.get("default_export_dir"):
            self._settings_export_entry.insert(0, self._settings["default_export_dir"])
        self._settings_export_entry.pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            row, text="Browse", width=75,
            command=self._browse_export_dir,
        ).pack(side="left")

        # ── Display ───────────────────────────────────────────────────
        section_header("Display")

        row = setting_row("Auto-expand categories on load")
        self._settings_auto_expand = ctk.CTkSwitch(row, text="", width=46)
        if self._settings.get("auto_expand_categories"):
            self._settings_auto_expand.select()
        self._settings_auto_expand.pack(side="left")

        # ── Reports ───────────────────────────────────────────────────
        section_header("Reports")

        row = setting_row("PDF page size")
        self._settings_pdf_size = ctk.CTkSegmentedButton(
            row, values=["A4", "Letter"], width=160,
        )
        self._settings_pdf_size.set(self._settings.get("pdf_page_size", "A4"))
        self._settings_pdf_size.pack(side="left")

        # ── Apply button ──────────────────────────────────────────────
        ctk.CTkButton(
            parent, text="Apply", width=120, height=34,
            command=self._apply_settings,
        ).pack(anchor="e", padx=12, pady=(6, 10))

    def _browse_export_dir(self) -> None:
        from tkinter import filedialog as _fd
        directory = _fd.askdirectory(
            title="Select Default Export Folder",
            initialdir=self._settings.get("default_export_dir") or PROJECT_ROOT,
        )
        if directory:
            self._settings_export_entry.delete(0, "end")
            self._settings_export_entry.insert(0, directory)

    def _apply_settings(self) -> None:
        new_theme  = "dark" if self._settings_theme_menu.get() == "Dark" else "light"
        export_dir = self._settings_export_entry.get().strip()
        auto_exp   = bool(self._settings_auto_expand.get())
        pdf_size   = self._settings_pdf_size.get()

        # Apply theme if it changed
        if new_theme != self.theme:
            self.theme = new_theme
            ctk.set_appearance_mode(new_theme)
            self.details_text.configure(
                bg="#1e1e1e" if new_theme == "dark" else "#f5f5f5",
                fg="#e8e8e8" if new_theme == "dark" else "#1a1a1a",
            )
            _configure_tags(self.details_text, mode=new_theme)

        self._settings["theme"]                  = new_theme
        self._settings["default_export_dir"]     = export_dir
        self._settings["auto_expand_categories"] = auto_exp
        self._settings["pdf_page_size"]          = pdf_size
        self._save_settings()
        self.set_status("Settings saved.")

    # ------------------------------------------------------------------
    def _update_summary_display(
        self,
        total: int          = 0,
        pass_count: int     = 0,
        fail_count: int     = 0,
        partial_count: int  = 0,
        skip_count: int     = 0,
        error_count: int    = 0,
        policy_count: int   = 0,
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
            self._stat_count_labels["policy"].configure(text=str(policy_count))

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

    def _reset_summary_counts(self) -> None:
        self._summary_counts = {
            "total": 0,
            "pass": 0,
            "fail": 0,
            "partial": 0,
            "skip": 0,
            "error": 0,
            "policy": 0,
            "checks_passed": 0,
            "checks_total": 0,
        }

    @staticmethod
    def _result_check_totals(result: RunResult) -> tuple[int, int]:
        checks_passed = 0
        checks_total = 0
        for check in result.get("checks", []):
            if check.get("status") == "POLICY":
                continue
            checks_total += 1
            if check.get("status") == "PASS":
                checks_passed += 1
        return checks_passed, checks_total

    def _apply_result_delta(self, previous: Optional[RunResult], current: RunResult) -> None:
        if previous is not None:
            prev_status = get_rule_status(previous)
            prev_key = prev_status.lower()
            if prev_key in self._summary_counts:
                self._summary_counts[prev_key] = max(0, self._summary_counts[prev_key] - 1)
            prev_passed, prev_total = self._result_check_totals(previous)
            self._summary_counts["checks_passed"] = max(0, self._summary_counts["checks_passed"] - prev_passed)
            self._summary_counts["checks_total"] = max(0, self._summary_counts["checks_total"] - prev_total)
        else:
            self._summary_counts["total"] += 1

        curr_status = get_rule_status(current)
        curr_key = curr_status.lower()
        if curr_key in self._summary_counts:
            self._summary_counts[curr_key] += 1
        curr_passed, curr_total = self._result_check_totals(current)
        self._summary_counts["checks_passed"] += curr_passed
        self._summary_counts["checks_total"] += curr_total

    def set_status(self, text: str):
        self.status_label.configure(text=f"Status: {text}")

    # ------------------------------------------------------------------
    def _show_results_tab(self) -> None:
        if self._settings_frame:
            self._settings_frame.pack_forget()
        if self._results_frame:
            self._results_frame.pack(fill="both", expand=True)
        if self._results_tab_btn:
            self._results_tab_btn.configure(
                fg_color=("#3b8ed0", "#1f6aa5"), text_color="white",
                hover_color=("#3b8ed0", "#1f6aa5"),
            )
        if self._settings_tab_btn:
            self._settings_tab_btn.configure(
                fg_color="transparent", text_color=("#444444", "#cccccc"),
                hover_color=("#c0c8d0", "#3a3a3a"),
            )

    def _show_settings_tab(self) -> None:
        if self._results_frame:
            self._results_frame.pack_forget()
        if self._settings_frame:
            self._settings_frame.pack(fill="both", expand=True)
        if self._settings_tab_btn:
            self._settings_tab_btn.configure(
                fg_color=("#3b8ed0", "#1f6aa5"), text_color="white",
                hover_color=("#3b8ed0", "#1f6aa5"),
            )
        if self._results_tab_btn:
            self._results_tab_btn.configure(
                fg_color="transparent", text_color=("#444444", "#cccccc"),
                hover_color=("#c0c8d0", "#3a3a3a"),
            )

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
        rules_dir = os.path.join(PROJECT_ROOT, "rulesets")
        folders = discover_rule_files(rules_dir)  # folder → category → [metas]

        # Merge any user-loaded custom rule directories
        for custom_dir in self._custom_rules_dirs:
            custom_folders = discover_rule_files(custom_dir)
            for folder_label, categories in custom_folders.items():
                if folder_label == "_root_":
                    key = "Custom Rules"
                else:
                    key = f"Custom: {folder_label}"
                for cat, metas in categories.items():
                    folders.setdefault(key, {}).setdefault(cat, []).extend(metas)

        # Keep a flat category view for exports and the category filter dropdown
        self.rules_by_folder = folders
        self.rules_by_category = {
            cat: metas
            for cats in folders.values()
            for cat, metas in cats.items()
        }
        self.rules = [m for metas in self.rules_by_category.values() for m in metas]

        # Tear down old UI tree
        for fs in self.folder_sections.values():
            fs.wrapper.destroy()
        self.folder_sections.clear()
        self.accordion_sections.clear()
        self._path_to_section.clear()
        self.results_by_path.clear()
        self._reset_summary_counts()
        self._update_progress(0.0)

        # Rebuild folder → category accordion tree
        for folder_label, categories in folders.items():
            fs = FolderSection(parent=self.rules_scroll, folder_label=folder_label)
            self.folder_sections[folder_label] = fs

            for category, metas in categories.items():
                section = AccordionSection(
                    parent=fs.body_frame,
                    category=category,
                    rule_metas=metas,
                    on_rule_select=self.select_rule,
                )
                fs.accordion_sections[category] = section
                self.accordion_sections[category] = section
                for meta in metas:
                    self._path_to_section[meta["path"]] = section
                if self._settings.get("auto_expand_categories"):
                    section.toggle()

        # Rebuild category dropdown
        cat_names = ["All"] + sorted(self.rules_by_category.keys())
        if self._filter_category_menu:
            self._filter_category_menu.configure(values=cat_names)
            self._filter_category_menu.set("All")
        if self._filter_severity_menu:
            self._filter_severity_menu.set("All")
        self._filter_category = "All"
        self._filter_severity = "All"

        total = len(self.rules)
        cat_count = len(self.rules_by_category)
        _log.info("Rules loaded: %d rules across %d categories in %d folders",
                  total, cat_count, len(folders))
        self._update_summary_display(total=total, cat_count=cat_count)
        render_placeholder(self.details_text, "Run rules to view results.")
        self.selected_rule_path = None
        self.all_rules_run = False
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

        # Re-pack folder wrappers in order, hiding any that have no visible rules
        for fs in self.folder_sections.values():
            fs.wrapper.pack_forget()

        for fs in self.folder_sections.values():
            has_visible = fs.apply_filter(visible)
            if has_visible:
                fs.wrapper.pack(fill="x", pady=(8, 0), padx=2)

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
                    "checks_policy":  0,
                    "checks":         [],
                    "error":          error_msg,
                }
            self.after(0, lambda: self._on_selected_rule_done(result))

        threading.Thread(target=worker, daemon=True).start()

    def _recompute_summary(self) -> None:
        """Refresh the dashboard from incrementally maintained counters."""
        self._update_summary_display(
            total         = self._summary_counts["total"],
            pass_count    = self._summary_counts["pass"],
            fail_count    = self._summary_counts["fail"],
            partial_count = self._summary_counts["partial"],
            skip_count    = self._summary_counts["skip"],
            error_count   = self._summary_counts["error"],
            policy_count  = self._summary_counts["policy"],
            cat_count     = len(self.rules_by_category),
            checks_passed = self._summary_counts["checks_passed"],
            checks_total  = self._summary_counts["checks_total"],
        )

    def _on_rule_result(self, path: str, result: RunResult) -> None:
        """Called on the main thread after each individual rule finishes during a full scan."""
        prev = self.results_by_path.get(path)
        self.results_by_path[path] = result
        self._apply_result_delta(prev, result)
        status  = get_rule_status(result)
        section = self._section_for_path(path)
        if section:
            section.set_button_color(path, status, result.get("rule_id", os.path.basename(path)))
            if path == self.selected_rule_path:
                section.highlight_selected(path, self.results_by_path)
        self._recompute_summary()
        if path == self.selected_rule_path:
            render_rule_details(self.details_text, result)

    def _on_selected_rule_done(self, result: RunResult):
        self.running = False
        path = self.selected_rule_path
        if not path:
            return
        prev = self.results_by_path.get(path)
        self.results_by_path[path] = result
        self._apply_result_delta(prev, result)
        status  = get_rule_status(result)
        section = self._section_for_path(path)
        if section:
            section.set_button_color(path, status, result.get("rule_id", os.path.basename(path)))
            section.highlight_selected(path, self.results_by_path)
        self._recompute_summary()
        self._update_progress(1.0)
        render_rule_details(self.details_text, result)
        self.set_status("Done")
        self._set_controls_enabled(True)

    # ------------------------------------------------------------------
    def _stop_scan(self):
        self._cancel_event.set()
        self.set_status("Stopping…")
        self.stop_btn.pack_forget()

    def run_all_rules(self):
        if self.running:
            self.set_status("Already running rules"); return
        self._cancel_event.clear()
        self.running = True
        self.set_status("Running...")
        self._set_controls_enabled(False)
        self.stop_btn.pack(side="left", padx=(0, 6))
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

        def result_cb(path: str, result: RunResult):
            self.after(0, lambda p=path, r=result: self._on_rule_result(p, r))

        def worker():
            results = run_rules_blocking(
                rule_paths,
                progress_cb=progress_cb,
                result_cb=result_cb,
                cancel_event=self._cancel_event,
            )
            elapsed = time.monotonic() - _scan_start[0]
            cancelled = self._cancel_event.is_set()
            self.after(0, lambda r=results, e=elapsed, c=cancelled: self._on_all_rules_done(r, e, c))

        threading.Thread(target=worker, daemon=True).start()

    def _on_all_rules_done(self, results: Dict[str, RunResult], elapsed: float = 0.0, cancelled: bool = False):
        self.running = False
        self.stop_btn.pack_forget()
        self._set_controls_enabled(True)
        # results_by_path and button colours were updated live by _on_rule_result;
        # do a final recompute to ensure the dashboard is fully in sync.
        self._recompute_summary()
        if cancelled:
            _log.info("Scan cancelled after %s.", _fmt_duration(elapsed))
            self._update_progress(0.0)
            self.set_status(f"Stopped  ({_fmt_duration(elapsed)} elapsed)")
        else:
            _log.info("Scan complete in %s.", _fmt_duration(elapsed))
            self._update_progress(1.0)
            self.set_status(f"Done  ({_fmt_duration(elapsed)} total)")
        self.all_rules_run = not cancelled

        result_to_show = (
            results.get(self.selected_rule_path)
            if self.selected_rule_path
            else next(iter(results.values()), None)
        )
        if result_to_show:
            render_rule_details(self.details_text, result_to_show)

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
        if not self.results_by_path:
            self.set_status("Run at least one rule before exporting.")
            return

        default_name = f"compliance_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        initial_dir  = self._settings.get("default_export_dir") or None
        save_path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=filetypes,
            initialfile=default_name,
            initialdir=initial_dir,
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
        page_size         = self._settings.get("pdf_page_size", "A4")
        self._run_export(
            ext=".pdf",
            filetypes=[("PDF Report", "*.pdf"), ("All Files", "*.*")],
            dialog_title="Save Compliance Report",
            busy_status="Generating PDF…",
            success_prefix="Report saved",
            worker_fn=lambda p: generate_report_pdf(p, results_snapshot, category_snapshot, page_size),
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
            win, text="RuleForge",
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
            win, text="Compliance Scanner by RuleForge",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(**pad)

        ctk.CTkLabel(
            win,
            text=(
                "Scans Windows, Linux, and Debian systems against\n"
                "JSON-based compliance rule sets (CMMC, SOC 2, or custom)\n"
                "and generates detailed PDF and CSV compliance reports."
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
    def _load_custom_rules(self) -> None:
        """Let the user pick a folder of custom rule JSON files."""
        directory = filedialog.askdirectory(
            title="Select Custom Rules Folder",
            initialdir=PROJECT_ROOT,
        )
        if not directory:
            return
        if directory not in self._custom_rules_dirs:
            self._custom_rules_dirs.append(directory)
            self.set_status(f"Custom rules loaded from: {os.path.basename(directory)}")
        self.refresh_rules()

    # ------------------------------------------------------------------
    def _show_rule_format(self) -> None:
        """Open a modal showing the framework-agnostic rule authoring guide."""
        win = ctk.CTkToplevel(self)
        win.title("Rule Format Guide")
        win.grab_set()

        self.update_idletasks()
        px = self.winfo_x() + self.winfo_width()  // 2
        py = self.winfo_y() + self.winfo_height() // 2
        win.geometry(f"780x620+{px - 390}+{py - 310}")
        win.minsize(600, 480)

        ctk.CTkLabel(
            win, text="Rule Authoring Guide",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(pady=(16, 4))

        ctk.CTkLabel(
            win,
            text="Place .json rule files in any folder, then use \"Load Rules\" to add them.",
            font=ctk.CTkFont(size=11),
        ).pack(pady=(0, 8))

        _bg = "#1e1e1e" if self.theme == "dark" else "#f5f5f5"
        _fg = "#e8e8e8" if self.theme == "dark" else "#1a1a1a"

        frame = ctk.CTkFrame(win, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        txt = tk.Text(
            frame, wrap="word", bg=_bg, fg=_fg,
            font=("Consolas", 10), relief="flat", bd=0,
            padx=10, pady=8, cursor="arrow", state="normal",
        )
        sb = ctk.CTkScrollbar(frame, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)

        _GUIDE = """\
RULE FILE STRUCTURE
───────────────────
Each rule is a single .json file.  Sub-folders are used as group labels
in the rule tree (e.g., MyFramework/AC/MY-001.json appears under "MyFramework → AC").

{
  "id":             "MY-001",            // Unique rule identifier
  "control_number": "MY-001",            // Control number (may equal id)
  "title":          "My Control Title",  // Short human-readable title
  "description":    "Full description of what this control requires.",
  "category":       "AC",               // See VALID CATEGORIES below
  "target_os":      ["windows_client", "linux"],  // See VALID OS TARGETS
  "severity":       "High",             // Critical | High | Medium | Low
  "remediation":    "Steps to fix non-compliance.",
  "tags":           ["AC", "MY-001"],   // Free-form searchable tags

  "check_details": {
    "windows_client": {
      "checks": [
        {
          "check_type":      "command",
          "name":            "Verify Audit Policy",
          "sub_control":     "a",
          "command":         "auditpol /get /category:* | Select-String 'Logon'",
          "expected_result": "Logon shows Success and Failure auditing enabled",
          "purpose":         "Confirms logon events are captured in the audit log"
        },
        {
          "check_type":      "service",
          "name":            "Windows Event Log Running",
          "sub_control":     "b",
          "command":         "EventLog",
          "expected_result": "Service is running",
          "purpose":         "Event log service must be active for auditing"
        }
      ]
    },
    "linux": {
      "checks": [
        {
          "check_type":      "command",
          "name":            "Auditd Enabled",
          "sub_control":     "a",
          "command":         "systemctl is-active auditd",
          "expected_result": "active",
          "purpose":         "auditd must be running to capture audit events"
        }
      ]
    }
  }
}

───────────────────────────────────────────────────────
CHECK TYPES
───────────────────────────────────────────────────────

  command           Run a shell command.
                    • Windows: executed via PowerShell
                    • Linux/Debian: executed via bash
                    PASS when exit code = 0.

  service           Check whether a named service is running.
                    "command" field = the service name.
                    • Windows: queries Get-Service
                    • Debian:  queries systemctl

  file_permissions  Check ACL / permissions on a file or directory.
                    "command" field = the file/directory path.
                    • Windows: uses Get-Acl
                    • Linux:   uses stat

  policy            Manual review required.
                    The check is recorded but never executed automatically.
                    Use this for controls that cannot be automated (e.g.,
                    "verify that a written policy document exists").

  NA                Skip this check entirely (placeholder for future work).

───────────────────────────────────────────────────────
CUSTOM PYTHON FUNCTIONS  (cs_f)
───────────────────────────────────────────────────────
Set check_type to "command" and use the special prefix:

  "command": "cs_f(module_name.function_name)"

The engine will import  core/custom_functions/<module_name>.py
and call  function_name().

  • Function takes no arguments.
  • Return (bool, str) — (passed, output_message) — or just bool.
  • Runs with a 60-second timeout.
  • Errors are caught and recorded as FAIL.

Example:
  "command": "cs_f(my_checks.verify_password_policy)"
  → calls core/custom_functions/my_checks.verify_password_policy()

───────────────────────────────────────────────────────
VALID CATEGORIES
───────────────────────────────────────────────────────

  AC   Access Control              AU   Audit & Accountability
  CA   Security Assessment         CM   Configuration Management
  IA   Identification & Auth       IR   Incident Response
  MA   Maintenance                 MP   Media Protection
  NC   Network Connectivity        SC   System & Comms Protection
  SI   System & Info Integrity

Any other string is accepted — it will appear as its own category group.

───────────────────────────────────────────────────────
VALID OS TARGETS  (target_os array)
───────────────────────────────────────────────────────

  windows_client    windows_server    linux    debian    mac

Checks under check_details keys that don't match the detected OS are ignored.
You can omit OS entries that don't apply to your environment.

───────────────────────────────────────────────────────
MINIMAL EXAMPLE
───────────────────────────────────────────────────────

{
  "id": "CUSTOM-001",
  "control_number": "CUSTOM-001",
  "title": "Ensure NTP is Configured",
  "description": "The system clock must be synchronized with an NTP server.",
  "category": "CM",
  "target_os": ["linux", "debian"],
  "severity": "Medium",
  "remediation": "Install and configure chrony or ntpd, then enable the service.",
  "tags": ["CM", "NTP", "CUSTOM-001"],
  "check_details": {
    "linux": {
      "checks": [
        {
          "check_type": "service",
          "name": "Chrony or NTP Service Running",
          "sub_control": "a",
          "command": "chronyd",
          "expected_result": "Service is active",
          "purpose": "Time synchronization must be active"
        }
      ]
    },
    "debian": {
      "checks": [
        {
          "check_type": "service",
          "name": "Chrony or NTP Service Running",
          "sub_control": "a",
          "command": "chronyd",
          "expected_result": "Service is active",
          "purpose": "Time synchronization must be active"
        }
      ]
    }
  }
}
"""

        txt.insert("1.0", _GUIDE)
        txt.configure(state="disabled")

        ctk.CTkButton(
            win, text="Close", command=win.destroy, width=100,
        ).pack(pady=(4, 16))

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
        if enabled:
            self.run_selected_btn.configure(
                state="normal" if self.selected_rule_path else "disabled")
        else:
            self.run_selected_btn.configure(state="disabled")
        export_state = "normal" if (enabled and bool(self.results_by_path)) else "disabled"
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
