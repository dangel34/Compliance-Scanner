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

from ui.utils import PROJECT_ROOT, RunResult, _safe_str, format_os_name, get_rule_status
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
        print(f"[WARN] Could not load rule_schema.json: {exc}", file=sys.stderr)
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
        print(f"[WARN] rule_schema.json is itself invalid: {exc.message}", file=sys.stderr)
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
                    print(f"[WARN] Schema validation error in {real_path}: {err}", file=sys.stderr)
                category = _safe_str(data.get("category") or "Uncategorised") or "Uncategorised"
                rule_id  = _safe_str(data.get("id") or data.get("rule_id") or name)
                title    = _safe_str(data.get("title") or data.get("control_number") or name)
            except json.JSONDecodeError:
                print(f"[WARN] Skipping malformed JSON: {real_path}", file=sys.stderr)
                continue
            except OSError as exc:
                print(f"[WARN] Could not read rule file {real_path}: {exc}", file=sys.stderr)
                continue

            categories.setdefault(category, []).append(
                {"path": real_path, "rule_id": rule_id, "title": title}
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
        color    = self._COLOR_MAP.get(status)
        fg_color = color if color is not None else "transparent"
        text_col = ("white", "white") if color is not None else ("#1a1a1a", "#e0e0e0")
        btn.configure(text=f"{rule_id}{icon}", fg_color=fg_color, text_color=text_col)

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

        self.refresh_btn:    Optional[ctk.CTkButton] = None
        self.run_all_btn:    Optional[ctk.CTkButton] = None
        self.export_btn:     Optional[ctk.CTkButton] = None
        self.export_csv_btn: Optional[ctk.CTkButton] = None

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

        # Row 1: run buttons (left) — status label (centre, expands) — export buttons (right)
        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(8, 4))

        self.run_all_btn = ctk.CTkButton(btn_row, text="Run All Rules", command=self.run_all_rules, width=140)
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
        return [m["path"] for m in self.rules]

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
        pass_count = fail_count = skip_count = 0

        # Single pass: update button colours and tally counts together
        for path, result in results.items():
            status  = get_rule_status(result)
            section = self._section_for_path(path)
            if section:
                section.set_button_color(path, status, result.get("rule_id", os.path.basename(path)))
            if status == "PASS":
                pass_count += 1
            elif status in ("FAIL", "PARTIAL", "ERROR"):
                fail_count += 1
            else:
                skip_count += 1

        if self.selected_rule_path:
            for section in self.accordion_sections.values():
                section.highlight_selected(self.selected_rule_path, results)

        self.summary_label.configure(text=(
            "Summary\n"
            f"- Categories  : {len(self.rules_by_category)}\n"
            f"- Total rules : {len(results)}\n"
            f"- PASS        : {pass_count}\n"
            f"- FAIL/PARTIAL: {fail_count}\n"
            f"- SKIP        : {skip_count}"
        ))
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
                self.after(0, lambda: (
                    self._update_progress(1.0),
                    self.set_status(f"{success_prefix}: {os.path.basename(save_path)}"),
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
    app = ComplianceDebugApp()
    app.mainloop()


if __name__ == "__main__":
    main()
