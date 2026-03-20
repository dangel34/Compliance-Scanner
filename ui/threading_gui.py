"""
Threading GUI for the Compliance Scanner.

Uses background threads for rule execution so the UI stays responsive.
Similar structure to main_gui.py but with async run behavior.
WILL BE UPDATING BOTH MAIN AND THREADING AS THINGS GO ALONG FOR FALLBACK
"""
from __future__ import annotations

import json
import os
import sys
import threading
from typing import Any, Dict, List, Optional

import customtkinter as ctk

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


def discover_rule_files(rules_dir: str) -> List[str]:
    """
    Find all .json rule files under a directory (recursively).
    Skips rule_template.json.

    :param rules_dir: Base directory to search for rule JSON files.
    :return: Sorted list of absolute paths to rule JSON files.
    """
    out: List[str] = []
    if not os.path.isdir(rules_dir):
        return out
    for root, _, files in os.walk(rules_dir):
        for name in files:
            if name.lower().endswith(".json") and name.lower() != "rule_template.json":
                out.append(os.path.join(root, name))
    return sorted(out)


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

    :param result: Rule execution result dictionary.
    :return: 'PASS', 'FAIL', 'ERROR', 'SKIP', or 'NOT_RUN'.
    """
    if result is None:
        return "NOT_RUN"
    if "error" in result:
        return "ERROR"
    checks = result.get("checks", [])
    if not checks:
        return "SKIP"
    for c in checks:
        if c.get("status") != "PASS":
            return "FAIL"
    return "PASS"


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

        self.rules: List[Dict[str, str]] = []
        self.results_by_path: Dict[str, RunResult] = {}
        self.selected_rule_path: Optional[str] = None
        self.rule_buttons: Dict[str, ctk.CTkButton] = {}
        self.theme: str = "dark"
        self.running: bool = False

        self._build_layout()
        self.refresh_rules()

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

        refresh_btn = ctk.CTkButton(top, text="Refresh Rules", command=self.refresh_rules)
        refresh_btn.pack(side="right", padx=10, pady=8)

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

        run_all_btn = ctk.CTkButton(bottom, text="Run All Rules", command=self.run_all_rules)
        run_all_btn.pack(side="left", padx=(10, 5), pady=8)

        self.run_selected_btn = ctk.CTkButton(
            bottom,
            text="Run Selected Rule",
            command=self.run_selected_rule,
            state="disabled",
        )
        self.run_selected_btn.pack(side="left", padx=(5, 10), pady=8)

        self.progress_bar = ctk.CTkProgressBar(bottom)
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=10, pady=14)
        self.progress_bar.set(0.0)

        self.status_label = ctk.CTkLabel(bottom, text="Status: Idle")
        self.status_label.pack(side="right", padx=10, pady=8)

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
            self.update_idletasks()

    def refresh_rules(self):
        """Re-scan rulesets and rebuild the rule list."""
        rules_dir = os.path.join(PROJECT_ROOT, "rulesets")
        rule_paths = discover_rule_files(rules_dir)
        self.rules = [load_rule_metadata(p) for p in rule_paths]

        for child in self.rules_scroll.winfo_children():
            child.destroy()
        self.rule_buttons.clear()
        self.results_by_path.clear()
        self._update_progress(0.0)

        for meta in self.rules:
            btn = ctk.CTkButton(
                self.rules_scroll,
                text=meta["rule_id"],
                anchor="w",
                command=lambda p=meta["path"]: self.select_rule(p),
            )
            btn.pack(fill="x", pady=4)
            self.rule_buttons[meta["path"]] = btn

        self.summary_label.configure(text=f"Summary\n- Total rules: {len(self.rules)}")
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", "Run rules to view results.\n")
        self.details_text.configure(state="disabled")
        self.selected_rule_path = None
        self.run_selected_btn.configure(state="disabled")
        self.set_status("Idle")

    def select_rule(self, rule_path: str):
        """Select a rule and show its details if available."""
        self.selected_rule_path = rule_path

        for path, btn in self.rule_buttons.items():
            result = self.results_by_path.get(path)
            if result:
                status = get_rule_status(result)
                if status == "PASS":
                    btn.configure(fg_color="#1f6f43")
                else:
                    btn.configure(fg_color="#8b1e1e")
            else:
                btn.configure(fg_color="transparent")

        selected_btn = self.rule_buttons.get(rule_path)
        if selected_btn:
            selected_btn.configure(fg_color="#3b8ed0")

        self.run_selected_btn.configure(state="normal")

        result = self.results_by_path.get(rule_path)
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        if result:
            self.details_text.insert("1.0", format_rule_details(result))
        else:
            self.details_text.insert("1.0", "Select a rule and click 'Run Selected Rule' to view results.\n")
        self.details_text.configure(state="disabled")
        self.set_status(f"Selected: {os.path.basename(rule_path)}")

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
        btn = self.rule_buttons.get(path)
        if btn:
            if status == "PASS":
                btn.configure(text=f"{result['rule_id']}  ✓", fg_color="#1f6f43")
            else:
                btn.configure(text=f"{result['rule_id']}  ✗", fg_color="#8b1e1e")

        self._update_progress(1.0)
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", format_rule_details(result))
        self.details_text.configure(state="disabled")
        self.set_status("Done")

    def run_all_rules(self):
        """Run all rules in a background thread."""
        if self.running:
            self.set_status("Already running rules")
            return

        self.running = True
        self.set_status("Running...")
        self._update_progress(0.0)

        rule_paths = [m["path"] for m in self.rules]

        def progress_cb(i: int, total: int, _path: str):
            self.after(0, lambda: self.set_status(f"Running… ({i}/{total})"))
            self.after(0, lambda: self._update_progress(i / total if total else 0))

        def worker():
            results = run_rules_blocking(rule_paths, progress_cb=progress_cb)
            self.after(0, lambda: self._on_all_rules_done(results))

        threading.Thread(target=worker, daemon=True).start()

    def _on_all_rules_done(self, results: Dict[str, RunResult]):
        """Called on main thread when all rules finish."""
        self.running = False
        self.results_by_path = results

        pass_count = 0
        fail_count = 0
        for path, result in results.items():
            status = get_rule_status(result)
            btn = self.rule_buttons.get(path)
            if btn:
                if status == "PASS":
                    btn.configure(text=f"{result['rule_id']}  ✓", fg_color="#1f6f43")
                    pass_count += 1
                else:
                    btn.configure(text=f"{result['rule_id']}  ✗", fg_color="#8b1e1e")
                    fail_count += 1

        self.summary_label.configure(
            text=(
                "Summary\n"
                f"- Total rules: {len(results)}\n"
                f"- PASS: {pass_count}\n"
                f"- FAIL: {fail_count}"
            )
        )
        self._update_progress(1.0)
        self.set_status("Done")

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


def main():
    """Entry point for the debug GUI."""
    app = ComplianceDebugApp()
    app.mainloop()


if __name__ == "__main__":
    main()
