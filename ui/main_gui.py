from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

import customtkinter as ctk


def get_project_root() -> str:
    """
    Return the project root folder (parent of ui/).

    :return: Absolute path to the project root directory.
    """
    ui_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(ui_dir)


PROJECT_ROOT = get_project_root()
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core import os_scan
from core.rule_runner import RuleRunner

RunResult = Dict[str, Any]


def format_os_name(os_name: str) -> str:
    """
    Format operating system name in the GUI

    :param os_name:
    :return:
    """
    return os_name.replace("_", " ").title()


def discover_rule_files(rules_dir: str) -> List[str]:
    """
    Find all .json rule files under a directory (recursively).

    :param rules_dir: Base directory to search for rule JSON files.
    :return: Sorted list of absolute paths to rule JSON files.
    """
    out: List[str] = []

    if not os.path.isdir(rules_dir):
        return out

    for root, _, files in os.walk(rules_dir):
        for name in files:
            if name.endswith(".json") and name != "rule_template.json":
                out.append(os.path.join(root, name))

    return sorted(out)


def load_rule_metadata(rule_path: str) -> Dict[str, str]:
    """
    Read a rule JSON and extract minimal metadata for the UI.

    :param rule_path: Absolute path to a rule JSON file.
    :return: Parsed rule metadata including id and title.
    """
    filename = os.path.basename(rule_path)

    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return {
            "path": rule_path,
            "rule_id": str(data.get("id") or filename),
            "title": str(data.get("title") or filename),
        }
    except Exception:
        return {
            "path": rule_path,
            "rule_id": filename,
            "title": filename,
        }


def get_rule_status(result: RunResult) -> str:
    """
    Compute the overall pass/fail/error status for a rule result.

    :param result: Rule execution result dictionary.
    :return: 'PASS', 'FAIL', or 'ERROR' if there are no checks.
    """
    checks = result.get("checks", [])

    if not checks:
        return "ERROR"

    for check in checks:
        if check.get("status") != "PASS":
            return "FAIL"

    return "PASS"


def format_rule_details(result: RunResult) -> str:
    """
    Format a RuleRunner result dict as readable text for the details pane.

    :param result: Rule execution result dictionary.
    :return: Multi-line human-readable string describing checks and status.
    """
    overall_status = get_rule_status(result)

    lines: List[str] = [
        "=" * 70,
        f"OVERALL STATUS: {overall_status}",
        "=" * 70,
        "",
        f"Rule ID   : {result.get('rule_id', '')}",
        f"Title     : {result.get('title', '')}",
        f"OS        : {result.get('os', '')}",
        f"Checks Run: {result.get('checks_run', 0)}",
        "",
        "-" * 70,
    ]

    for i, check in enumerate(result.get("checks", []), start=1):

        lines.extend([
            f"Check #{i}",
            "-" * 70,
            f"Name      : {check.get('check_name', '')}",
            f"Status    : {check.get('status', '')}",
            f"Command   : {check.get('command', '')}",
            f"ReturnCode: {check.get('returncode', '')}",
        ])

        stdout = check.get("stdout", "")
        stderr = check.get("stderr", "")

        if stdout:
            lines.extend([
                "",
                "STDOUT:",
                stdout,
            ])

        if stderr:
            lines.extend([
                "",
                "STDERR:",
                stderr,
            ])

        lines.append("\n" + "=" * 70 + "\n")

    return "\n".join(lines)


class ComplianceApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        # Window config
        self.title("Compliance Scanner")
        self.geometry("1000x750")
        self.minsize(900, 650)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # State
        self.rules: List[Dict[str, str]] = []
        self.results_by_path: Dict[str, RunResult] = {}
        self.selected_rule_path: Optional[str] = None
        self.rule_buttons: Dict[str, ctk.CTkButton] = {}
        self.theme: str = "dark"

        # Build UI
        self._build_layout()

        # Initial load
        self.refresh_rules()

    def _build_layout(self):
        """
        Create the main window and all widgets.

        This keeps widget creation in one place so the rest of the code can focus
        on behavior (refresh rules, run rules, display results).

        :return:
        """
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

        refresh_btn = ctk.CTkButton(
            top,
            text="Refresh Rules",
            command=self.refresh_rules,
        )
        refresh_btn.pack(side="right", padx=10, pady=8)

        # ---------- MAIN ----------
        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=10, pady=6)

        left = ctk.CTkFrame(main, width=320)
        left.pack(side="left", fill="y", padx=(10, 6), pady=10)

        right = ctk.CTkFrame(main)
        right.pack(side="right", fill="both", expand=True, padx=(6, 10), pady=10)

        ctk.CTkLabel(
            left,
            text="Rules",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=10, pady=(10, 6))

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

        run_all_btn = ctk.CTkButton(
            bottom,
            text="Run All Rules",
            command=self.run_all_rules,
        )
        run_all_btn.pack(side="left", padx=(10, 5), pady=8)

        self.run_selected_btn = ctk.CTkButton(
            bottom,
            text="Run Selected Rule",
            command=self.run_selected_rule,
            state="disabled",
        )
        self.run_selected_btn.pack(side="left", padx=(5, 10), pady=8)

        self.status_label = ctk.CTkLabel(bottom, text="Status: Idle")
        self.status_label.pack(side="right", padx=10, pady=8)

    def toggle_theme(self):
        """
        Toggle between dark and light appearance modes for the application.

        :return: None
        """
        if self.theme == "dark":
            self.theme = "light"
            ctk.set_appearance_mode("light")
            self.theme_button.configure(text="Switch to Dark Mode")
        else:
            self.theme = "dark"
            ctk.set_appearance_mode("dark")
            self.theme_button.configure(text="Switch to Light Mode")

    # -------------------------------------------------

    def set_status(self, text: str):
        """
        Update the bottom status label.

        :param text: Status message (without leading 'Status: ' prefix).
        :return: None
        """
        self.status_label.configure(text=f"Status: {text}")

    # -------------------------------------------------

    def refresh_rules(self):
        """
        Re-scan the rulesets folder and rebuild the rule list UI.

        :return: None
        """
        rules_dir = os.path.join(PROJECT_ROOT, "rulesets")
        rule_paths = discover_rule_files(rules_dir)

        self.rules = [load_rule_metadata(p) for p in rule_paths]

        for child in self.rules_scroll.winfo_children():
            child.destroy()

        self.rule_buttons.clear()
        self.results_by_path.clear()

        for meta in self.rules:
            btn = ctk.CTkButton(
                self.rules_scroll,
                text=meta["rule_id"],
                anchor="w",
                command=lambda p=meta["path"]: self.select_rule(p),
            )
            btn.pack(fill="x", pady=4)

            self.rule_buttons[meta["path"]] = btn

        self.summary_label.configure(
            text=f"Summary\n- Total rules: {len(self.rules)}"
        )

        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", "Run rules to view results.\n")
        self.details_text.configure(state="disabled")
        self.selected_rule_path = None
        self.run_selected_btn.configure(state="disabled")

        self.set_status("Idle")

    def select_rule(self, rule_path: str):
        """
        Select a rule in the UI and highlight it.

        :param rule_path: Path to the selected rule JSON file.
        """
        self.selected_rule_path = rule_path

        # Reset all button colors
        for path, btn in self.rule_buttons.items():
            # If rule already has results, preserve PASS/FAIL color
            result = self.results_by_path.get(path)
            if result:
                status = get_rule_status(result)
                if status == "PASS":
                    btn.configure(fg_color="#1f6f43")
                else:
                    btn.configure(fg_color="#8b1e1e")
            else:
                btn.configure(fg_color="transparent")

        # Highlight selected
        selected_btn = self.rule_buttons.get(rule_path)
        if selected_btn:
            selected_btn.configure(fg_color="#3b8ed0")

        # Enable run selected button
        self.run_selected_btn.configure(state="normal")

        self.set_status(f"Selected: {os.path.basename(rule_path)}")

    def run_selected_rule(self):
        """
        Run only the currently selected rule.

        :return:
        """
        if not self.selected_rule_path:
            self.set_status("No rule selected")
            return

        self.set_status("Running selected rule...")

        meta = next(
            (m for m in self.rules if m["path"] == self.selected_rule_path),
            None
        )

        if not meta:
            self.set_status("Invalid rule selection")
            return

        try:
            result = RuleRunner(
                rule_path=meta["path"],
                os_type=None
            ).run_checks()

        except Exception as e:
            result = {
                "rule_id": meta["rule_id"],
                "title": meta["title"],
                "os": os_scan(),
                "checks_run": 0,
                "checks": [],
                "error": str(e),
            }

        # Store result
        self.results_by_path[self.selected_rule_path] = result

        status = get_rule_status(result)
        btn = self.rule_buttons.get(self.selected_rule_path)

        if btn:
            if status == "PASS":
                btn.configure(text=f"{result['rule_id']}  ✓", fg_color="#1f6f43")
            else:
                btn.configure(text=f"{result['rule_id']}  ✗", fg_color="#8b1e1e")

        # Show details
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", format_rule_details(result))
        self.details_text.configure(state="disabled")

        self.set_status("Done")

    def run_all_rules(self):
        """
        Run all discovered rules synchronously and update the UI with results.

        :return: None
        """
        self.set_status("Running...")

        results: Dict[str, RunResult] = {}

        for meta in self.rules:
            try:
                r = RuleRunner(rule_path=meta["path"], os_type=None).run_checks()
                results[meta["path"]] = r
            except Exception as e:
                results[meta["path"]] = {
                    "rule_id": meta["rule_id"],
                    "title": meta["title"],
                    "os": os_scan(),
                    "checks_run": 0,
                    "checks": [],
                    "error": str(e),
                }

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

        self.set_status("Done")

        # Display first result automatically
        if results:
            first_result = next(iter(results.values()))
            self.details_text.configure(state="normal")
            self.details_text.delete("1.0", "end")
            self.details_text.insert("1.0", format_rule_details(first_result))
            self.details_text.configure(state="disabled")


def main():
    """
    Entry point for the main GUI application.

    :return: None
    """
    app = ComplianceApp()
    app.mainloop()


if __name__ == "__main__":
    main()
