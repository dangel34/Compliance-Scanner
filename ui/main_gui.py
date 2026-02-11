# DID NOT PUT THREADING IN THIS, WE SHOULD DISCUSS IF WE NEED IT
# REFRESH HAS SOME ISSUES I THINK

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class RuleMeta:
    path: str
    rule_id: str
    title: str


RunResult = Dict[str, Any]


@dataclass
class GUI:
    """
    Stores widgets and UI state for the main compliance scanner window.

    :param app: Root CustomTkinter application instance.
    """
    app: ctk.CTk
    os_label: ctk.CTkLabel
    status_label: ctk.CTkLabel
    summary_label: ctk.CTkLabel
    details_text: ctk.CTkTextbox
    rules_scroll: ctk.CTkScrollableFrame

    rules: List[RuleMeta] = field(default_factory=list)
    results_by_path: Dict[str, RunResult] = field(default_factory=dict)
    selected_rule_path: Optional[str] = None
    rule_buttons: Dict[str, ctk.CTkButton] = field(default_factory=dict)


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


def load_rule_metadata(rule_path: str) -> RuleMeta:
    """
    Read a rule JSON and extract minimal metadata for the UI.

    :param rule_path: Absolute path to a rule JSON file.
    :return: Parsed rule metadata including id and title.
    """
    filename = os.path.basename(rule_path)
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rule_id = str(data.get("id") or filename)
        title = str(data.get("title") or filename)
        return RuleMeta(path=rule_path, rule_id=rule_id, title=title)
    except Exception:
        return RuleMeta(path=rule_path, rule_id=filename, title=filename)


def format_rule_details(result: RunResult) -> str:
    """
    Format a RuleRunner result dict as readable text for the details pane.

    :param result: Rule execution result dictionary.
    :return: Multi-line human-readable string describing checks and status.
    """
    lines: List[str] = [
        f"Rule ID: {result.get('rule_id', '')}",
        f"Title: {result.get('title', '')}",
        f"OS: {result.get('os', '')}",
        f"Checks Run: {result.get('checks_run', 0)}",
        "",
    ]

    overall_status = get_rule_status(result)
    lines.insert(0, f"Overall Status: {overall_status}")
    lines.insert(1, "=" * 50)

    for check in result.get("checks", []):
        lines.append(f"Check: {check.get('check_name', '')}")
        lines.append(f"Status: {check.get('status', '')}")
        lines.append("-" * 50)

    return "\n".join(lines)


def build_app() -> GUI:
    """
    Create the main window and all widgets.

    This keeps widget creation in one place so the rest of the code can focus
    on behavior (refresh rules, run rules, display results).

    :return: Constructed GUI dataclass with initialized widgets and CTk app.
    """
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    app = ctk.CTk()
    app.title("Compliance Scanner")
    app.geometry("1000x750")
    app.minsize(900, 650)

    # Top
    top = ctk.CTkFrame(app)
    top.pack(fill="x", padx=10, pady=(10, 6))

    os_label = ctk.CTkLabel(top, text=f"Detected OS: {os_scan()}")
    os_label.pack(side="left", padx=10, pady=8)

    refresh_btn = ctk.CTkButton(top, text="Refresh rules")
    refresh_btn.pack(side="right", padx=10, pady=8)

    # Main layout
    main = ctk.CTkFrame(app)
    main.pack(fill="both", expand=True, padx=10, pady=6)

    left = ctk.CTkFrame(main, width=320)
    left.pack(side="left", fill="y", padx=(10, 6), pady=10)

    right = ctk.CTkFrame(main)
    right.pack(side="right", fill="both", expand=True, padx=(6, 10), pady=10)

    ctk.CTkLabel(left, text="Rules", font=ctk.CTkFont(size=14, weight="bold")).pack(
        anchor="w", padx=10, pady=(10, 6)
    )

    rules_scroll = ctk.CTkScrollableFrame(left)
    rules_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    summary_label = ctk.CTkLabel(
        right,
        text="Summary: (not run yet)",
        font=ctk.CTkFont(size=14, weight="bold"),
        justify="left",
    )
    summary_label.pack(anchor="w", padx=10, pady=(10, 6))

    details_text = ctk.CTkTextbox(right, wrap="word")
    details_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    details_text.insert("1.0", "Select a rule to view results.\n")
    details_text.configure(state="disabled")

    bottom = ctk.CTkFrame(app)
    bottom.pack(fill="x", padx=10, pady=(6, 10))

    run_all_btn = ctk.CTkButton(bottom, text="Run all rules")
    run_all_btn.pack(side="left", padx=10, pady=8)

    status_label = ctk.CTkLabel(bottom, text="Status: Idle")
    status_label.pack(side="right", padx=10, pady=8)

    gui = GUI(
        app=app,
        os_label=os_label,
        status_label=status_label,
        summary_label=summary_label,
        details_text=details_text,
        rules_scroll=rules_scroll,
    )

    refresh_btn.configure(command=lambda: refresh_rules(gui))
    run_all_btn.configure(command=lambda: run_all_rules(gui))

    return gui


def set_status(gui: GUI, text: str) -> None:
    """
    Update the bottom status label.

    :param gui: GUI state object containing the status label widget.
    :param text: Status message (without leading 'Status: ' prefix).
    :return: None
    """
    gui.status_label.configure(text=f"Status: {text}")


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


def refresh_rules(gui: GUI) -> None:
    """
    Re-scan the rulesets folder and rebuild the rule list UI.

    :param gui: GUI state object whose rule list and buttons will be refreshed.
    :return: None
    """
    rules_dir = os.path.join(PROJECT_ROOT, "rulesets")
    rule_paths = discover_rule_files(rules_dir)
    gui.rules = [load_rule_metadata(p) for p in rule_paths]

    for child in gui.rules_scroll.winfo_children():
        child.destroy()
    gui.rule_buttons.clear()

    for meta in gui.rules:
        btn = ctk.CTkButton(
            gui.rules_scroll,
            text=meta.title,
            anchor="w",
            command=lambda p=meta.path: on_select_rule(gui, p),
        )
        btn.pack(fill="x", pady=4)
        gui.rule_buttons[meta.path] = btn

    gui.selected_rule_path = None
    gui.results_by_path.clear()
    gui.summary_label.configure(text=f"Summary\n- Total rules: {len(gui.rules)}")


def on_select_rule(gui: GUI, rule_path: str) -> None:
    """
    Handle selection of a rule in the left-hand list.

    :param gui: GUI state object containing rule results and widgets.
    :param rule_path: Absolute path of the selected rule JSON file.
    :return: None
    """
    gui.selected_rule_path = rule_path
    render_rule_details(gui, gui.results_by_path.get(rule_path))


def render_rule_details(gui: GUI, result: Optional[RunResult]) -> None:
    """
    Update the right-hand details textbox with the selected rule result.

    :param gui: GUI state object containing the details textbox widget.
    :param result: Rule execution result for the selected rule, or None.
    :return: None
    """
    gui.details_text.configure(state="normal")
    gui.details_text.delete("1.0", "end")

    if result is None:
        gui.details_text.insert("1.0", "No results for this rule yet.\n")
    else:
        gui.details_text.insert("1.0", format_rule_details(result))

    gui.details_text.configure(state="disabled")


def run_all_rules(gui: GUI) -> None:
    """
    Run all discovered rules synchronously and update the UI with results.

    :param gui: GUI state object whose rules will be executed.
    :return: None
    """
    set_status(gui, "Running...")

    results: Dict[str, RunResult] = {}

    for meta in gui.rules:
        try:
            r = RuleRunner(rule_path=meta.path, os_type=None).run_checks()
            results[meta.path] = r
        except Exception as e:
            results[meta.path] = {
                "rule_id": meta.rule_id,
                "title": meta.title,
                "os": os_scan(),
                "checks_run": 0,
                "checks": [],
                "error": str(e),
            }

    gui.results_by_path = results

    for path, result in results.items():
        status = get_rule_status(result)
        meta = next((r for r in gui.rules if r.path == path), None)
        if meta:
            btn = gui.rule_buttons.get(path)
            if btn:
                btn.configure(text=f"{meta.title}  [{status}]")

    set_status(gui, "Done")

    pass_count = 0
    fail_count = 0

    for r in results.values():
        status = get_rule_status(r)
        if status == "PASS":
            pass_count += 1
        else:
            fail_count += 1

    gui.summary_label.configure(
        text=(
            "Summary\n"
            f"- Total rules: {len(results)}\n"
            f"- PASS: {pass_count}\n"
            f"- FAIL: {fail_count}"
        )
    )

    if gui.selected_rule_path:
        render_rule_details(gui, gui.results_by_path.get(gui.selected_rule_path))


def main() -> None:
    """
    Entry point for the main GUI application.

    :return: None
    """
    gui = build_app()
    refresh_rules(gui)
    gui.app.mainloop()


if __name__ == "__main__":
    main()
