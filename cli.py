#!/usr/bin/env python3
"""
RuleForge CLI — headless compliance scanning for servers and CI pipelines.

Runs the same rule checks as the GUI without requiring a display, then writes
results to stdout (text summary) or a file (JSON, CSV, or PDF).

Usage:
    python cli.py [options]

Exit codes:
    0  All automated checks passed (or only policy/skip results)
    1  One or more checks failed or errored
    2  Bad arguments or no rule files found
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys

# ---------------------------------------------------------------------------
# Path setup — mirror what final_gui.py does so core.* imports resolve.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.scanner_init import os_scan
from core.rule_runner import RuleRunner
from ui.utils import RunResult, _safe_str, get_rule_status, setup_logging

_log = logging.getLogger(__name__)

_NATURAL_SORT_RE = re.compile(r"(\d+)")

def _natural_key(path: str) -> list:
    """Sort key that orders filenames numerically, e.g. 2 before 10."""
    fname = os.path.basename(path)
    return [
        int(chunk) if chunk.isdigit() else chunk.lower()
        for chunk in _NATURAL_SORT_RE.split(fname)
    ]

# ---------------------------------------------------------------------------
# Rule discovery (no GUI dependency — standalone version)
# ---------------------------------------------------------------------------

def _discover_rule_paths(rules_dir: str) -> list[str]:
    """
    Walk *rules_dir* recursively and return a sorted list of absolute paths to
    every valid JSON rule file.  Skips rule_template.json and rule_schema.json.
    Validates each discovered path stays inside rules_dir (path-traversal guard).
    """
    paths: list[str] = []
    if not os.path.isdir(rules_dir):
        return paths

    rules_dir_real = os.path.realpath(rules_dir)

    for root, _, files in os.walk(rules_dir):
        for name in sorted(files):
            if not name.lower().endswith(".json"):
                continue
            if name.lower() in ("rule_template.json", "rule_schema.json"):
                continue
            full = os.path.join(root, name)
            try:
                real = os.path.realpath(full)
            except OSError:
                continue
            # Path-traversal guard
            if not real.startswith(rules_dir_real + os.sep) and real != rules_dir_real:
                continue
            paths.append(real)

    return sorted(paths, key=_natural_key)


# ---------------------------------------------------------------------------
# Scan runner
# ---------------------------------------------------------------------------

def run_scan(
    rule_paths: list[str],
    verbose: bool = False,
) -> dict[str, RunResult]:
    """Run every rule in *rule_paths* and return a {path: result} dict."""
    results: dict[str, RunResult] = {}
    total = len(rule_paths)

    for i, path in enumerate(rule_paths, start=1):
        label = os.path.basename(path)
        print(f"[{i}/{total}] {label}", file=sys.stderr)
        try:
            r = RuleRunner(rule_path=path, os_type=None).run_checks()
        except Exception as exc:
            error_msg = _safe_str(f"{type(exc).__name__}: {exc}", max_len=256)
            _log.error("Rule execution error %s: %s", label, error_msg)
            r = {
                "rule_id":        label,
                "title":          label,
                "os":             os_scan(),
                "checks_run":     0,
                "checks_skipped": 0,
                "checks_policy":  0,
                "checks":         [],
                "error":          error_msg,
            }

        results[path] = r

        if verbose:
            status = get_rule_status(r)
            print(f"  -> {status}", file=sys.stderr)

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _print_text_summary(results: dict[str, RunResult]) -> None:
    """Print a human-readable summary table to stdout."""
    from ui.utils import format_os_name

    counts: dict[str, int] = {"PASS": 0, "FAIL": 0, "PARTIAL": 0,
                               "POLICY": 0, "SKIP": 0, "ERROR": 0, "NOT_RUN": 0}
    rows: list[tuple[str, str, str]] = []

    for result in results.values():
        status = get_rule_status(result)
        counts[status] = counts.get(status, 0) + 1
        rule_id = _safe_str(result.get("rule_id", ""))
        title   = _safe_str(result.get("title",   ""))
        rows.append((rule_id, title, status))

    # Status column
    _STATUS_LABEL = {
        "PASS":    "PASS   ",
        "FAIL":    "FAIL   ",
        "PARTIAL": "PARTIAL",
        "POLICY":  "POLICY ",
        "SKIP":    "SKIP   ",
        "ERROR":   "ERROR  ",
        "NOT_RUN": "NOT_RUN",
    }

    print()
    print("=" * 72)
    print("  RuleForge Compliance Scan Results")
    print("=" * 72)
    for rule_id, title, status in rows:
        label = _STATUS_LABEL.get(status, status.ljust(7))
        print(f"  {label}  {rule_id:<22}  {title}")

    automated = counts["PASS"] + counts["FAIL"] + counts["PARTIAL"]
    score_str = (
        f"{counts['PASS'] / automated * 100:.1f}%"
        if automated > 0 else "N/A"
    )

    print()
    print("-" * 72)
    print(f"  PASS {counts['PASS']}  FAIL {counts['FAIL']}  PARTIAL {counts['PARTIAL']}  "
          f"POLICY {counts['POLICY']}  SKIP {counts['SKIP']}  ERROR {counts['ERROR']}")
    print(f"  Compliance score: {score_str}  ({counts['PASS']} / {automated} automated checks)")
    print("=" * 72)
    print()


def _write_json(save_path: str, results: dict[str, RunResult]) -> None:
    payload = {
        "results": list(results.values()),
        "summary": {
            status: sum(1 for r in results.values() if get_rule_status(r) == status)
            for status in ("PASS", "FAIL", "PARTIAL", "POLICY", "SKIP", "ERROR")
        },
    }
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _write_csv(save_path: str, results: dict[str, RunResult]) -> None:
    from ui.report_csv import generate_report_csv
    generate_report_csv(save_path, results)


def _write_pdf(save_path: str, results: dict[str, RunResult], page_size: str = "A4") -> None:
    from ui.report_pdf import generate_report_pdf
    generate_report_pdf(save_path, results, page_size=page_size)


# ---------------------------------------------------------------------------
# Exit code logic
# ---------------------------------------------------------------------------

def _exit_code(results: dict[str, RunResult]) -> int:
    """Return 0 if all automated checks pass, 1 if any fail or error."""
    for result in results.values():
        s = get_rule_status(result)
        if s in ("FAIL", "PARTIAL", "ERROR"):
            return 1
    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description=(
            "RuleForge headless compliance scanner.\n"
            "Scans the local system against JSON rule files and outputs results."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python cli.py\n"
            "  python cli.py --ruleset rulesets/cmmc-rules\n"
            "  python cli.py --format csv --output report.csv\n"
            "  python cli.py --format pdf --output report.pdf\n"
            "  python cli.py --format json --output report.json\n"
            "  python cli.py --ruleset rulesets/cmmc-rules --format pdf --output out.pdf --verbose\n"
        ),
    )
    parser.add_argument(
        "--ruleset",
        default=os.path.join(_PROJECT_ROOT, "rulesets"),
        metavar="DIR",
        help=(
            "Directory to scan for rule files (default: rulesets/).\n"
            "Can point to a specific sub-folder, e.g. rulesets/cmmc-rules."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv", "pdf"],
        default="text",
        help="Output format (default: text). text prints a summary to stdout.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Path to write the report file. Required for json/csv/pdf formats.",
    )
    parser.add_argument(
        "--page-size",
        choices=["A4", "LETTER"],
        default="A4",
        help="Page size for PDF reports (default: A4).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each rule's status to stderr as the scan runs.",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0, even when checks fail. Useful in CI to collect results without blocking.",
    )
    return parser


def main() -> None:
    setup_logging()
    parser = _build_parser()
    args = parser.parse_args()

    # Validate output argument
    if args.format != "text" and not args.output:
        parser.error(f"--output is required when --format is {args.format}")

    # Discover rules
    ruleset_dir = os.path.abspath(args.ruleset)
    rule_paths = _discover_rule_paths(ruleset_dir)

    if not rule_paths:
        print(f"Error: no rule files found in {ruleset_dir}", file=sys.stderr)
        sys.exit(2)

    print(f"Found {len(rule_paths)} rule file(s) in {ruleset_dir}", file=sys.stderr)
    print(f"Detected OS: {os_scan()}", file=sys.stderr)
    print(file=sys.stderr)

    # Run scan
    results = run_scan(rule_paths, verbose=args.verbose)

    # Output
    if args.format == "text":
        _print_text_summary(results)
    elif args.format == "json":
        _write_json(args.output, results)
        print(f"JSON report written to {args.output}", file=sys.stderr)
    elif args.format == "csv":
        _write_csv(args.output, results)
        print(f"CSV report written to {args.output}", file=sys.stderr)
    elif args.format == "pdf":
        _write_pdf(args.output, results, page_size=args.page_size)
        print(f"PDF report written to {args.output}", file=sys.stderr)

    if args.no_fail:
        sys.exit(0)
    sys.exit(_exit_code(results))


if __name__ == "__main__":
    main()
