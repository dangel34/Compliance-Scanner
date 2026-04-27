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
import concurrent.futures
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
_DEFAULT_SETTINGS: dict[str, object] = {
    "verbose_output": False,
    "result_detail_mode": "full",
    "scan_workers": 2,
}

def _natural_key(path: str) -> list:
    """Sort key that orders filenames numerically, e.g. 2 before 10."""
    fname = os.path.basename(path)
    return [
        int(chunk) if chunk.isdigit() else chunk.lower()
        for chunk in _NATURAL_SORT_RE.split(fname)
    ]


def _load_settings() -> dict[str, object]:
    settings = dict(_DEFAULT_SETTINGS)
    path = os.path.join(_PROJECT_ROOT, "settings.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            for key in settings:
                if key in loaded:
                    settings[key] = loaded[key]
    except (OSError, json.JSONDecodeError):
        pass
    return settings

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
            if not real.startswith(rules_dir_real + os.sep):
                continue
            paths.append(real)

    return sorted(paths, key=_natural_key)


# ---------------------------------------------------------------------------
# Rule metadata filtering
# ---------------------------------------------------------------------------

def _load_rule_meta(path: str) -> dict[str, str]:
    """Return {severity, category} from a rule file, or empty strings on error."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "severity": str(data.get("severity", "")).strip(),
            "category": str(data.get("category", "")).strip().upper(),
        }
    except Exception:
        return {"severity": "", "category": ""}


def _filter_rule_paths(
    paths: list[str],
    severities: list[str] | None,
    categories: list[str] | None,
) -> list[str]:
    """
    Return only the paths whose rule metadata matches the requested filters.
    Both filters are OR-within-filter and AND-between-filters:
      --filter-severity High Critical  →  High OR Critical
      --filter-category AC IA          →  AC OR IA
      both specified                   →  (High OR Critical) AND (AC OR IA)
    """
    if not severities and not categories:
        return paths
    filtered = []
    sev_set  = {s.capitalize() for s in severities} if severities else None
    cat_set  = {c.upper() for c in categories}       if categories else None
    for path in paths:
        meta = _load_rule_meta(path)
        if sev_set and meta["severity"] not in sev_set:
            continue
        if cat_set and meta["category"] not in cat_set:
            continue
        filtered.append(path)
    return filtered


# ---------------------------------------------------------------------------
# Scan runner
# ---------------------------------------------------------------------------

def run_scan(
    rule_paths: list[str],
    verbose: bool = False,
    max_workers: int = 2,
) -> dict[str, RunResult]:
    """Run every rule in *rule_paths* and return a {path: result} dict."""
    results: dict[str, RunResult] = {}
    total = len(rule_paths)
    detected_os = os_scan()

    def _run_one(path: str) -> RunResult:
        try:
            return RuleRunner(rule_path=path, os_type=detected_os).run_checks()
        except Exception as exc:
            label = os.path.basename(path)
            error_msg = _safe_str(f"{type(exc).__name__}: {exc}", max_len=256)
            _log.error("Rule execution error %s: %s", label, error_msg)
            return {
                "rule_id":        label,
                "title":          label,
                "os":             detected_os,
                "checks_run":     0,
                "checks_skipped": 0,
                "checks_policy":  0,
                "checks":         [],
                "error":          error_msg,
            }

    if max_workers <= 1 or total <= 1:
        for i, path in enumerate(rule_paths, start=1):
            label = os.path.basename(path)
            print(f"[{i}/{total}] {label}", file=sys.stderr)
            r = _run_one(path)
            results[path] = r
            if verbose:
                status = get_rule_status(r)
                print(f"  -> {status}", file=sys.stderr)
        return results

    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(_run_one, path): path for path in rule_paths}
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            completed += 1
            label = os.path.basename(path)
            print(f"[{completed}/{total}] {label}", file=sys.stderr)
            r = future.result()
            results[path] = r
            if verbose:
                status = get_rule_status(r)
                print(f"  -> {status}", file=sys.stderr)

    return results


# ---------------------------------------------------------------------------
# Output formatters
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


def _print_text_summary(
    results: dict[str, RunResult],
    detail_mode: str = "status_only",
    elapsed: float | None = None,
) -> None:
    """Print a human-readable summary table to stdout."""
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

    duration_str = f"  Scan time: {_fmt_duration(elapsed)}" if elapsed is not None else ""

    print()
    print("-" * 72)
    print(f"  PASS {counts['PASS']}  FAIL {counts['FAIL']}  PARTIAL {counts['PARTIAL']}  "
          f"POLICY {counts['POLICY']}  SKIP {counts['SKIP']}  ERROR {counts['ERROR']}")
    print(f"  Compliance score: {score_str}  ({counts['PASS']} / {automated} automated checks)")
    if duration_str:
        print(duration_str)
    print("=" * 72)
    print()

    for result in results.values():
        rule_id = _safe_str(result.get("rule_id", ""))
        title = _safe_str(result.get("title", ""))
        print(f"Rule: {rule_id} — {title}")
        print("-" * 72)
        for idx, check in enumerate(result.get("checks", []), start=1):
            status = _safe_str(check.get("status", ""))
            name = _safe_str(check.get("check_name", ""))
            if status == "POLICY":
                print(f"[{idx}] POLICY  {name}")
                continue

            bool_text = "True" if status == "PASS" else "False"
            print(f"[{idx}] {bool_text:<5} ({status})  {name}")

            if detail_mode != "full":
                continue
            command = _safe_str(check.get("command", ""), max_len=4096).strip()
            expected = _safe_str(check.get("expected_result", ""), max_len=4096).strip()
            stdout = _safe_str(check.get("stdout", ""), max_len=20000).strip()
            stderr = _safe_str(check.get("stderr", ""), max_len=20000).strip()
            returncode = check.get("returncode", "")
            if command:
                print(f"    command: {command}")
            if expected:
                print(f"    expected: {expected}")
            print(f"    returncode: {returncode}")
            if stdout:
                print("    stdout:")
                for line in stdout.splitlines():
                    print(f"      {line}")
            if stderr:
                print("    stderr:")
                for line in stderr.splitlines():
                    print(f"      {line}")
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


def _write_html(save_path: str, results: dict[str, RunResult]) -> None:
    from ui.report_html import generate_report_html
    generate_report_html(save_path, results)


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
            "  python cli.py --ruleset \"rulesets/CMMC Level 1 & 2\"\n"
            "  python cli.py --format csv --output report.csv\n"
            "  python cli.py --format pdf --output report.pdf\n"
            "  python cli.py --format json --output report.json\n"
            "  python cli.py --ruleset \"rulesets/CMMC Level 1 & 2\" --format pdf --output out.pdf --verbose\n"
        ),
    )
    parser.add_argument(
        "--ruleset",
        default=os.path.join(_PROJECT_ROOT, "rulesets"),
        metavar="DIR",
        help=(
            "Directory to scan for rule files (default: rulesets/).\n"
            "Can point to a specific sub-folder, e.g. \"rulesets/CMMC Level 1 & 2\"."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv", "pdf", "html"],
        default="text",
        help="Output format (default: text). text prints a summary to stdout.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Path to write the report file. Required for json/csv/pdf/html formats.",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help=(
            "Write one report file per rule into DIR. "
            "Filename is {rule_id}.{format}. "
            "Incompatible with --output and --format text."
        ),
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
        "--detail-mode",
        choices=["status_only", "full"],
        help=(
            "Override text output detail mode. "
            "'status_only' shows bool-style results; "
            "'full' includes full check output."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        metavar="N",
        help="Number of parallel scan workers (default: value from settings.json, usually 2).",
    )
    parser.add_argument(
        "--filter-severity",
        nargs="+",
        metavar="LEVEL",
        help=(
            "Run only rules whose severity matches one of the given values "
            "(Critical, High, Medium, Low). Multiple values are OR-ed together."
        ),
    )
    parser.add_argument(
        "--filter-category",
        nargs="+",
        metavar="CAT",
        help=(
            "Run only rules whose category matches one of the given values "
            "(e.g. AC, AU, CM, IA, SC, SI). Multiple values are OR-ed together."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List the rule files that would be scanned and exit without running any checks.",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0, even when checks fail. Useful in CI to collect results without blocking.",
    )
    return parser


def main() -> None:
    import time
    setup_logging()
    parser = _build_parser()
    args = parser.parse_args()
    settings = _load_settings()

    detail_mode = str(settings.get("result_detail_mode", "status_only")).strip().lower()
    if args.detail_mode:
        detail_mode = args.detail_mode
    if detail_mode not in ("status_only", "full"):
        detail_mode = "status_only"

    # Validate output / output-dir arguments
    if args.output and args.output_dir:
        parser.error("--output and --output-dir are mutually exclusive")
    if args.output_dir and args.format == "text":
        parser.error("--output-dir requires --format json, csv, pdf, or html")
    if args.format != "text" and not args.output and not args.output_dir and not args.dry_run:
        parser.error(f"--output is required when --format is {args.format}")

    # Discover rules
    ruleset_dir = os.path.abspath(args.ruleset)
    rule_paths = _discover_rule_paths(ruleset_dir)

    if not rule_paths:
        print(f"Error: no rule files found in {ruleset_dir}", file=sys.stderr)
        sys.exit(2)

    # Apply severity / category filters
    rule_paths = _filter_rule_paths(
        rule_paths,
        severities=args.filter_severity,
        categories=args.filter_category,
    )

    if not rule_paths:
        print("Error: no rule files matched the specified filters.", file=sys.stderr)
        sys.exit(2)

    # --dry-run: list matching rules and exit without executing any checks
    if args.dry_run:
        print(f"Dry run — {len(rule_paths)} rule(s) would be scanned:\n", file=sys.stderr)
        for path in rule_paths:
            meta = _load_rule_meta(path)
            label = os.path.basename(path)
            sev = meta["severity"] or "?"
            cat = meta["category"] or "?"
            print(f"  [{cat}] [{sev:<8}] {label}")
        sys.exit(0)

    print(f"Found {len(rule_paths)} rule file(s) in {ruleset_dir}", file=sys.stderr)
    print(f"Detected OS: {os_scan()}", file=sys.stderr)
    print(file=sys.stderr)

    # Run scan — --workers flag overrides settings.json value
    scan_workers = settings.get("scan_workers", 2)
    try:
        scan_workers = max(1, int(scan_workers))
    except (TypeError, ValueError):
        scan_workers = 2
    if args.workers is not None:
        scan_workers = max(1, args.workers)

    t0 = time.monotonic()
    results = run_scan(rule_paths, verbose=args.verbose, max_workers=scan_workers)
    elapsed = time.monotonic() - t0

    # Output
    if args.format == "text":
        _print_text_summary(results, detail_mode=detail_mode, elapsed=elapsed)
    elif args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        for path, result in results.items():
            rule_id = _safe_str(result.get("rule_id", os.path.basename(path)))
            safe_id = rule_id.replace("/", "_").replace("\\", "_").replace(":", "_")
            out_file = os.path.join(args.output_dir, f"{safe_id}.{args.format}")
            single = {path: result}
            if args.format == "json":
                _write_json(out_file, single)
            elif args.format == "csv":
                _write_csv(out_file, single)
            elif args.format == "pdf":
                _write_pdf(out_file, single, page_size=args.page_size)
            elif args.format == "html":
                _write_html(out_file, single)
        print(f"Per-rule {args.format.upper()} reports written to {args.output_dir}", file=sys.stderr)
    elif args.format == "json":
        _write_json(args.output, results)
        print(f"JSON report written to {args.output}", file=sys.stderr)
    elif args.format == "csv":
        _write_csv(args.output, results)
        print(f"CSV report written to {args.output}", file=sys.stderr)
    elif args.format == "pdf":
        _write_pdf(args.output, results, page_size=args.page_size)
        print(f"PDF report written to {args.output}", file=sys.stderr)
    elif args.format == "html":
        _write_html(args.output, results)
        print(f"HTML report written to {args.output}", file=sys.stderr)

    if args.no_fail:
        sys.exit(0)
    sys.exit(_exit_code(results))


if __name__ == "__main__":
    main()
