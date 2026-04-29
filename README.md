# RuleForge

![CI](https://github.com/dangel34/Compliance-Scanner/actions/workflows/ci.yml/badge.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=YOUR_ORG_KEY_Compliance-Scanner&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dangel34_Compliance-Scanner)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=YOUR_ORG_KEY_Compliance-Scanner&metric=coverage)](https://sonarcloud.io/summary/new_code?id=dangel34_Compliance-Scanner)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-orange)

A desktop application that scans Windows, Linux, and Debian systems against CMMC Level 2 control requirements and produces detailed compliance reports. Built as a senior project at Mercyhurst University by Derek Angelini, Connor McBee, and Melanie Fox.

## Overview

The scanner loads a set of JSON rule files, executes the checks defined in each rule against the local system, and displays pass/fail results in a graphical interface. Results can be exported as a PDF, CSV, JSON, or HTML report. The tool detects the operating system at startup and runs only the checks relevant to that platform.

The 94 included rules cover six CMMC Level 2 control families across Windows Client and Windows Server: Access Control (AC), Audit and Accountability (AU), Configuration Management (CM), Identification and Authentication (IA), System and Communications Protection (SC), and System and Information Integrity (SI). SOC 2 rules are also included.

## Installation (Windows — Recommended)

A pre-built Windows installer is available. Download `ComplianceScannerSetup.exe` and run it. The installer places the application in `C:\Program Files\Compliance Scanner\`, creates a Start Menu shortcut, and registers an uninstaller.

The application requests administrator privileges at launch — this is required for accurate compliance scanning on Windows.

> **Note:** The installer is unsigned. Windows SmartScreen may show a warning on first run. Click **More info → Run anyway** to proceed.

## Building from Source

Requires Python 3.10+, [PyInstaller](https://pyinstaller.org), and [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```bat
scripts\build.bat
```

This script installs PyInstaller if needed, runs it against `scripts\compliance_scanner.spec`, then (if Inno Setup is installed) compiles `scripts\installer.iss` to produce `dist\installer\ComplianceScannerSetup.exe`.

## Running Without the Installer

To run directly from source, install dependencies and launch the GUI:

```
pip install -r requirements.txt
python ui/final_gui.py
```

## Requirements

Python 3.10 or later is required. Install dependencies with:

```
pip install -r requirements.txt
```

The three required packages are:

```
customtkinter>=5.2.0
reportlab>=4.0.0
jsonschema>=4.0.0
```

## Running the Application

```
python ui/final_gui.py
```

The application must be run from the project root directory so that it can locate the `rulesets/` and `core/` directories correctly.

On Windows, some checks execute PowerShell commands and require Administrator privileges to return accurate results. On Linux and Debian, certain checks require root privileges for the same reason. All PowerShell and subprocess calls run headlessly — no console windows appear during scanning.

## Headless / CLI Mode

For servers and CI pipelines that have no graphical display, use the CLI entry point instead:

```
python cli.py [options]
```

The CLI runs the same rule checks and produces the same results as the GUI without requiring `tkinter` or a display.

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ruleset DIR` | `rulesets/` | Directory to scan for rule files. Can point to a specific sub-folder. |
| `--format text\|json\|csv\|pdf\|html` | `text` | Output format. `text` prints a summary table to stdout. `html` writes a self-contained single-file report. |
| `--output FILE` | — | File path to write the report. Required for `json`, `csv`, and `pdf`. |
| `--page-size A4\|LETTER` | `A4` | Page size for PDF reports. |
| `--workers N` | from `settings.json` | Number of parallel scan workers. Overrides the `scan_workers` value in `settings.json`. |
| `--verbose` / `-v` | off | Print each rule's pass/fail status to stderr as the scan progresses. |
| `--detail-mode status_only\|full` | from `settings.json` | Override text output detail mode. `status_only` prints bool-style check results; `full` includes full per-check debug output. |
| `--no-fail` | off | Always exit 0, even when checks fail. Useful for collecting results without blocking a CI pipeline. |
| `--filter-severity SEVERITY` | — | Only scan rules matching this severity. Repeatable (`--filter-severity High --filter-severity Critical`). Case-insensitive. |
| `--filter-category CATEGORY` | — | Only scan rules matching this category abbreviation (e.g. `AC`, `AU`). Repeatable. Case-insensitive. |
| `--dry-run` | off | List rule files that would be scanned (to stdout) without executing any checks. Rule list is pipeable; summary header goes to stderr. |
| `--output-dir DIR` | — | Write one report file per rule into `DIR` (filename is `{rule_id}.{format}`). Incompatible with `--output` and `--format text`. |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | All automated checks passed (policy and skip results are ignored) |
| `1` | One or more checks failed, partially passed, or errored |
| `2` | Bad arguments or no rule files found |

**Examples:**

```bash
# Print a summary table to stdout (default)
python cli.py

# Scan a specific ruleset folder
python cli.py --ruleset "rulesets/CMMC Level 1 & 2"

# Export a CSV report
python cli.py --format csv --output report.csv

# Export a PDF report
python cli.py --format pdf --output report.pdf

# Export a JSON report
python cli.py --format json --output report.json

# Verbose scan with PDF output (useful in CI logs)
python cli.py --ruleset "rulesets/CMMC Level 1 & 2" --format pdf --output out.pdf --verbose

# Force bool-style text output for quick triage
python cli.py --format text --detail-mode status_only

# Force full text output for debugging check failures
python cli.py --format text --detail-mode full

# Collect results in CI without failing the build
python cli.py --format json --output results.json --no-fail

# Run with 4 parallel workers instead of the settings.json default
python cli.py --workers 4

# Preview which rules would run (no checks executed)
python cli.py --ruleset "rulesets/CMMC Level 1 & 2" --dry-run

# Scan only Critical and High severity rules
python cli.py --filter-severity Critical --filter-severity High

# Scan only Access Control rules
python cli.py --filter-category AC

# Combine filters: High AC rules only
python cli.py --filter-severity High --filter-category AC

# Export a self-contained HTML report
python cli.py --format html --output report.html

# Write one JSON file per rule into a directory
python cli.py --format json --output-dir results/
```

Progress lines (e.g. `[1/74] AC.L2-3.1.1.json`) are written to stderr so they do not pollute piped stdout or output files. Text-format output includes a `Scan time:` footer showing total elapsed time.

## Using the Interface

The left panel lists all discovered rules grouped by control family. Click a category header to expand it and see the individual rules. Click a rule name to preview its metadata, including the checks it will run and the remediation guidance for that control.

Four controls above the rule list narrow what is shown:

- The search box filters rules by ID or title as you type.
- Below the search box, three compact dropdowns sit in one row: **Category**, **Severity**, and **Status**. Category and severity filter before a scan; the status dropdown (All, PASS, FAIL, PARTIAL, POLICY, SKIP, ERROR) filters by scan result after a scan runs. Only rules that have been scanned appear when a status other than All is selected.

The bottom bar shows scan progress with an estimated time remaining while a scan is running. When a scan completes, the summary dashboard at the top of the right panel updates with the total count of rules and a per-status breakdown. The compliance score is calculated as the number of passing rules divided by the total number of rules that produced a result, excluding skipped checks.

A **Stop** button appears next to the run controls while a scan is in progress. Clicking it cancels the scan after the current rule finishes, preserving all results collected so far.

An **Export...** button appears in the bottom toolbar after a scan completes. Clicking it opens a format picker with four options:

- **PDF Report**: generates a full PDF compliance report.
- **CSV**: generates a CSV file with one row per check result.
- **JSON**: generates a JSON report in the same format as `--format json` from the CLI.
- **HTML**: generates a self-contained single-file HTML report that can be opened in any browser.

A **Copy Output** button appears above the details pane when a rule is selected. Clicking it copies the full contents of the details pane to the system clipboard.

In **Settings → Performance**, the `Parallel scan workers` field controls how many rules run concurrently. Increasing this speeds up large scans on multi-core machines.

In **Settings → Scheduled Scan**, you can configure the application to run automatically on a schedule without manual interaction:

- Toggle `Enable scheduled scan` on.
- Set `Frequency` to Daily or Weekly. For weekly, pick a day of the week.
- Set the time in 24-hour HH:MM format.
- Set the output file path where results will be written as JSON.
- Click **Apply Schedule**.

On Windows this creates a Task Scheduler task (`RuleForgeComplianceScan`) running as the current user with highest privileges. On Linux and macOS it writes a crontab entry. Toggling the switch off and clicking Apply Schedule removes the task or crontab entry.

In **Settings → Display**, `Result detail mode` controls how check output is shown:
- `Status Only`: show check status plus a bool-style result (`True`/`False`) for fast triage.
- `Full Output`: show full check diagnostics (command, expected result, return code, stdout/stderr).

Settings are saved to `settings.json` automatically when you click **Apply** in the Settings tab and persist across restarts.

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| Ctrl+R | Run all visible rules |
| Ctrl+E | Export PDF report |
| F5 | Refresh rule list |

## Rule Files

Rules are stored as JSON files organised into category subfolders under each framework directory. For example: `rulesets/CMMC Level 1 & 2/Access Control/AC.L2-3.1.1.json`. The GUI uses the category subfolder name as the group label; the CLI uses the `category` field inside the JSON. Each file defines one control and contains separate check lists for each supported operating system. Files must conform to the schema defined in `rulesets/rule_schema.json`.

The required top-level fields are:

```
id              Unique rule identifier matching the CMMC control number (e.g. AC.L2-3.1.1)
control_number  Same as id
title           Human-readable control title
description     Full description of the requirement
category        Control family abbreviation (e.g. AC, AU, CM, IA, SC, SI). Used by the CLI --filter-category flag; the GUI derives the displayed group name from the containing subfolder.
target_os       Array of operating systems this rule applies to
check_details   Per-OS check definitions (see below)
severity        One of: Critical, High, Medium, Low
remediation     Instructions to fix non-compliance
tags            Array of strings used for categorization
```

The `check_details` object contains one key per supported OS (`windows_client`, `windows_server`, `linux`, `debian`). Each OS block has a `checks` array. Every check requires:

```
check_type      One of: command, service, file_permissions, policy
name            Human-readable check name
sub_control     Sub-control letter (a, b, c, ...)
command         The shell command to run, a cs_f() call, or "NA" to skip
expected_result Human-readable description of a passing result
purpose         Why this check is required
```

**Check types:**

| Type | Behaviour |
|------|-----------|
| `command` | Runs the command string via PowerShell (Windows) or bash (Linux/Debian). Exit code 0 = PASS. Supports `cs_f()` calls for Python-based checks. |
| `service` | Queries the service by name. Returns PASS if the service is actively running (`Running` on Windows, `active` on Debian/Linux). Any other status — including `Stopped` or `inactive` — is FAIL. |
| `file_permissions` | Retrieves the ACL or permission bits for the given path. Returns PASS if the path is accessible and permission data is returned; the result string is included in reports for manual review. |
| `policy` | No command is executed. The check is recorded as POLICY and excluded from the automated compliance score. Used for controls that require human attestation. |

A command value of `"NA"` causes the check to be skipped and counted separately from run checks in the results.

To add a new rule, copy `rulesets/rule_template.json`, fill in the fields, and place the file in the appropriate category subfolder (e.g. `rulesets/CMMC Level 1 & 2/Access Control/`). Create the subfolder if it does not exist — the GUI will use the folder name as the category label. The application picks up new files automatically on the next launch or when Refresh Rules is clicked.

## Custom Check Functions

When a check command begins with `cs_f(`, the scanner executes a Python function instead of a shell command. The syntax is:

```
cs_f(module.function_name)
```

Where `module` is a file in `core/custom_functions/` and `function_name` is a callable in that module. The function may return either:
- `bool` (legacy/simple format), or
- `(bool, str)` where the string is a human-readable diagnostic message (preferred).

A `True` result is treated as a pass. The message string (when provided) is surfaced in full-output views to help with compliance troubleshooting.

The existing custom function modules are organized by control family and OS suffix: `_wc` for Windows Client, `_ws` for Windows Server, and `_lx` for Linux and Debian.

## Reports

PDF and CSV reports are available after a full scan completes using the **Export...** button in the bottom toolbar.

The PDF report includes a header with the scan timestamp and detected OS, a summary table with pass/fail/partial/skip counts, and a per-rule section listing every check that was run with its return code, output, and any errors.

The CSV report contains one row per check result with columns for rule ID, title, OS, overall status, check name, sub-control, status, expected result, return code, stdout, and stderr. The file is UTF-8 encoded with a BOM for compatibility with Excel.

## Development

### Running Tests

Install dev dependencies and run the full test suite:

```bash
pip install -r requirements-dev.txt
pytest
```

Tests live under `tests/` and cover the CLI argument parser, rule discovery, rule file validation (all 94 CMMC rules and SOC 2 rules are validated against the JSON schema), the `RuleRunner` execution engine, and shared utility functions.

### Linting

The project uses [ruff](https://docs.astral.sh/ruff/) for linting. Run it from the project root:

```bash
pip install ruff
ruff check .
```

Lint configuration is in `pyproject.toml`. The `F` (pyflakes) and `E9` (syntax error) rule sets are enforced. Unused-variable warnings (`F841`) are suppressed in `core/custom_functions/` where side-effect assignments are intentional.

### CI

Every push to `main` and every pull request triggers the CI workflow, which runs the full test suite across:

- **OS:** Windows and Ubuntu
- **Python:** 3.10, 3.11, 3.12

A separate lint job runs `ruff check .` on Ubuntu / Python 3.11.

After all test matrix jobs pass, a SonarCloud scan runs automatically. It analyzes code quality, security hotspots, and test coverage (measured on Ubuntu / Python 3.11). Results appear on the [SonarCloud project dashboard](https://sonarcloud.io/summary/new_code?id=YOUR_ORG_KEY_Compliance-Scanner) and as inline annotations on pull requests.

The scan requires a `SONAR_TOKEN` secret set in **Settings → Secrets and variables → Actions**. Generate the token at **sonarcloud.io → My Account → Security**. See [docs/RELEASE.md](docs/RELEASE.md) for the full secrets reference.

## Project Structure

```
cli.py                      Headless CLI entry point (no display required)
pyproject.toml              Ruff lint configuration

scripts/
  build.bat                 Build script — runs PyInstaller then Inno Setup
  compliance_scanner.spec   PyInstaller spec file
  installer.iss             Inno Setup installer script

core/
  rule_runner.py            Loads rule files and executes checks
  scanner_init.py           OS detection and scanner factory
  scanners/
    base_scanner.py         Abstract scanner interface
    windows.py              Windows check implementations (PowerShell)
    debian.py               Linux and Debian check implementations
  custom_functions/         Per-family Python check functions

rulesets/
  CMMC Level 1 & 2/
    Access Control/         AC rules
    Audit and Accountability/
    Configuration Management/
    Identification and Authentication/
    Incident Response/
    Maintenance/
    Media Protection/
    Security Assessment/
    System Communications Protection/
    System and Information Integrity/
  SOC 2/
    Common Controls/        SOC 2 rules
  rule_schema.json          JSON Schema that all rule files must satisfy
  rule_template.json        Starting point for new rules

ui/
  final_gui.py              Main application entry point and GUI
  rule_display.py           Result and metadata rendering into the text widget
  report_pdf.py             PDF report generation
  report_csv.py             CSV report generation
  report_html.py            Self-contained HTML report generation
  utils.py                  Shared helpers, path setup, and headless subprocess patch
```

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

Free to use for individuals, students, researchers, nonprofits, and government institutions. Commercial use by companies requires explicit written consent from the authors.
