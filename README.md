# RuleForge

A desktop application that scans Windows, Linux, and Debian systems against CMMC Level 2 control requirements and produces detailed compliance reports. Built as a senior project at Mercyhurst University by Derek Angelini, Connor McBee, and Melanie Fox.

## Overview

The scanner loads a set of JSON rule files, executes the checks defined in each rule against the local system, and displays pass/fail results in a graphical interface. Results can be exported as a PDF report or a CSV file. The tool detects the operating system at startup and runs only the checks relevant to that platform.

The 94 included rules cover six CMMC Level 2 control families across Windows Client and Windows Server: Access Control (AC), Audit and Accountability (AU), Configuration Management (CM), Identification and Authentication (IA), System and Communications Protection (SC), and System and Information Integrity (SI). SOC 2 rules are also included.

## Installation (Windows — Recommended)

A pre-built Windows installer is available. Download `ComplianceScannerSetup.exe` and run it. The installer places the application in `C:\Program Files\Compliance Scanner\`, creates a Start Menu shortcut, and registers an uninstaller.

The application requests administrator privileges at launch — this is required for accurate compliance scanning on Windows.

> **Note:** The installer is unsigned. Windows SmartScreen may show a warning on first run. Click **More info → Run anyway** to proceed.

## Building from Source

Requires Python 3.10+, [PyInstaller](https://pyinstaller.org), and [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```bat
build.bat
```

This script installs PyInstaller if needed, runs it against `compliance_scanner.spec`, then (if Inno Setup is installed) compiles `installer.iss` to produce `dist\installer\ComplianceScannerSetup.exe`.

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
| `--format text\|json\|csv\|pdf` | `text` | Output format. `text` prints a summary table to stdout. |
| `--output FILE` | — | File path to write the report. Required for `json`, `csv`, and `pdf`. |
| `--page-size A4\|LETTER` | `A4` | Page size for PDF reports. |
| `--verbose` / `-v` | off | Print each rule's pass/fail status to stderr as the scan progresses. |
| `--detail-mode status_only\|full` | from `settings.json` | Override text output detail mode. `status_only` prints bool-style check results; `full` includes full per-check debug output. |
| `--no-fail` | off | Always exit 0, even when checks fail. Useful for collecting results without blocking a CI pipeline. |

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
```

Progress lines (e.g. `[1/74] AC.L2-3.1.1.json`) are written to stderr so they do not pollute piped stdout or output files.

## Using the Interface

The left panel lists all discovered rules grouped by control family. Click a category header to expand it and see the individual rules. Click a rule name to preview its metadata, including the checks it will run and the remediation guidance for that control.

The filter dropdowns above the rule list narrow the list by control family or severity (Critical, High, Medium, Low). The Run All Rules button and the compliance score only reflect the rules currently visible after filtering.

The bottom bar shows scan progress with an estimated time remaining while a scan is running. When a scan completes, the summary dashboard at the top of the right panel updates with the total count of rules and a per-status breakdown. The compliance score is calculated as the number of passing rules divided by the total number of rules that produced a result, excluding skipped checks.

A **Stop** button appears next to the run controls while a scan is in progress. Clicking it cancels the scan after the current rule finishes, preserving all results collected so far.

In **Settings → Display**, `Result detail mode` controls how check output is shown:
- `Status Only`: show check status plus a bool-style result (`True`/`False`) for fast triage.
- `Full Output`: show full check diagnostics (command, expected result, return code, stdout/stderr).

The `Untruncate failed output` setting still applies in full mode and disables line capping for failed/partial/error checks.

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| Ctrl+R | Run all visible rules |
| Ctrl+E | Export PDF report |
| F5 | Refresh rule list |

## Rule Files

Rules are stored as JSON files under `rulesets/CMMC Level 1 & 2/`. Each file defines one CMMC control and contains separate check lists for each supported operating system. The file must conform to the schema defined in `rulesets/rule_schema.json`.

The required top-level fields are:

```
id              Unique rule identifier matching the CMMC control number (e.g. AC.L2-3.1.1)
control_number  Same as id
title           Human-readable control title
description     Full description of the requirement
category        Control family abbreviation: AC, AU, CM, IA, SC, or SI
target_os       Array of operating systems this rule applies to
check_details   Per-OS check definitions (see below)
severity        One of: Critical, High, Medium, Low
remediation     Instructions to fix non-compliance
tags            Array of strings used for categorization
```

The `check_details` object contains one key per supported OS (`windows_client`, `windows_server`, `linux`, `debian`). Each OS block has a `checks` array. Every check requires:

```
check_type      One of: command, service, file_permissions
name            Human-readable check name
sub_control     Sub-control letter (a, b, c, ...)
command         The shell command to run, a cs_f() call, or "NA" to skip
expected_result Human-readable description of a passing result
purpose         Why this check is required
```

A command value of `"NA"` causes the check to be skipped and counted separately from run checks in the results.

To add a new rule, copy `rulesets/rule_template.json`, fill in the fields, and place the file in `rulesets/CMMC Level 1 & 2/` (or a custom sub-folder). The application will pick it up automatically on the next launch or when Refresh Rules is clicked.

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

PDF and CSV reports are available after a full scan completes using the Export PDF and Export CSV buttons.

The PDF report includes a header with the scan timestamp and detected OS, a summary table with pass/fail/partial/skip counts, and a per-rule section listing every check that was run with its return code, output, and any errors.

The CSV report contains one row per check result with columns for rule ID, title, OS, overall status, check name, sub-control, status, expected result, return code, stdout, and stderr. The file is UTF-8 encoded with a BOM for compatibility with Excel.

## Project Structure

```
cli.py                      Headless CLI entry point (no display required)
build.bat                   Build script — runs PyInstaller then Inno Setup
compliance_scanner.spec     PyInstaller spec file
installer.iss               Inno Setup installer script

core/
  rule_runner.py            Loads rule files and executes checks
  scanner_init.py           OS detection and scanner factory
  scanners/
    base_scanner.py         Abstract scanner interface
    windows.py              Windows check implementations (PowerShell)
    debian.py               Linux and Debian check implementations
  custom_functions/         Per-family Python check functions

rulesets/
  CMMC Level 1 & 2/        94 JSON rule files
  SOC 2/                   SOC 2 rule files
  rule_schema.json          JSON Schema that all rule files must satisfy
  rule_template.json        Starting point for new rules

ui/
  final_gui.py              Main application entry point and GUI
  rule_display.py           Result and metadata rendering into the text widget
  report_pdf.py             PDF report generation
  report_csv.py             CSV report generation
  utils.py                  Shared helpers, path setup, and headless subprocess patch
```
