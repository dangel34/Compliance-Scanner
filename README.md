# RuleForge

A desktop application that scans Windows, Linux, and Debian systems against CMMC Level 2 control requirements and produces detailed compliance reports. Built as a senior project at Mercyhurst University by Derek Angelini, Connor McBee, and Melanie Fox.

## Overview

The scanner loads a set of JSON rule files, executes the checks defined in each rule against the local system, and displays pass/fail results in a graphical interface. Results can be exported as a PDF report or a CSV file. The tool detects the operating system at startup and runs only the checks relevant to that platform.

The 74 included rules cover six CMMC Level 2 control families: Access Control (AC), Audit and Accountability (AU), Configuration Management (CM), Identification and Authentication (IA), System and Communications Protection (SC), and System and Information Integrity (SI).

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

On Windows, some checks execute PowerShell commands and may require the terminal to be run as Administrator to return accurate results. On Linux and Debian, certain checks require root privileges for the same reason.

## Using the Interface

The left panel lists all discovered rules grouped by control family. Click a category header to expand it and see the individual rules. Click a rule name to preview its metadata, including the checks it will run and the remediation guidance for that control.

The filter dropdowns above the rule list narrow the list by control family or severity (Critical, High, Medium, Low). The Run All Rules button and the compliance score only reflect the rules currently visible after filtering.

The bottom bar shows scan progress with an estimated time remaining while a scan is running. When a scan completes, the summary dashboard at the top of the right panel updates with the total count of rules and a per-status breakdown. The compliance score is calculated as the number of passing rules divided by the total number of rules that produced a result, excluding skipped checks.

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| Ctrl+R | Run all visible rules |
| Ctrl+E | Export PDF report |
| F5 | Refresh rule list |

## Rule Files

Rules are stored as JSON files under `rulesets/cmmc-rules/`. Each file defines one CMMC control and contains separate check lists for each supported operating system. The file must conform to the schema defined in `rulesets/rule_schema.json`.

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

To add a new rule, copy `rulesets/rule_template.json`, fill in the fields, and place the file in `rulesets/cmmc-rules/`. The application will pick it up automatically on the next launch or when Refresh Rules is clicked.

## Custom Check Functions

When a check command begins with `cs_f(`, the scanner executes a Python function instead of a shell command. The syntax is:

```
cs_f(module.function_name)
```

Where `module` is a file in `core/custom_functions/` and `function_name` is a callable in that module. The function must return either a boolean or a tuple of `(bool, str)` where the string is the output message. A return value of `True` is treated as a passing result.

The existing custom function modules are organized by control family and OS suffix: `_wc` for Windows Client, `_ws` for Windows Server, and `_lx` for Linux and Debian.

## Reports

PDF and CSV reports are available after a full scan completes using the Export PDF and Export CSV buttons.

The PDF report includes a header with the scan timestamp and detected OS, a summary table with pass/fail/partial/skip counts, and a per-rule section listing every check that was run with its return code, output, and any errors.

The CSV report contains one row per check result with columns for rule ID, title, OS, overall status, check name, sub-control, status, expected result, return code, stdout, and stderr. The file is UTF-8 encoded with a BOM for compatibility with Excel.

## Project Structure

```
core/
  rule_runner.py          Loads rule files and executes checks
  scanner_init.py         OS detection and scanner factory
  scanners/
    windows.py            Windows check implementations (PowerShell)
    debian.py             Linux and Debian check implementations
  custom_functions/       Per-family Python check functions

rulesets/
  cmmc-rules/             74 JSON rule files
  rule_schema.json        JSON Schema that all rule files must satisfy
  rule_template.json      Starting point for new rules

ui/
  final_gui.py            Main application entry point and GUI
  rule_display.py         Result and metadata rendering into the text widget
  report_pdf.py           PDF report generation
  report_csv.py           CSV report generation
  utils.py                Shared helpers and status determination logic
```
