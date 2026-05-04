# RuleForge Roadmap

## Overview

This document tracks planned improvements and features for RuleForge. Items are grouped by theme and roughly ordered by priority within each section.

---

## Ruleset and Rule Authoring

### Rule Builder GUI
A graphical wizard for creating and editing rules without touching JSON directly. The tool would walk through each required field (ID, title, severity, OS targets, check type), validate input in real-time against the JSON schema, and write the finished rule to the rulesets directory. It should also support editing existing rules and show a live JSON preview so authors can verify the output before saving.

### Custom Function Builder
An in-app editor for writing and testing Python custom check functions. The editor would include syntax highlighting, a run button that executes the function against the local machine in a sandboxed subprocess, and output showing the `(bool, str)` return value. New functions would be scaffolded with the correct module structure and `clear_cache()` stub, then wired into the rule JSON via a dropdown so the author never has to type `cs_f(module.function_name)` manually.

### Rule Validation and Linting Panel
A dedicated UI panel (and CLI subcommand) that runs all rule files through the JSON schema validator and reports errors with file name, line number, and a plain-English explanation. Currently validation happens silently at load time; surfacing it explicitly helps when authoring new rules or onboarding contributors.

### Rule Import and Export
Allow users to package a subset of rules into a portable `.zip` bundle and import bundles from other RuleForge installations. This makes it easy to share organization-specific rule extensions without replacing the base ruleset.

---

## Scan Results and Reporting

### Scan Comparison and Diff View
Load two saved JSON scan results and show a side-by-side diff: rules that changed from PASS to FAIL, newly skipped checks, and score delta. This is useful for tracking whether a remediation action actually fixed a finding or whether a system drifted between audits.

### Remediation Automation
For a curated subset of rules, add an optional "Auto-Remediate" button that applies the documented fix (e.g., enabling a service, setting a registry value) with a preview of the exact command before it runs. Each automated fix must require explicit confirmation and produce an audit log entry. This is opt-in and never runs without user approval.

### Executive Summary Report
A one-page PDF format containing only the overall score, a category-level breakdown bar chart, top failing rules by severity, and a trend line if previous scan data is available. Designed for non-technical stakeholders and distinct from the existing detailed PDF.

### Report Branding and Customization
Let users set an organization name and logo that appear in PDF and HTML report headers. Store these in `settings.json` so they persist across sessions.

### Trend Tracking and History View
Persist scan results to a local SQLite database and display a score-over-time line chart in the GUI. Show when specific rules started failing so engineers can correlate findings with system changes.

---

## Scanning Engine

### Remote and Network Scanning
Add an agent-based scan mode where RuleForge connects to a remote host (SSH for Linux, WinRM for Windows), pushes a minimal scan bundle, executes checks, and retrieves results. The UI would manage a list of target hosts and aggregate results into a multi-host report.

### Incremental and Targeted Scanning
Allow users to run only the rules that failed in the last scan, or only rules matching a specific filter, without re-scanning everything. This speeds up iterative remediation workflows significantly.

### Rule Dependency and Ordering
Support a `depends_on` field in rule JSON so a rule can be skipped automatically if a prerequisite check failed. For example, a rule that checks an audit log configuration should be skipped if the audit service is not running.

### macOS Support
Add a `MacScanner` implementation and macOS-specific check definitions for the existing rule families. The OS detection logic in `scanner_init.py` already has a placeholder for Mac; this fills it in.

### Additional Linux Distribution Support
Extend the existing Debian scanner to handle RPM-based distributions (RHEL, Rocky, Fedora) by detecting the package manager and adjusting commands accordingly. Add distribution-specific rule variants where behavior differs.

---

## User Interface

### Rule Notes and Annotations
Let users attach free-text notes to individual rules (e.g., "Accepted risk approved by CISO on 2026-01-15"). Notes persist in a local database and appear in reports as an annotation alongside the check result.

### Bulk Status Override
Allow marking one or more rules as "Accepted Risk" or "Not Applicable" with a required justification. Overridden rules are excluded from scoring but remain visible in reports with the justification text.

### Settings Migration and Profiles
Support multiple named settings profiles (e.g., "Workstation Baseline", "Server Hardening") so different scan configurations can be switched without manually editing `settings.json`. Include import and export for profiles.

### Keyboard Navigation Improvements
Make the accordion rule list fully keyboard-navigable (arrow keys to move between rules, Enter to expand, Space to select). Currently mouse interaction is required for most operations.

### Accessibility Improvements
Add ARIA-equivalent labels to all interactive elements for screen readers. Ensure color is never the sole indicator of pass/fail status (add icons). Test against high-contrast display modes.

---

## CLI and Integration

### Watch Mode
A `--watch` flag that re-runs the scan whenever a relevant configuration file changes (detected via filesystem events). Useful for developers actively remediating a system who want immediate feedback.

### Output to Syslog and SIEM
Add a `--syslog` output option that emits structured JSON events per rule result to the local syslog daemon or a remote UDP/TCP endpoint. This enables integration with SIEM tools like Splunk or Elastic without post-processing report files.

### Configuration File Support for CLI
Allow all CLI flags to be specified in a `.ruleforge.toml` configuration file checked into the repo, so CI pipelines do not need long argument lists. Flags passed directly still override the config file.

### Exit Code Granularity
Extend exit codes to distinguish between "scan ran and found failures" (current code 1) and "scan ran but was partially skipped due to errors" (new code 3). This lets CI pipelines treat error conditions differently from clean failures.

---

## Developer Experience

### Plugin System for Scanners and Report Generators
Define a formal plugin interface so third-party packages can register new scanner targets, check types, or report formats without modifying core files. Use Python entry points for discovery. This would make the custom function system more composable and allow community contributions without forking.

### Rule Authoring Documentation and Examples
Add a `docs/authoring-rules.md` guide covering the full rule schema, all check types, custom function patterns, caching, OS targeting, and common pitfalls. Include annotated example rules for each check type.

### Developer CLI Subcommands
Add `ruleforge validate` (validates all rule files), `ruleforge scaffold rule` (generates a rule template), and `ruleforge scaffold function` (generates a custom function stub) as first-class CLI subcommands so authors do not need to manually copy templates.

---

## Security and Compliance

### Rule Signing and Integrity Verification
Optionally sign the bundled rulesets with a GPG key so organizations can verify that rules have not been tampered with between distribution and execution. The rule loader would verify signatures before running any checks.

### Audit Log for Scan Sessions
Write a tamper-evident log of every scan session (who ran it, when, which rules executed, result summary) to a local append-only file. This supports compliance requirements that mandate evidence of regular audits.

### Role-Based Access Control for Remediation
When the remediation automation feature is added, gate it behind a simple role check (e.g., require running as Administrator/root, or require a confirmation token) to prevent accidental or unauthorized changes.

### Additional Compliance Frameworks
Add rule families and scoring logic for NIST SP 800-171, HIPAA Security Rule, and CIS Benchmarks in addition to the existing CMMC Level 2 and SOC 2 coverage. Each framework would be selectable at scan time so only relevant rules run.
