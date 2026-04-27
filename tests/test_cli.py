"""Tests for cli.py — argument parsing, rule discovery, exit codes, and end-to-end."""
import json
import os
import sys
import subprocess

import pytest

import cli
from ui.report_html import generate_report_html

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestParser:
    def test_defaults(self):
        parser = cli._build_parser()
        args = parser.parse_args([])
        assert args.format == "text"
        assert args.verbose is False
        assert args.no_fail is False
        assert args.output is None
        assert args.page_size == "A4"

    def test_verbose_short_flag(self):
        args = cli._build_parser().parse_args(["-v"])
        assert args.verbose is True

    def test_no_fail_flag(self):
        args = cli._build_parser().parse_args(["--no-fail"])
        assert args.no_fail is True

    def test_invalid_format_rejected(self):
        with pytest.raises(SystemExit):
            cli._build_parser().parse_args(["--format", "xml"])

    def test_detail_mode_choices(self):
        args = cli._build_parser().parse_args(["--detail-mode", "full"])
        assert args.detail_mode == "full"


class TestDiscoverRulePaths:
    def test_nonexistent_dir_returns_empty(self, tmp_path):
        assert cli._discover_rule_paths(str(tmp_path / "nope")) == []

    def test_empty_dir_returns_empty(self, tmp_path):
        assert cli._discover_rule_paths(str(tmp_path)) == []

    def test_finds_json_files(self, tmp_path):
        (tmp_path / "rule.json").write_text("{}")
        result = cli._discover_rule_paths(str(tmp_path))
        assert len(result) == 1

    def test_skips_rule_schema(self, tmp_path):
        (tmp_path / "rule_schema.json").write_text("{}")
        assert cli._discover_rule_paths(str(tmp_path)) == []

    def test_skips_rule_template(self, tmp_path):
        (tmp_path / "rule_template.json").write_text("{}")
        assert cli._discover_rule_paths(str(tmp_path)) == []

    def test_skips_non_json_files(self, tmp_path):
        (tmp_path / "readme.txt").write_text("hello")
        assert cli._discover_rule_paths(str(tmp_path)) == []

    def test_natural_sort_order(self, tmp_path):
        for name in ("rule10.json", "rule2.json", "rule1.json"):
            (tmp_path / name).write_text("{}")
        paths = cli._discover_rule_paths(str(tmp_path))
        names = [os.path.basename(p) for p in paths]
        assert names == ["rule1.json", "rule2.json", "rule10.json"]

    def test_recurses_into_subdirectories(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "rule.json").write_text("{}")
        result = cli._discover_rule_paths(str(tmp_path))
        assert len(result) == 1


class TestExitCode:
    def test_all_pass_returns_zero(self):
        results = {"a": {"checks": [{"status": "PASS"}, {"status": "PASS"}]}}
        assert cli._exit_code(results) == 0

    def test_any_fail_returns_one(self):
        results = {"a": {"checks": [{"status": "FAIL"}]}}
        assert cli._exit_code(results) == 1

    def test_partial_returns_one(self):
        results = {"a": {"checks": [{"status": "PASS"}, {"status": "FAIL"}]}}
        assert cli._exit_code(results) == 1

    def test_error_result_returns_one(self):
        results = {"a": {"error": "crashed", "checks": []}}
        assert cli._exit_code(results) == 1

    def test_skip_only_returns_zero(self):
        results = {"a": {"checks": []}}
        assert cli._exit_code(results) == 0

    def test_policy_only_returns_zero(self):
        results = {"a": {"checks": [{"status": "POLICY"}]}}
        assert cli._exit_code(results) == 0

    def test_mixed_rules_any_fail_returns_one(self):
        results = {
            "a": {"checks": [{"status": "PASS"}]},
            "b": {"checks": [{"status": "FAIL"}]},
        }
        assert cli._exit_code(results) == 1


class TestLoadSettings:
    def test_returns_all_default_keys_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "_PROJECT_ROOT", str(tmp_path))
        settings = cli._load_settings()
        for key in cli._DEFAULT_SETTINGS:
            assert key in settings

    def test_loads_value_from_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "_PROJECT_ROOT", str(tmp_path))
        (tmp_path / "settings.json").write_text(json.dumps({"scan_workers": 8}))
        assert cli._load_settings()["scan_workers"] == 8

    def test_ignores_unknown_keys(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "_PROJECT_ROOT", str(tmp_path))
        (tmp_path / "settings.json").write_text(json.dumps({"totally_unknown": True}))
        assert "totally_unknown" not in cli._load_settings()

    def test_tolerates_malformed_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "_PROJECT_ROOT", str(tmp_path))
        (tmp_path / "settings.json").write_text("not json {{{")
        settings = cli._load_settings()
        assert settings == dict(cli._DEFAULT_SETTINGS)


class TestCLIEndToEnd:
    """Subprocess tests — invoke cli.py as a real process."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "cli.py", *args],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )

    def test_help_exits_zero(self):
        result = self._run("--help")
        assert result.returncode == 0
        assert "usage" in result.stdout.lower()

    def test_missing_ruleset_exits_two(self):
        result = self._run("--ruleset", "/nonexistent/path/xyz123")
        assert result.returncode == 2

    def test_json_format_without_output_exits_two(self):
        result = self._run("--format", "json")
        assert result.returncode == 2

    def test_csv_format_without_output_exits_two(self):
        result = self._run("--format", "csv")
        assert result.returncode == 2

    def test_json_output_is_valid(self, tmp_path, fixtures_dir):
        out = tmp_path / "report.json"
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "json",
            "--output", str(out),
            "--no-fail",
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "results" in data
        assert "summary" in data
        assert isinstance(data["results"], list)
        assert len(data["results"]) == 1

    def test_csv_output_is_created(self, tmp_path, fixtures_dir):
        out = tmp_path / "report.csv"
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "csv",
            "--output", str(out),
            "--no-fail",
        )
        assert result.returncode == 0, result.stderr
        assert out.exists()
        content = out.read_text(encoding="utf-8-sig")
        assert "rule_id" in content.lower() or len(content) > 0

    def test_text_output_printed_to_stdout(self, fixtures_dir):
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "text",
            "--no-fail",
        )
        assert result.returncode == 0, result.stderr
        assert "RuleForge" in result.stdout

    def test_no_fail_overrides_exit_code(self, fixtures_dir):
        result = self._run("--ruleset", fixtures_dir, "--no-fail")
        assert result.returncode == 0

    def test_dry_run_exits_zero_and_prints_rules(self, fixtures_dir):
        result = self._run("--ruleset", fixtures_dir, "--dry-run")
        assert result.returncode == 0
        # Rule list goes to stdout (pipeable); header summary goes to stderr
        assert "sample_rule.json" in result.stdout

    def test_dry_run_header_goes_to_stderr(self, fixtures_dir):
        result = self._run("--ruleset", fixtures_dir, "--dry-run")
        assert "Dry run" in result.stderr

    def test_text_output_contains_scan_time(self, fixtures_dir):
        result = self._run("--ruleset", fixtures_dir, "--format", "text", "--no-fail")
        assert result.returncode == 0
        assert "Scan time:" in result.stdout

    def test_html_output_is_valid(self, tmp_path, fixtures_dir):
        out = tmp_path / "report.html"
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "html",
            "--output", str(out),
            "--no-fail",
        )
        assert result.returncode == 0, result.stderr
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "RuleForge" in content
        assert "PASS" in content or "FAIL" in content or "SKIP" in content

    def test_html_format_without_output_exits_two(self):
        result = self._run("--format", "html")
        assert result.returncode == 2

    def test_output_dir_json(self, tmp_path, fixtures_dir):
        out_dir = tmp_path / "per_rule"
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "json",
            "--output-dir", str(out_dir),
            "--no-fail",
        )
        assert result.returncode == 0, result.stderr
        json_files = list(out_dir.glob("*.json"))
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text(encoding="utf-8"))
        assert "results" in data

    def test_output_dir_html(self, tmp_path, fixtures_dir):
        out_dir = tmp_path / "per_rule_html"
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "html",
            "--output-dir", str(out_dir),
            "--no-fail",
        )
        assert result.returncode == 0, result.stderr
        html_files = list(out_dir.glob("*.html"))
        assert len(html_files) == 1
        assert "<!DOCTYPE html>" in html_files[0].read_text(encoding="utf-8")

    def test_output_dir_and_output_mutually_exclusive(self, tmp_path, fixtures_dir):
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "json",
            "--output", str(tmp_path / "x.json"),
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 2

    def test_output_dir_with_text_format_exits_two(self, tmp_path, fixtures_dir):
        result = self._run(
            "--ruleset", fixtures_dir,
            "--format", "text",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 2


class TestFilterRulePaths:
    def _write_rule(self, path, severity="High", category="AC"):
        import json
        path.write_text(json.dumps({
            "id": "TEST.01", "severity": severity, "category": category,
        }), encoding="utf-8")

    def test_no_filters_returns_all(self, tmp_path):
        for name in ("a.json", "b.json"):
            self._write_rule(tmp_path / name)
        paths = [str(tmp_path / "a.json"), str(tmp_path / "b.json")]
        assert cli._filter_rule_paths(paths, None, None) == paths

    def test_severity_filter_keeps_matching(self, tmp_path):
        self._write_rule(tmp_path / "high.json", severity="High")
        self._write_rule(tmp_path / "low.json",  severity="Low")
        paths = [str(tmp_path / "high.json"), str(tmp_path / "low.json")]
        result = cli._filter_rule_paths(paths, severities=["High"], categories=None)
        assert len(result) == 1
        assert "high.json" in result[0]

    def test_severity_filter_multi_value(self, tmp_path):
        self._write_rule(tmp_path / "critical.json", severity="Critical")
        self._write_rule(tmp_path / "high.json",     severity="High")
        self._write_rule(tmp_path / "low.json",      severity="Low")
        paths = [str(tmp_path / f) for f in ("critical.json", "high.json", "low.json")]
        result = cli._filter_rule_paths(paths, severities=["Critical", "High"], categories=None)
        assert len(result) == 2

    def test_category_filter_keeps_matching(self, tmp_path):
        self._write_rule(tmp_path / "ac.json", category="AC")
        self._write_rule(tmp_path / "au.json", category="AU")
        paths = [str(tmp_path / "ac.json"), str(tmp_path / "au.json")]
        result = cli._filter_rule_paths(paths, severities=None, categories=["AC"])
        assert len(result) == 1
        assert "ac.json" in result[0]

    def test_both_filters_are_anded(self, tmp_path):
        self._write_rule(tmp_path / "ac_high.json",  severity="High",   category="AC")
        self._write_rule(tmp_path / "ac_low.json",   severity="Low",    category="AC")
        self._write_rule(tmp_path / "au_high.json",  severity="High",   category="AU")
        paths = [str(tmp_path / f) for f in ("ac_high.json", "ac_low.json", "au_high.json")]
        result = cli._filter_rule_paths(paths, severities=["High"], categories=["AC"])
        assert len(result) == 1
        assert "ac_high.json" in result[0]

    def test_case_insensitive_severity(self, tmp_path):
        self._write_rule(tmp_path / "rule.json", severity="High")
        paths = [str(tmp_path / "rule.json")]
        assert len(cli._filter_rule_paths(paths, severities=["high"], categories=None)) == 1

    def test_case_insensitive_category(self, tmp_path):
        self._write_rule(tmp_path / "rule.json", category="AC")
        paths = [str(tmp_path / "rule.json")]
        assert len(cli._filter_rule_paths(paths, severities=None, categories=["ac"])) == 1


class TestHtmlReport:
    """Unit tests for ui/report_html.generate_report_html."""

    def _fake_results(self, status: str = "PASS") -> dict:
        return {
            "fake_path": {
                "rule_id": "TEST.01",
                "title":   "Test Rule",
                "os":      "windows_client",
                "checks_run":     1,
                "checks_skipped": 0,
                "checks_policy":  0,
                "checks": [
                    {
                        "status":          status,
                        "check_name":      "Sample check",
                        "command":         "echo hello",
                        "expected_result": "hello",
                        "returncode":      0 if status == "PASS" else 1,
                        "stdout":          "hello",
                        "stderr":          "",
                    }
                ],
            }
        }

    def test_produces_html_file(self, tmp_path):
        out = tmp_path / "report.html"
        generate_report_html(str(out), self._fake_results())
        assert out.exists()

    def test_html_is_valid_doctype(self, tmp_path):
        out = tmp_path / "report.html"
        generate_report_html(str(out), self._fake_results())
        content = out.read_text(encoding="utf-8")
        assert content.strip().startswith("<!DOCTYPE html>")

    def test_contains_rule_id(self, tmp_path):
        out = tmp_path / "report.html"
        generate_report_html(str(out), self._fake_results())
        assert "TEST.01" in out.read_text(encoding="utf-8")

    def test_contains_pass_badge(self, tmp_path):
        out = tmp_path / "report.html"
        generate_report_html(str(out), self._fake_results("PASS"))
        assert "PASS" in out.read_text(encoding="utf-8")

    def test_contains_fail_badge(self, tmp_path):
        out = tmp_path / "report.html"
        generate_report_html(str(out), self._fake_results("FAIL"))
        assert "FAIL" in out.read_text(encoding="utf-8")

    def test_empty_results_produces_file(self, tmp_path):
        out = tmp_path / "empty.html"
        generate_report_html(str(out), {})
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_escapes_html_in_rule_title(self, tmp_path):
        out = tmp_path / "report.html"
        results = self._fake_results()
        results["fake_path"]["title"] = "<script>alert(1)</script>"
        generate_report_html(str(out), results)
        content = out.read_text(encoding="utf-8")
        assert "<script>" not in content
        assert "&lt;script&gt;" in content

    def test_score_shown_for_automated_checks(self, tmp_path):
        out = tmp_path / "report.html"
        generate_report_html(str(out), self._fake_results("PASS"))
        content = out.read_text(encoding="utf-8")
        assert "100.0%" in content

    def test_check_stdout_included(self, tmp_path):
        out = tmp_path / "report.html"
        generate_report_html(str(out), self._fake_results("PASS"))
        assert "hello" in out.read_text(encoding="utf-8")
