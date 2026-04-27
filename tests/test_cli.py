"""Tests for cli.py — argument parsing, rule discovery, exit codes, and end-to-end."""
import json
import os
import sys
import subprocess

import pytest

import cli

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
