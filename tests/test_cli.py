"""Tests for the CLI."""

import json

from typer.testing import CliRunner

from aigis.cli import app

runner = CliRunner()


def test_scan_unsafe_returns_exit_1(fixtures_dir):
    result = runner.invoke(app, ["scan", str(fixtures_dir / "unsafe_no_approval.py")])
    assert result.exit_code == 1
    assert "AIGIS001" in result.output


def test_scan_safe_returns_exit_0(fixtures_dir):
    result = runner.invoke(app, ["scan", str(fixtures_dir / "safe_guarded.py")])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_scan_json_format(fixtures_dir):
    result = runner.invoke(app, ["scan", str(fixtures_dir / "unsafe_no_approval.py"), "-f", "json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["summary"]["total"] >= 2
    assert "evidence" in data["findings"][0]


def test_scan_sarif_format(fixtures_dir):
    result = runner.invoke(app, ["scan", str(fixtures_dir / "unsafe_no_approval.py"), "-f", "sarif"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"


def test_scan_nonexistent_path():
    result = runner.invoke(app, ["scan", "/nonexistent/path"])
    assert result.exit_code == 2


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert "aigis" in result.output
    assert "0.3.0" in result.output


def test_scan_directory(fixtures_dir):
    result = runner.invoke(app, ["scan", str(fixtures_dir)])
    assert "AIGIS001" in result.output


# -- Severity threshold -------------------------------------------------------

def test_severity_threshold_warning_exits_1(fixtures_dir):
    """unsafe_no_budget has only warnings (AIGIS003) — with threshold=warning, exit 1."""
    result = runner.invoke(app, [
        "scan", str(fixtures_dir / "unsafe_no_budget.py"),
        "-s", "warning",
    ])
    assert result.exit_code == 1


def test_severity_threshold_error_exits_0_on_warnings(fixtures_dir):
    """unsafe_no_budget has only warnings — with threshold=error (default), exit 0."""
    result = runner.invoke(app, [
        "scan", str(fixtures_dir / "unsafe_no_budget.py"),
        "-s", "error",
    ])
    assert result.exit_code == 0


# -- Baseline ----------------------------------------------------------------

def test_baseline_command(fixtures_dir, tmp_path):
    bl_file = tmp_path / "baseline.json"
    result = runner.invoke(app, [
        "baseline", str(fixtures_dir / "unsafe_no_approval.py"),
        "-o", str(bl_file),
    ])
    assert result.exit_code == 0
    assert "Baseline created" in result.output
    data = json.loads(bl_file.read_text())
    assert data["count"] >= 2


def test_scan_with_baseline_ignores_known(fixtures_dir, tmp_path):
    bl_file = tmp_path / "baseline.json"
    # Create baseline
    runner.invoke(app, [
        "baseline", str(fixtures_dir / "unsafe_no_approval.py"),
        "-o", str(bl_file),
    ])
    # Scan with baseline — all findings are known, exit 0
    result = runner.invoke(app, [
        "scan", str(fixtures_dir / "unsafe_no_approval.py"),
        "--baseline", str(bl_file),
    ])
    assert result.exit_code == 0
    assert "baselined" in result.output


# -- Config ------------------------------------------------------------------

def test_scan_with_config_suppression(fixtures_dir, tmp_path):
    config_file = tmp_path / ".aigis.yaml"
    config_file.write_text(
        "suppressions:\n"
        "  - rule: AIGIS001\n"
        "    reason: test suppression\n"
    )
    result = runner.invoke(app, [
        "scan", str(fixtures_dir / "unsafe_no_approval.py"),
        "--config", str(config_file),
    ])
    assert result.exit_code == 0
    assert "suppressed" in result.output
