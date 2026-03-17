"""Tests for output formatters."""

import json

from aigis.analyzer import PythonAnalyzer
from aigis.output import format_console, format_json, format_sarif
from aigis.output_html import format_html
from aigis.rules import run_all_rules


def _scan(fixture_path):
    graph = PythonAnalyzer().analyze(fixture_path)
    return run_all_rules(graph)


def test_console_output_contains_rule_ids(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_console(results, str(fixtures_dir / "unsafe_no_approval.py"))
    assert "AIGIS001" in text
    assert "ERROR" in text
    assert "finding" in text.lower()


def test_console_no_findings(fixtures_dir):
    results = _scan(fixtures_dir / "safe_guarded.py")
    text = format_console(results, str(fixtures_dir / "safe_guarded.py"))
    assert "No findings" in text


def test_console_shows_evidence(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_console(results, str(fixtures_dir / "unsafe_no_approval.py"))
    assert "Evidence:" in text
    assert "Fix:" in text
    assert "confidence=" in text


def test_console_shows_summary_by_rule(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_console(results, str(fixtures_dir / "unsafe_no_approval.py"))
    assert "Summary by rule:" in text
    assert "AIGIS001" in text


def test_console_shows_suppressed_count(fixtures_dir):
    results = _scan(fixtures_dir / "safe_guarded.py")
    text = format_console(results, str(fixtures_dir / "safe_guarded.py"), suppressed_count=3)
    assert "3 suppressed" in text


def test_console_shows_baselined_count(fixtures_dir):
    results = _scan(fixtures_dir / "safe_guarded.py")
    text = format_console(results, str(fixtures_dir / "safe_guarded.py"), baselined_count=5)
    assert "5 baselined" in text


def test_json_output_is_valid(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_json(results, str(fixtures_dir / "unsafe_no_approval.py"))
    data = json.loads(text)
    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["total"] >= 2


def test_json_has_evidence(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    data = json.loads(format_json(results, "test"))
    for finding in data["findings"]:
        assert "evidence" in finding
        ev = finding["evidence"]
        assert "subject_name" in ev
        assert "sink_type" in ev
        assert "approval_signal_found" in ev
        assert "confidence" in ev
        assert "remediation" in ev


def test_json_summary_has_suppressed_and_baselined(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    data = json.loads(format_json(results, "test", suppressed_count=2, baselined_count=1))
    assert data["summary"]["suppressed"] == 2
    assert data["summary"]["baselined"] == 1


def test_json_empty_findings(fixtures_dir):
    results = _scan(fixtures_dir / "safe_guarded.py")
    data = json.loads(format_json(results, "safe"))
    assert data["summary"]["total"] == 0


def test_sarif_output_is_valid(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_sarif(results, str(fixtures_dir / "unsafe_no_approval.py"))
    data = json.loads(text)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "aigis"
    assert len(run["results"]) >= 2


def test_sarif_results_have_locations(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    data = json.loads(format_sarif(results, str(fixtures_dir / "unsafe_no_approval.py")))
    for result in data["runs"][0]["results"]:
        assert "locations" in result
        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc
        assert loc["region"]["startLine"] > 0


def test_sarif_has_evidence_in_properties(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    data = json.loads(format_sarif(results, str(fixtures_dir / "unsafe_no_approval.py")))
    for result in data["runs"][0]["results"]:
        assert "properties" in result
        assert "evidence" in result["properties"]


# -- HTML output ---------------------------------------------------------------

def test_html_output_is_valid(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_html(results, str(fixtures_dir / "unsafe_no_approval.py"))
    assert "<!DOCTYPE html>" in text
    assert "aigis" in text
    assert "AIGIS001" in text
    assert "const F=" in text or "const S=" in text  # JS data variables


def test_html_output_has_findings_data(fixtures_dir):
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_html(results, str(fixtures_dir / "unsafe_no_approval.py"))
    assert "delete_user_data" in text
    assert "send_notification" in text
    assert "subject_name" in text


def test_html_empty_findings(fixtures_dir):
    results = _scan(fixtures_dir / "safe_guarded.py")
    text = format_html(results, str(fixtures_dir / "safe_guarded.py"))
    assert "<!DOCTYPE html>" in text
    assert '"total": 0' in text


def test_html_output_self_contained(fixtures_dir):
    """HTML report should not depend on external JS frameworks."""
    results = _scan(fixtures_dir / "unsafe_no_approval.py")
    text = format_html(results, str(fixtures_dir / "unsafe_no_approval.py"))
    # No external JS frameworks — font CDN is allowed (degrades gracefully)
    assert "<script src=" not in text.lower()
