"""Tests for baseline support."""

from aigis.analyzer import PythonAnalyzer
from aigis.baseline import create_baseline, filter_by_baseline, fingerprint
from aigis.rules import run_all_rules


def _findings_for(fixture_path):
    graph = PythonAnalyzer().analyze(fixture_path)
    results = run_all_rules(graph)
    return [f for r in results for f in r.findings]


def test_fingerprint_stable(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    base = str(fixtures_dir)
    fp1 = fingerprint(findings[0], base)
    fp2 = fingerprint(findings[0], base)
    assert fp1 == fp2


def test_fingerprint_differs_by_rule(fixtures_dir):
    """Different rule IDs should produce different fingerprints."""
    from aigis.models import Evidence, Finding, Location, Severity, TriState
    f1 = Finding(
        rule_id="AIGIS001", message="x", severity=Severity.ERROR,
        location=Location(file="a.py", line=1),
        evidence=Evidence(subject_name="tool1"),
    )
    f2 = Finding(
        rule_id="AIGIS002", message="x", severity=Severity.ERROR,
        location=Location(file="a.py", line=1),
        evidence=Evidence(subject_name="tool1"),
    )
    assert fingerprint(f1, ".") != fingerprint(f2, ".")


def test_create_baseline(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    bl = create_baseline(findings, str(fixtures_dir))
    assert bl["version"] == "1"
    assert bl["count"] == len(findings)
    assert len(bl["findings"]) == len(findings)
    for entry in bl["findings"]:
        assert "fingerprint" in entry
        assert "rule_id" in entry
        assert "message" in entry


def test_filter_by_baseline_removes_known(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    base = str(fixtures_dir)
    bl = create_baseline(findings, base)
    # All existing findings should be baselined
    new, baselined = filter_by_baseline(findings, bl, base)
    assert len(new) == 0
    assert len(baselined) == len(findings)


def test_filter_by_baseline_passes_new(fixtures_dir):
    """New findings not in baseline should pass through."""
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    base = str(fixtures_dir)
    # Create baseline with only the first finding
    partial_bl = create_baseline(findings[:1], base)
    new, baselined = filter_by_baseline(findings, partial_bl, base)
    assert len(baselined) == 1
    assert len(new) == len(findings) - 1


def test_empty_baseline_passes_all(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    empty_bl = {"version": "1", "findings": []}
    new, baselined = filter_by_baseline(findings, empty_bl, str(fixtures_dir))
    assert len(new) == len(findings)
    assert len(baselined) == 0
