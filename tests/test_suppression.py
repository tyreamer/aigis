"""Tests for suppression logic."""

from aigis.analyzer import PythonAnalyzer
from aigis.rules import run_all_rules
from aigis.suppression import SuppressionFilter


def _findings_for(fixture_path):
    graph = PythonAnalyzer().analyze(fixture_path)
    results = run_all_rules(graph)
    return [f for r in results for f in r.findings]


# -- Inline suppression -----------------------------------------------------

def test_inline_aigis_disable_suppresses(fixtures_dir):
    findings = _findings_for(fixtures_dir / "inline_suppression.py")
    sf = SuppressionFilter()
    active, suppressed = sf.filter(findings)

    active_subjects = [f.evidence.subject_name for f in active if f.evidence]
    suppressed_subjects = [f.evidence.subject_name for f in suppressed if f.evidence]

    assert "suppressed_delete" in suppressed_subjects
    assert "not_suppressed" in active_subjects


def test_inline_noqa_style_suppresses(fixtures_dir):
    findings = _findings_for(fixtures_dir / "inline_suppression.py")
    sf = SuppressionFilter()
    active, suppressed = sf.filter(findings)
    suppressed_subjects = [f.evidence.subject_name for f in suppressed if f.evidence]
    assert "noqa_style_suppressed" in suppressed_subjects


def test_inline_suppression_does_not_affect_other_rules(fixtures_dir):
    """AEG001 is suppressed but other rules should still fire."""
    findings = _findings_for(fixtures_dir / "inline_suppression.py")
    sf = SuppressionFilter()
    active, suppressed = sf.filter(findings)
    # Only AEG001 findings should be suppressed
    for f in suppressed:
        assert f.rule_id == "AEG001"


# -- Config suppression ------------------------------------------------------

def test_config_suppression_by_rule(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    config_suppressions = [{"rule": "AEG001", "reason": "accepted risk"}]
    sf = SuppressionFilter(config_suppressions)
    active, suppressed = sf.filter(findings)
    # All AEG001 findings should be suppressed
    for f in suppressed:
        assert f.rule_id == "AEG001"
    for f in active:
        assert f.rule_id != "AEG001"


def test_config_suppression_by_symbol(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    config_suppressions = [{"rule": "AEG001", "symbol": "delete_user_data"}]
    sf = SuppressionFilter(config_suppressions)
    active, suppressed = sf.filter(findings)
    assert any(f.evidence.subject_name == "delete_user_data" for f in suppressed if f.evidence)
    # send_notification should still be active
    assert any(f.evidence.subject_name == "send_notification" for f in active if f.evidence)


def test_config_suppression_by_path_glob(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    config_suppressions = [{"path": "**/fixtures/*", "reason": "test fixtures"}]
    sf = SuppressionFilter(config_suppressions)
    active, suppressed = sf.filter(findings)
    assert len(active) == 0
    assert len(suppressed) > 0


def test_no_suppressions_all_active(fixtures_dir):
    findings = _findings_for(fixtures_dir / "unsafe_no_approval.py")
    sf = SuppressionFilter()
    active, suppressed = sf.filter(findings)
    assert len(suppressed) == 0
    assert len(active) == len(findings)
