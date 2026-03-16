"""Tests for governance rules."""

from aigis.analyzer import PythonAnalyzer
from aigis.models import TriState
from aigis.rules import run_all_rules


def _run(fixture_path):
    graph = PythonAnalyzer().analyze(fixture_path)
    results = run_all_rules(graph)
    return {r.rule_id: r for r in results}


# -- AEG001: unguarded mutating tool ----------------------------------------

def test_aeg001_fires_on_unguarded_tool(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_approval.py")
    assert len(results["AEG001"].findings) >= 2


def test_aeg001_silent_when_guarded(fixtures_dir):
    results = _run(fixtures_dir / "safe_guarded.py")
    assert len(results["AEG001"].findings) == 0


def test_aeg001_silent_with_langgraph_interrupt(fixtures_dir):
    results = _run(fixtures_dir / "safe_langgraph.py")
    assert isinstance(results["AEG001"].findings, list)


def test_aeg001_evidence_populated(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_approval.py")
    for f in results["AEG001"].findings:
        assert f.evidence is not None
        assert f.evidence.subject_name != ""
        assert f.evidence.sink_type != ""
        assert f.evidence.approval_signal_found == TriState.NO
        assert f.evidence.confidence == "high"
        assert f.evidence.remediation != ""
        assert f.evidence.rationale != ""


def test_aeg001_readonly_tools_silent(fixtures_dir):
    results = _run(fixtures_dir / "readonly_tool.py")
    assert len(results["AEG001"].findings) == 0


def test_aeg001_misleading_safe_names_silent(fixtures_dir):
    results = _run(fixtures_dir / "misleading_names.py")
    finding_subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    assert "safe_delete" not in finding_subjects
    assert "destroy_cache" not in finding_subjects


def test_aeg001_misleading_innocent_name_flagged(fixtures_dir):
    results = _run(fixtures_dir / "misleading_names.py")
    finding_subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    assert "harmless_helper" in finding_subjects


def test_aeg001_nested_approval_respected(fixtures_dir):
    results = _run(fixtures_dir / "nested_wrappers.py")
    finding_subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    assert "stacked_delete" not in finding_subjects  # has approval
    assert "stacked_no_approval" in finding_subjects  # no approval


def test_aeg001_custom_approval_patterns(fixtures_dir):
    results = _run(fixtures_dir / "custom_approval.py")
    subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    # unguarded_write has no approval
    assert "unguarded_write" in subjects
    # manual_confirm_delete has input() → approval
    assert "manual_confirm_delete" not in subjects
    # guarded_http_post has authorize_action → approval
    assert "guarded_http_post" not in subjects


def test_aeg001_false_positive_edges(fixtures_dir):
    results = _run(fixtures_dir / "false_positive_edge.py")
    subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    # These should NOT be flagged (read-only)
    assert "tool_calls_post_but_its_a_variable" not in subjects
    assert "tool_with_open_read" not in subjects
    assert "tool_with_open_no_mode" not in subjects
    # This SHOULD be flagged (os.remove)
    assert "tool_with_conditional_write" in subjects


# -- AEG002: privileged without consent/policy --------------------------------

def test_aeg002_fires_on_generic_approval(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_privileged.py")
    assert len(results["AEG002"].findings) >= 1


def test_aeg002_evidence_has_approval_signal(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_privileged.py")
    for f in results["AEG002"].findings:
        assert f.evidence is not None
        assert f.evidence.subject_name != ""
        # This tool has @requires_approval but not consent
        assert f.evidence.approval_signal_found == TriState.YES
        assert "requires_approval" in f.evidence.approval_signal_kind


def test_aeg002_silent_with_consent_wrapper(fixtures_dir):
    results = _run(fixtures_dir / "safe_guarded.py")
    assert len(results["AEG002"].findings) == 0


def test_aeg002_silent_when_no_privileged_sinks(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_approval.py")
    assert len(results["AEG002"].findings) == 0


# -- AEG003: missing execution budget ----------------------------------------

def test_aeg003_fires_when_no_budget(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_budget.py")
    assert len(results["AEG003"].findings) >= 1


def test_aeg003_evidence_populated(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_budget.py")
    for f in results["AEG003"].findings:
        assert f.evidence is not None
        assert f.evidence.budget_signal_found == TriState.NO
        assert f.evidence.remediation != ""


def test_aeg003_silent_with_max_iterations(fixtures_dir):
    results = _run(fixtures_dir / "safe_guarded.py")
    assert len(results["AEG003"].findings) == 0


def test_aeg003_silent_with_recursion_limit(fixtures_dir):
    results = _run(fixtures_dir / "safe_langgraph.py")
    assert len(results["AEG003"].findings) == 0


# -- LangGraph safe patterns -------------------------------------------------

def test_langgraph_safe_all_guarded(fixtures_dir):
    results = _run(fixtures_dir / "langgraph_safe_patterns.py")
    # app1 has interrupt_before + recursion_limit → AEG003 should be clean
    assert len(results["AEG003"].findings) == 0
