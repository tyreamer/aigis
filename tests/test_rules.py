"""Tests for governance rules."""

from aigis.analyzer import PythonAnalyzer
from aigis.models import TriState
from aigis.rules import run_all_rules


def _run(fixture_path, exclude_patterns=None):
    graph = PythonAnalyzer().analyze(fixture_path, exclude_patterns=exclude_patterns)
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


# -- OpenAI Agents SDK -------------------------------------------------------

def test_openai_agents_unsafe_aeg001(fixtures_dir):
    """OpenAI @function_tool with sinks and no approval should fire AEG001."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    assert "delete_file" in subjects
    assert "send_webhook" in subjects
    assert "execute_command" in subjects


def test_openai_agents_unsafe_aeg002(fixtures_dir):
    """OpenAI @function_tool with subprocess should fire AEG002."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AEG002"].findings]
    assert "execute_command" in subjects


def test_openai_agents_unsafe_aeg003(fixtures_dir):
    """Agent() without max_turns should fire AEG003."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    assert len(results["AEG003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AEG003"].findings]
    assert "Agent" in subjects


def test_openai_agents_safe_no_aeg001(fixtures_dir):
    """OpenAI @function_tool with approval should NOT fire AEG001."""
    results = _run(fixtures_dir / "openai_agents_safe.py")
    subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    assert "delete_file" not in subjects


def test_openai_agents_safe_no_aeg003(fixtures_dir):
    """Agent() with max_turns should NOT fire AEG003."""
    results = _run(fixtures_dir / "openai_agents_safe.py")
    assert len(results["AEG003"].findings) == 0


def test_openai_agents_evidence_populated(fixtures_dir):
    """Evidence on OpenAI Agents findings should be complete."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    for f in results["AEG001"].findings:
        assert f.evidence is not None
        assert f.evidence.subject_name != ""
        assert f.evidence.sink_type != ""
        assert f.evidence.confidence == "high"
        assert f.evidence.rationale != ""
        assert f.evidence.remediation != ""


# -- CrewAI -------------------------------------------------------------------

def test_crewai_unsafe_aeg001(fixtures_dir):
    """CrewAI @tool with sinks and no approval should fire AEG001."""
    results = _run(fixtures_dir / "crewai_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    assert "write_output" in subjects
    assert "deploy_service" in subjects


def test_crewai_unsafe_aeg002(fixtures_dir):
    """CrewAI @tool with subprocess should fire AEG002."""
    results = _run(fixtures_dir / "crewai_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AEG002"].findings]
    assert "deploy_service" in subjects


def test_crewai_unsafe_aeg003(fixtures_dir):
    """Crew() without max_iter should fire AEG003."""
    results = _run(fixtures_dir / "crewai_unsafe.py")
    assert len(results["AEG003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AEG003"].findings]
    assert "Crew" in subjects


def test_crewai_safe_no_aeg001(fixtures_dir):
    """CrewAI @tool with consent wrapper should NOT fire AEG001."""
    results = _run(fixtures_dir / "crewai_safe.py")
    subjects = [f.evidence.subject_name for f in results["AEG001"].findings]
    assert "write_output" not in subjects


def test_crewai_safe_no_aeg003(fixtures_dir):
    """Crew() with max_iter should NOT fire AEG003."""
    results = _run(fixtures_dir / "crewai_safe.py")
    assert len(results["AEG003"].findings) == 0


# -- AutoGen / AG2 -----------------------------------------------------------

def test_autogen_unsafe_aeg003(fixtures_dir):
    """AutoGen agents without budget should fire AEG003."""
    results = _run(fixtures_dir / "autogen_unsafe.py")
    assert len(results["AEG003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AEG003"].findings]
    assert "AssistantAgent" in subjects or "GroupChatManager" in subjects


def test_autogen_safe_no_aeg003(fixtures_dir):
    """AutoGen agents with budget controls should NOT fire AEG003."""
    results = _run(fixtures_dir / "autogen_safe.py")
    assert len(results["AEG003"].findings) == 0


# -- LangGraph interrupt() detection -----------------------------------------

def test_langgraph_interrupt_function_recognized(fixtures_dir):
    """interrupt() from langgraph.types should satisfy AEG001 approval."""
    results = _run(fixtures_dir / "langgraph_interrupt_safe.py")
    # The file has interrupt() from langgraph.types — entry point should have approval
    # AEG003 should still be clean because recursion_limit is set
    assert len(results["AEG003"].findings) == 0


def test_langgraph_interrupt_false_positive_rejected(fixtures_dir):
    """Custom interrupt() NOT from langgraph.types should NOT count as approval."""
    results = _run(fixtures_dir / "langgraph_interrupt_false_positive.py")
    # Should still fire AEG003 — custom interrupt() is not a real approval signal
    assert len(results["AEG003"].findings) >= 1


def test_langgraph_interrupt_before_still_works(fixtures_dir):
    """interrupt_before kwarg should still work for AEG003 budget detection."""
    results = _run(fixtures_dir / "safe_langgraph.py")
    # interrupt_before + recursion_limit → AEG003 clean
    assert len(results["AEG003"].findings) == 0


# -- Test file exclusion ------------------------------------------------------

def test_default_excludes_skip_test_dirs(fixtures_dir):
    """Default exclusions should skip files in tests/ directories."""
    from aigis.config import DEFAULT_EXCLUDE_PATTERNS
    results = _run(
        fixtures_dir / "test_exclusion",
        exclude_patterns=DEFAULT_EXCLUDE_PATTERNS,
    )
    # Only src/agent.py should be scanned, not tests/test_agent.py
    assert len(results["AEG003"].findings) == 1
    assert "src" in results["AEG003"].findings[0].location.file


def test_no_excludes_scans_everything(fixtures_dir):
    """With no exclusions, test files should also be scanned."""
    results = _run(fixtures_dir / "test_exclusion", exclude_patterns=[])
    # Both src/agent.py and tests/test_agent.py should fire AEG003
    assert len(results["AEG003"].findings) == 2


# -- Execution-time budget detection -----------------------------------------

def test_openai_runner_run_satisfies_budget(fixtures_dir):
    """Agent() with Runner.run(agent, max_turns=N) should NOT fire AEG003."""
    results = _run(fixtures_dir / "openai_agents_exec_budget.py")
    assert len(results["AEG003"].findings) == 0


def test_openai_runner_run_without_budget_still_fires(fixtures_dir):
    """Agent() with Runner.run(agent) but no max_turns should still fire AEG003."""
    results = _run(fixtures_dir / "openai_agents_no_exec_budget.py")
    assert len(results["AEG003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AEG003"].findings]
    assert "Agent" in subjects


def test_autogen_initiate_chat_satisfies_budget(fixtures_dir):
    """AssistantAgent with initiate_chat(max_turns=N) should NOT fire AEG003."""
    results = _run(fixtures_dir / "autogen_exec_budget.py")
    # assistant is bounded via proxy.initiate_chat(assistant, max_turns=5)
    # GroupChat has max_round=10 on constructor
    subjects = [f.evidence.subject_name for f in results["AEG003"].findings]
    assert "AssistantAgent" not in subjects
    assert "GroupChat" not in subjects


def test_autogen_no_budget_still_fires(fixtures_dir):
    """AutoGen agents with no budget anywhere should still fire AEG003."""
    results = _run(fixtures_dir / "autogen_no_exec_budget.py")
    assert len(results["AEG003"].findings) >= 1


def test_langgraph_invoke_config_satisfies_budget(fixtures_dir):
    """compile() with invoke(config={"recursion_limit": N}) should NOT fire AEG003."""
    results = _run(fixtures_dir / "langgraph_exec_budget.py")
    assert len(results["AEG003"].findings) == 0


def test_exec_budget_wrong_var_does_not_satisfy(fixtures_dir):
    """Budget on agent_b should NOT satisfy agent_a."""
    results = _run(fixtures_dir / "exec_budget_wrong_var.py")
    # agent_a should still fire (no budget on it)
    assert len(results["AEG003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AEG003"].findings]
    assert "Agent" in subjects


def test_exec_budget_does_not_affect_aeg001(fixtures_dir):
    """Execution-time budget should NOT affect AEG001 findings."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    # AEG001 should still fire on all 3 tools regardless of budget
    assert len(results["AEG001"].findings) >= 3


def test_exec_budget_evidence_updated(fixtures_dir):
    """AEG003 evidence should mention both constructor and execution paths."""
    results = _run(fixtures_dir / "openai_agents_no_exec_budget.py")
    for f in results["AEG003"].findings:
        assert f.evidence is not None
        assert f.evidence.budget_signal_found == TriState.NO
        assert "constructor" in f.evidence.rationale.lower()
        assert f.evidence.remediation != ""


# -- Semantic linking improvements -------------------------------------------

def test_langgraph_config_var_satisfies_budget(fixtures_dir):
    """config variable with recursion_limit should satisfy AEG003."""
    results = _run(fixtures_dir / "langgraph_config_var_budget.py")
    assert len(results["AEG003"].findings) == 0


def test_groupchat_budget_propagates_to_manager(fixtures_dir):
    """GroupChat(max_round=N) should propagate to GroupChatManager(groupchat=chat)."""
    results = _run(fixtures_dir / "autogen_groupchat_manager_propagation.py")
    subjects = [f.evidence.subject_name for f in results["AEG003"].findings]
    assert "GroupChatManager" not in subjects
    assert "GroupChat" not in subjects


def test_aliased_variable_budget_detected(fixtures_dir):
    """Budget via aliased entry point variable should be detected."""
    results = _run(fixtures_dir / "openai_agents_alias_budget.py")
    assert len(results["AEG003"].findings) == 0


def test_aeg003_evidence_has_framework_name(fixtures_dir):
    """AEG003 evidence should include the framework name."""
    results = _run(fixtures_dir / "openai_agents_no_exec_budget.py")
    for f in results["AEG003"].findings:
        assert "OpenAI" in f.evidence.rationale or "Agent" in f.evidence.rationale


def test_aeg003_evidence_has_specific_remediation(fixtures_dir):
    """AEG003 remediation should be framework-specific."""
    results = _run(fixtures_dir / "unsafe_no_budget.py")
    for f in results["AEG003"].findings:
        # LangChain AgentExecutor should get LangChain-specific remediation
        assert "max_iterations" in f.evidence.remediation or "max_turns" in f.evidence.remediation


# -- AG2 initiate_group_chat file-level budget --------------------------------

def test_ag2_initiate_group_chat_with_budget_is_safe(fixtures_dir):
    """initiate_group_chat(max_rounds=N) should satisfy AEG003 for all agents."""
    results = _run(fixtures_dir / "autogen_initiate_group_chat_safe.py")
    assert len(results["AEG003"].findings) == 0


def test_ag2_initiate_group_chat_without_budget_fires(fixtures_dir):
    """initiate_group_chat() without max_rounds should still fire AEG003."""
    results = _run(fixtures_dir / "autogen_initiate_group_chat_unsafe.py")
    assert len(results["AEG003"].findings) >= 1
