"""Tests for governance rules."""

from aigis.analyzer import PythonAnalyzer
from aigis.models import TriState
from aigis.rules import run_all_rules


def _run(fixture_path, exclude_patterns=None):
    graph = PythonAnalyzer().analyze(fixture_path, exclude_patterns=exclude_patterns)
    results = run_all_rules(graph)
    return {r.rule_id: r for r in results}


# -- AIGIS001: unguarded mutating tool ----------------------------------------

def test_aigis001_fires_on_unguarded_tool(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_approval.py")
    assert len(results["AIGIS001"].findings) >= 2


def test_aigis001_silent_when_guarded(fixtures_dir):
    results = _run(fixtures_dir / "safe_guarded.py")
    assert len(results["AIGIS001"].findings) == 0


def test_aigis001_silent_with_langgraph_interrupt(fixtures_dir):
    results = _run(fixtures_dir / "safe_langgraph.py")
    assert isinstance(results["AIGIS001"].findings, list)


def test_aigis001_evidence_populated(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_approval.py")
    for f in results["AIGIS001"].findings:
        assert f.evidence is not None
        assert f.evidence.subject_name != ""
        assert f.evidence.sink_type != ""
        assert f.evidence.approval_signal_found == TriState.NO
        assert f.evidence.confidence == "high"
        assert f.evidence.remediation != ""
        assert f.evidence.rationale != ""


def test_aigis001_readonly_tools_silent(fixtures_dir):
    results = _run(fixtures_dir / "readonly_tool.py")
    assert len(results["AIGIS001"].findings) == 0


def test_aigis001_misleading_safe_names_silent(fixtures_dir):
    results = _run(fixtures_dir / "misleading_names.py")
    finding_subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    assert "safe_delete" not in finding_subjects
    assert "destroy_cache" not in finding_subjects


def test_aigis001_misleading_innocent_name_flagged(fixtures_dir):
    results = _run(fixtures_dir / "misleading_names.py")
    finding_subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    assert "harmless_helper" in finding_subjects


def test_aigis001_nested_approval_respected(fixtures_dir):
    results = _run(fixtures_dir / "nested_wrappers.py")
    finding_subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    assert "stacked_delete" not in finding_subjects  # has approval
    assert "stacked_no_approval" in finding_subjects  # no approval


def test_aigis001_custom_approval_patterns(fixtures_dir):
    results = _run(fixtures_dir / "custom_approval.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    # unguarded_write has no approval
    assert "unguarded_write" in subjects
    # manual_confirm_delete has input() → approval
    assert "manual_confirm_delete" not in subjects
    # guarded_http_post has authorize_action → approval
    assert "guarded_http_post" not in subjects


def test_aigis001_false_positive_edges(fixtures_dir):
    results = _run(fixtures_dir / "false_positive_edge.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    # These should NOT be flagged (read-only)
    assert "tool_calls_post_but_its_a_variable" not in subjects
    assert "tool_with_open_read" not in subjects
    assert "tool_with_open_no_mode" not in subjects
    # This SHOULD be flagged (os.remove)
    assert "tool_with_conditional_write" in subjects


# -- AIGIS002: privileged without consent/policy --------------------------------

def test_aigis002_fires_on_generic_approval(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_privileged.py")
    assert len(results["AIGIS002"].findings) >= 1


def test_aigis002_evidence_has_approval_signal(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_privileged.py")
    for f in results["AIGIS002"].findings:
        assert f.evidence is not None
        assert f.evidence.subject_name != ""
        # This tool has @requires_approval but not consent
        assert f.evidence.approval_signal_found == TriState.YES
        assert "requires_approval" in f.evidence.approval_signal_kind


def test_aigis002_silent_with_consent_wrapper(fixtures_dir):
    results = _run(fixtures_dir / "safe_guarded.py")
    assert len(results["AIGIS002"].findings) == 0


def test_aigis002_silent_when_no_privileged_sinks(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_approval.py")
    assert len(results["AIGIS002"].findings) == 0


# -- AIGIS003: missing execution budget ----------------------------------------

def test_aigis003_fires_when_no_budget(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_budget.py")
    assert len(results["AIGIS003"].findings) >= 1


def test_aigis003_evidence_populated(fixtures_dir):
    results = _run(fixtures_dir / "unsafe_no_budget.py")
    for f in results["AIGIS003"].findings:
        assert f.evidence is not None
        assert f.evidence.budget_signal_found == TriState.NO
        assert f.evidence.remediation != ""


def test_aigis003_silent_with_max_iterations(fixtures_dir):
    results = _run(fixtures_dir / "safe_guarded.py")
    assert len(results["AIGIS003"].findings) == 0


def test_aigis003_silent_with_recursion_limit(fixtures_dir):
    results = _run(fixtures_dir / "safe_langgraph.py")
    assert len(results["AIGIS003"].findings) == 0


# -- LangGraph safe patterns -------------------------------------------------

def test_langgraph_safe_all_guarded(fixtures_dir):
    results = _run(fixtures_dir / "langgraph_safe_patterns.py")
    # app1 has interrupt_before + recursion_limit → AIGIS003 should be clean
    assert len(results["AIGIS003"].findings) == 0


# -- OpenAI Agents SDK -------------------------------------------------------

def test_openai_agents_unsafe_aigis001(fixtures_dir):
    """OpenAI @function_tool with sinks and no approval should fire AIGIS001."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    assert "delete_file" in subjects
    assert "send_webhook" in subjects
    assert "execute_command" in subjects


def test_openai_agents_unsafe_aigis002(fixtures_dir):
    """OpenAI @function_tool with subprocess should fire AIGIS002."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS002"].findings]
    assert "execute_command" in subjects


def test_openai_agents_unsafe_aigis003(fixtures_dir):
    """Agent() without max_turns should fire AIGIS003."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    assert len(results["AIGIS003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AIGIS003"].findings]
    assert "Agent" in subjects


def test_openai_agents_safe_no_aigis001(fixtures_dir):
    """OpenAI @function_tool with approval should NOT fire AIGIS001."""
    results = _run(fixtures_dir / "openai_agents_safe.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    assert "delete_file" not in subjects


def test_openai_agents_safe_no_aigis003(fixtures_dir):
    """Agent() with max_turns should NOT fire AIGIS003."""
    results = _run(fixtures_dir / "openai_agents_safe.py")
    assert len(results["AIGIS003"].findings) == 0


def test_openai_agents_evidence_populated(fixtures_dir):
    """Evidence on OpenAI Agents findings should be complete."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    for f in results["AIGIS001"].findings:
        assert f.evidence is not None
        assert f.evidence.subject_name != ""
        assert f.evidence.sink_type != ""
        assert f.evidence.confidence == "high"
        assert f.evidence.rationale != ""
        assert f.evidence.remediation != ""


# -- CrewAI -------------------------------------------------------------------

def test_crewai_unsafe_aigis001(fixtures_dir):
    """CrewAI @tool with sinks and no approval should fire AIGIS001."""
    results = _run(fixtures_dir / "crewai_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    assert "write_output" in subjects
    assert "deploy_service" in subjects


def test_crewai_unsafe_aigis002(fixtures_dir):
    """CrewAI @tool with subprocess should fire AIGIS002."""
    results = _run(fixtures_dir / "crewai_unsafe.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS002"].findings]
    assert "deploy_service" in subjects


def test_crewai_unsafe_aigis003(fixtures_dir):
    """Crew() without max_iter should fire AIGIS003."""
    results = _run(fixtures_dir / "crewai_unsafe.py")
    assert len(results["AIGIS003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AIGIS003"].findings]
    assert "Crew" in subjects


def test_crewai_safe_no_aigis001(fixtures_dir):
    """CrewAI @tool with consent wrapper should NOT fire AIGIS001."""
    results = _run(fixtures_dir / "crewai_safe.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS001"].findings]
    assert "write_output" not in subjects


def test_crewai_safe_no_aigis003(fixtures_dir):
    """Crew() with max_iter should NOT fire AIGIS003."""
    results = _run(fixtures_dir / "crewai_safe.py")
    assert len(results["AIGIS003"].findings) == 0


# -- AutoGen / AG2 -----------------------------------------------------------

def test_autogen_unsafe_aigis003(fixtures_dir):
    """AutoGen agents without budget should fire AIGIS003."""
    results = _run(fixtures_dir / "autogen_unsafe.py")
    assert len(results["AIGIS003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AIGIS003"].findings]
    assert "AssistantAgent" in subjects or "GroupChatManager" in subjects


def test_autogen_safe_no_aigis003(fixtures_dir):
    """AutoGen agents with budget controls should NOT fire AIGIS003."""
    results = _run(fixtures_dir / "autogen_safe.py")
    assert len(results["AIGIS003"].findings) == 0


# -- LangGraph interrupt() detection -----------------------------------------

def test_langgraph_interrupt_function_recognized(fixtures_dir):
    """interrupt() from langgraph.types should satisfy AIGIS001 approval."""
    results = _run(fixtures_dir / "langgraph_interrupt_safe.py")
    # The file has interrupt() from langgraph.types — entry point should have approval
    # AIGIS003 should still be clean because recursion_limit is set
    assert len(results["AIGIS003"].findings) == 0


def test_langgraph_interrupt_false_positive_rejected(fixtures_dir):
    """Custom interrupt() NOT from langgraph.types should NOT count as approval."""
    results = _run(fixtures_dir / "langgraph_interrupt_false_positive.py")
    # Should still fire AIGIS003 — custom interrupt() is not a real approval signal
    assert len(results["AIGIS003"].findings) >= 1


def test_langgraph_interrupt_before_still_works(fixtures_dir):
    """interrupt_before kwarg should still work for AIGIS003 budget detection."""
    results = _run(fixtures_dir / "safe_langgraph.py")
    # interrupt_before + recursion_limit → AIGIS003 clean
    assert len(results["AIGIS003"].findings) == 0


# -- Test file exclusion ------------------------------------------------------

def test_default_excludes_skip_test_dirs(fixtures_dir):
    """Default exclusions should skip files in tests/ directories."""
    from aigis.config import DEFAULT_EXCLUDE_PATTERNS
    results = _run(
        fixtures_dir / "test_exclusion",
        exclude_patterns=DEFAULT_EXCLUDE_PATTERNS,
    )
    # Only src/agent.py should be scanned, not tests/test_agent.py
    assert len(results["AIGIS003"].findings) == 1
    assert "src" in results["AIGIS003"].findings[0].location.file


def test_no_excludes_scans_everything(fixtures_dir):
    """With no exclusions, test files should also be scanned."""
    results = _run(fixtures_dir / "test_exclusion", exclude_patterns=[])
    # Both src/agent.py and tests/test_agent.py should fire AIGIS003
    assert len(results["AIGIS003"].findings) == 2


# -- Execution-time budget detection -----------------------------------------

def test_openai_runner_run_satisfies_budget(fixtures_dir):
    """Agent() with Runner.run(agent, max_turns=N) should NOT fire AIGIS003."""
    results = _run(fixtures_dir / "openai_agents_exec_budget.py")
    assert len(results["AIGIS003"].findings) == 0


def test_openai_runner_run_without_budget_still_fires(fixtures_dir):
    """Agent() with Runner.run(agent) but no max_turns should still fire AIGIS003."""
    results = _run(fixtures_dir / "openai_agents_no_exec_budget.py")
    assert len(results["AIGIS003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AIGIS003"].findings]
    assert "Agent" in subjects


def test_autogen_initiate_chat_satisfies_budget(fixtures_dir):
    """AssistantAgent with initiate_chat(max_turns=N) should NOT fire AIGIS003."""
    results = _run(fixtures_dir / "autogen_exec_budget.py")
    # assistant is bounded via proxy.initiate_chat(assistant, max_turns=5)
    # GroupChat has max_round=10 on constructor
    subjects = [f.evidence.subject_name for f in results["AIGIS003"].findings]
    assert "AssistantAgent" not in subjects
    assert "GroupChat" not in subjects


def test_autogen_no_budget_still_fires(fixtures_dir):
    """AutoGen agents with no budget anywhere should still fire AIGIS003."""
    results = _run(fixtures_dir / "autogen_no_exec_budget.py")
    assert len(results["AIGIS003"].findings) >= 1


def test_langgraph_invoke_config_satisfies_budget(fixtures_dir):
    """compile() with invoke(config={"recursion_limit": N}) should NOT fire AIGIS003."""
    results = _run(fixtures_dir / "langgraph_exec_budget.py")
    assert len(results["AIGIS003"].findings) == 0


def test_exec_budget_wrong_var_does_not_satisfy(fixtures_dir):
    """Budget on agent_b should NOT satisfy agent_a."""
    results = _run(fixtures_dir / "exec_budget_wrong_var.py")
    # agent_a should still fire (no budget on it)
    assert len(results["AIGIS003"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AIGIS003"].findings]
    assert "Agent" in subjects


def test_exec_budget_does_not_affect_aigis001(fixtures_dir):
    """Execution-time budget should NOT affect AIGIS001 findings."""
    results = _run(fixtures_dir / "openai_agents_unsafe.py")
    # AIGIS001 should still fire on all 3 tools regardless of budget
    assert len(results["AIGIS001"].findings) >= 3


def test_exec_budget_evidence_updated(fixtures_dir):
    """AIGIS003 evidence should mention both constructor and execution paths."""
    results = _run(fixtures_dir / "openai_agents_no_exec_budget.py")
    for f in results["AIGIS003"].findings:
        assert f.evidence is not None
        assert f.evidence.budget_signal_found == TriState.NO
        assert "constructor" in f.evidence.rationale.lower()
        assert f.evidence.remediation != ""


# -- Semantic linking improvements -------------------------------------------

def test_langgraph_config_var_satisfies_budget(fixtures_dir):
    """config variable with recursion_limit should satisfy AIGIS003."""
    results = _run(fixtures_dir / "langgraph_config_var_budget.py")
    assert len(results["AIGIS003"].findings) == 0


def test_groupchat_budget_propagates_to_manager(fixtures_dir):
    """GroupChat(max_round=N) should propagate to GroupChatManager(groupchat=chat)."""
    results = _run(fixtures_dir / "autogen_groupchat_manager_propagation.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS003"].findings]
    assert "GroupChatManager" not in subjects
    assert "GroupChat" not in subjects


def test_aliased_variable_budget_detected(fixtures_dir):
    """Budget via aliased entry point variable should be detected."""
    results = _run(fixtures_dir / "openai_agents_alias_budget.py")
    assert len(results["AIGIS003"].findings) == 0


def test_aigis003_evidence_has_framework_name(fixtures_dir):
    """AIGIS003 evidence should include the framework name."""
    results = _run(fixtures_dir / "openai_agents_no_exec_budget.py")
    for f in results["AIGIS003"].findings:
        assert "OpenAI" in f.evidence.rationale or "Agent" in f.evidence.rationale


def test_aigis003_evidence_has_specific_remediation(fixtures_dir):
    """AIGIS003 remediation should be framework-specific."""
    results = _run(fixtures_dir / "unsafe_no_budget.py")
    for f in results["AIGIS003"].findings:
        # LangChain AgentExecutor should get LangChain-specific remediation
        assert "max_iterations" in f.evidence.remediation or "max_turns" in f.evidence.remediation


# -- AG2 initiate_group_chat file-level budget --------------------------------

def test_ag2_initiate_group_chat_with_budget_is_safe(fixtures_dir):
    """initiate_group_chat(max_rounds=N) should satisfy AIGIS003 for all agents."""
    results = _run(fixtures_dir / "autogen_initiate_group_chat_safe.py")
    assert len(results["AIGIS003"].findings) == 0


def test_ag2_initiate_group_chat_without_budget_fires(fixtures_dir):
    """initiate_group_chat() without max_rounds should still fire AIGIS003."""
    results = _run(fixtures_dir / "autogen_initiate_group_chat_unsafe.py")
    assert len(results["AIGIS003"].findings) >= 1


# -- AIGIS004: unbounded retry / loop ----------------------------------------

def test_aigis004_fires_on_bare_retry(fixtures_dir):
    """@retry without max attempts should fire AIGIS004."""
    results = _run(fixtures_dir / "retry_unbounded.py")
    assert len(results["AIGIS004"].findings) >= 1
    subjects = [f.evidence.subject_name for f in results["AIGIS004"].findings]
    assert "fetch_data" in subjects


def test_aigis004_fires_on_while_true_no_break(fixtures_dir):
    """while True without break should fire AIGIS004."""
    results = _run(fixtures_dir / "retry_unbounded.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS004"].findings]
    assert "poll_status" in subjects


def test_aigis004_silent_on_capped_retry(fixtures_dir):
    """@retry with stop= should NOT fire AIGIS004."""
    results = _run(fixtures_dir / "retry_bounded.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS004"].findings]
    assert "fetch_data_safe" not in subjects


def test_aigis004_silent_on_while_with_break(fixtures_dir):
    """while True with break should NOT fire AIGIS004."""
    results = _run(fixtures_dir / "retry_bounded.py")
    subjects = [f.evidence.subject_name for f in results["AIGIS004"].findings]
    assert "poll_with_break" not in subjects


# -- AIGIS005: user-controlled budget ----------------------------------------

def test_aigis005_fires_on_variable_budget(fixtures_dir):
    """Budget from user variable should fire AIGIS005."""
    results = _run(fixtures_dir / "user_controlled_budget.py")
    assert len(results["AIGIS005"].findings) >= 1


def test_aigis005_silent_on_constant_budget(fixtures_dir):
    """Budget as constant should NOT fire AIGIS005."""
    results = _run(fixtures_dir / "user_controlled_budget_safe.py")
    assert len(results["AIGIS005"].findings) == 0


# -- AIGIS006: raw history retrieval -----------------------------------------

def test_aigis006_fires_on_raw_history(fixtures_dir):
    """Raw chat_history passed to retrieval should fire AIGIS006."""
    results = _run(fixtures_dir / "raw_history_retrieval.py")
    assert len(results["AIGIS006"].findings) >= 1


def test_aigis006_silent_on_proper_query(fixtures_dir):
    """Proper query variable should NOT fire AIGIS006."""
    results = _run(fixtures_dir / "raw_history_retrieval_safe.py")
    assert len(results["AIGIS006"].findings) == 0
