"""Tests for the Python AST analyzer."""

from aigis.analyzer import PythonAnalyzer
from aigis.models import EdgeKind, NodeKind


def test_detects_tool_decorated_functions(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "unsafe_no_approval.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    names = {t.name for t in tools}
    assert "delete_user_data" in names
    assert "send_notification" in names


def test_detects_sinks_in_tools(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "unsafe_no_approval.py")
    sinks = graph.nodes_by_kind(NodeKind.SINK)
    sink_names = {s.name for s in sinks}
    assert "os.remove" in sink_names
    assert "requests.post" in sink_names


def test_detects_approval_decorator(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_guarded.py")
    gates = graph.nodes_by_kind(NodeKind.APPROVAL_GATE)
    assert len(gates) >= 2


def test_detects_entry_point(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "unsafe_no_budget.py")
    eps = graph.nodes_by_kind(NodeKind.ENTRY_POINT)
    assert len(eps) == 1
    assert eps[0].name == "AgentExecutor"


def test_detects_budget_control(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_guarded.py")
    budgets = graph.nodes_by_kind(NodeKind.BUDGET_CONTROL)
    assert len(budgets) >= 1
    assert budgets[0].name == "max_iterations"


def test_no_budget_when_missing(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "unsafe_no_budget.py")
    budgets = graph.nodes_by_kind(NodeKind.BUDGET_CONTROL)
    assert len(budgets) == 0


def test_langgraph_add_node_registers_tool(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_langgraph.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    assert any(t.name == "write_report" for t in tools)


def test_langgraph_compile_is_entry_point(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_langgraph.py")
    eps = graph.nodes_by_kind(NodeKind.ENTRY_POINT)
    assert len(eps) >= 1


def test_langgraph_interrupt_before_is_approval(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_langgraph.py")
    gates = graph.nodes_by_kind(NodeKind.APPROVAL_GATE)
    assert any(g.name == "interrupt_before" for g in gates)


def test_langgraph_recursion_limit_is_budget(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_langgraph.py")
    budgets = graph.nodes_by_kind(NodeKind.BUDGET_CONTROL)
    assert any(b.name == "recursion_limit" for b in budgets)


def test_privileged_sink_metadata(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "unsafe_privileged.py")
    sinks = graph.nodes_by_kind(NodeKind.SINK)
    priv = [s for s in sinks if s.metadata.get("privileged")]
    assert len(priv) >= 1
    assert "subprocess" in priv[0].name


def test_open_write_detected_as_sink(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_langgraph.py")
    sinks = graph.nodes_by_kind(NodeKind.SINK)
    assert any("open" in s.name for s in sinks)


def test_edges_connect_tool_to_sink(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "unsafe_no_approval.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    for tool in tools:
        call_edges = graph.edges_from(tool.id, EdgeKind.CALLS)
        assert len(call_edges) > 0, f"Tool {tool.name} should have CALLS edges to sinks"


# -- Read-only tools should produce no sinks --------------------------------

def test_readonly_tools_have_no_sinks(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "readonly_tool.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    assert len(tools) == 4
    sinks = graph.nodes_by_kind(NodeKind.SINK)
    assert len(sinks) == 0


# -- Misleading names -------------------------------------------------------

def test_misleading_safe_names_no_sinks(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "misleading_names.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    # safe_delete and destroy_cache have no real side effects
    safe_tools = [t for t in tools if t.name in ("safe_delete", "destroy_cache")]
    for t in safe_tools:
        edges = graph.edges_from(t.id, EdgeKind.CALLS)
        assert len(edges) == 0, f"{t.name} should have no sink edges"


def test_misleading_innocent_name_has_sink(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "misleading_names.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    bad = [t for t in tools if t.name == "harmless_helper"]
    assert len(bad) == 1
    edges = graph.edges_from(bad[0].id, EdgeKind.CALLS)
    assert len(edges) == 1  # os.remove


# -- Custom approval patterns -----------------------------------------------

def test_custom_approval_body_call(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "custom_approval.py")
    gates = graph.nodes_by_kind(NodeKind.APPROVAL_GATE)
    gate_names = [g.name for g in gates]
    # manual_confirm_delete has input() and guarded_http_post has authorize_action
    assert any("manual_confirm_delete" in n for n in gate_names)
    assert any("guarded_http_post" in n for n in gate_names)


# -- Nested wrappers --------------------------------------------------------

def test_nested_approval_detected(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "nested_wrappers.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    stacked = [t for t in tools if t.name == "stacked_delete"]
    assert len(stacked) == 1
    wraps = graph.edges_to(stacked[0].id, EdgeKind.WRAPS)
    assert len(wraps) >= 1  # requires_approval is detected


def test_nested_no_approval_not_detected(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "nested_wrappers.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    no_approval = [t for t in tools if t.name == "stacked_no_approval"]
    assert len(no_approval) == 1
    wraps = graph.edges_to(no_approval[0].id, EdgeKind.WRAPS)
    assert len(wraps) == 0


# -- False positive edge cases ----------------------------------------------

def test_open_read_not_flagged(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "false_positive_edge.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    read_tool = [t for t in tools if t.name == "tool_with_open_read"]
    assert len(read_tool) == 1
    edges = graph.edges_from(read_tool[0].id, EdgeKind.CALLS)
    assert len(edges) == 0


def test_open_no_mode_not_flagged(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "false_positive_edge.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    no_mode = [t for t in tools if t.name == "tool_with_open_no_mode"]
    assert len(no_mode) == 1
    edges = graph.edges_from(no_mode[0].id, EdgeKind.CALLS)
    assert len(edges) == 0


def test_variable_name_not_confused_with_call(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "false_positive_edge.py")
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    var_tool = [t for t in tools if t.name == "tool_calls_post_but_its_a_variable"]
    assert len(var_tool) == 1
    edges = graph.edges_from(var_tool[0].id, EdgeKind.CALLS)
    assert len(edges) == 0


# -- Approval gate stores source info ---------------------------------------

def test_approval_gate_has_source_metadata(fixtures_dir):
    graph = PythonAnalyzer().analyze(fixtures_dir / "safe_guarded.py")
    gates = graph.nodes_by_kind(NodeKind.APPROVAL_GATE)
    for g in gates:
        assert "source" in g.metadata
        assert g.metadata["source"] != ""
