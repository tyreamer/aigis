"""LangGraph framework patterns."""

TOOL_REGISTRATION_METHODS = {"add_node"}

ENTRY_POINT_METHODS = {"compile"}

# Constructor names that produce graph objects (whose .compile() is an entry point)
GRAPH_CONSTRUCTORS = {"StateGraph", "MessageGraph", "Graph"}

APPROVAL_COMPILE_KWARGS = {"interrupt_before"}

BUDGET_KWARGS = {"recursion_limit"}

# Known modules/names whose .compile() is NOT a graph entry point
COMPILE_FALSE_POSITIVES = {"re", "pattern", "regex", "jinja2", "template", "schema"}

# Execution-time budget patterns:
# app.invoke(input, config={"recursion_limit": 25})
# app.stream(input, config={"recursion_limit": 25})
EXECUTION_BUDGET_PATTERNS = [
    {
        "methods": {"invoke", "ainvoke", "stream", "astream"},
        "receiver_is_entry": True,
        "budget_in_config": {"recursion_limit"},
    },
]
