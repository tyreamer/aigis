"""LangGraph framework patterns."""

TOOL_REGISTRATION_METHODS = {"add_node"}

ENTRY_POINT_METHODS = {"compile"}

# Constructor names that produce graph objects (whose .compile() is an entry point)
GRAPH_CONSTRUCTORS = {"StateGraph", "MessageGraph", "Graph"}

APPROVAL_COMPILE_KWARGS = {"interrupt_before"}

BUDGET_KWARGS = {"recursion_limit"}

# Known modules/names whose .compile() is NOT a graph entry point
COMPILE_FALSE_POSITIVES = {"re", "pattern", "regex", "jinja2", "template", "schema"}
