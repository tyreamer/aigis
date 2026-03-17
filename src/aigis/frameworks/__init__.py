"""Merged framework patterns for analyzer consumption.

To add a new framework, create a module in this package and merge its
patterns into the sets below.  The analyzer and rules import from here —
no need to touch rule logic.
"""

from . import autogen, crewai, custom, langchain, langgraph, openai_agents

# -- Tool detection ----------------------------------------------------------
TOOL_DECORATORS = langchain.TOOL_DECORATORS | openai_agents.TOOL_DECORATORS
TOOL_REGISTRATION_METHODS = (
    langgraph.TOOL_REGISTRATION_METHODS | autogen.TOOL_REGISTRATION_METHODS
)
TOOL_REGISTRATION_NAME_PATTERNS = custom.TOOL_REGISTRATION_NAME_PATTERNS

# -- Entry points ------------------------------------------------------------
ENTRY_POINT_NAMES = (
    langchain.ENTRY_POINT_NAMES
    | openai_agents.ENTRY_POINT_NAMES
    | crewai.ENTRY_POINT_NAMES
    | autogen.ENTRY_POINT_NAMES
)

# Names that require import-source disambiguation (e.g. "Agent" from "agents"
# vs "Agent" from "crewai").  Maps name -> set of qualifying module prefixes.
ENTRY_POINT_QUALIFIED: dict[str, set[str]] = {}
for _name in openai_agents.ENTRY_POINT_NAMES:
    ENTRY_POINT_QUALIFIED[_name] = openai_agents.ENTRY_POINT_MODULES
ENTRY_POINT_METHODS = langgraph.ENTRY_POINT_METHODS
GRAPH_CONSTRUCTORS = langgraph.GRAPH_CONSTRUCTORS
COMPILE_FALSE_POSITIVES = langgraph.COMPILE_FALSE_POSITIVES

# -- Approval ----------------------------------------------------------------
APPROVAL_DECORATOR_PATTERNS = custom.APPROVAL_DECORATOR_PATTERNS
CONSENT_DECORATOR_PATTERNS = custom.CONSENT_DECORATOR_PATTERNS
APPROVAL_COMPILE_KWARGS = langgraph.APPROVAL_COMPILE_KWARGS

# -- Budget ------------------------------------------------------------------
BUDGET_KWARGS = (
    langchain.BUDGET_KWARGS
    | langgraph.BUDGET_KWARGS
    | openai_agents.BUDGET_KWARGS
    | crewai.BUDGET_KWARGS
    | autogen.BUDGET_KWARGS
)

# -- Execution-time budget patterns ------------------------------------------
# Each pattern dict describes a call shape that carries a budget control
# applied at execution time rather than at construction time.
EXECUTION_BUDGET_PATTERNS: list[dict] = (
    openai_agents.EXECUTION_BUDGET_PATTERNS
    + autogen.EXECUTION_BUDGET_PATTERNS
    + crewai.EXECUTION_BUDGET_PATTERNS
    + langgraph.EXECUTION_BUDGET_PATTERNS
)

# -- File-level budget functions ---------------------------------------------
# Standalone functions that, when called with a budget kwarg, apply the budget
# to all entry points in the file.  Maps function_name -> set of budget kwargs.
FILE_LEVEL_BUDGET_FUNCTIONS: dict[str, set[str]] = {
    **autogen.FILE_LEVEL_BUDGET_FUNCTIONS,
}
