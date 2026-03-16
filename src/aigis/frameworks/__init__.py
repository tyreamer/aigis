"""Merged framework patterns for analyzer consumption.

To add a new framework, create a module in this package and merge its
patterns into the sets below.  The analyzer and rules import from here —
no need to touch rule logic.
"""

from . import custom, langchain, langgraph

# -- Tool detection ----------------------------------------------------------
TOOL_DECORATORS = langchain.TOOL_DECORATORS
TOOL_REGISTRATION_METHODS = langgraph.TOOL_REGISTRATION_METHODS
TOOL_REGISTRATION_NAME_PATTERNS = custom.TOOL_REGISTRATION_NAME_PATTERNS

# -- Entry points ------------------------------------------------------------
ENTRY_POINT_NAMES = langchain.ENTRY_POINT_NAMES
ENTRY_POINT_METHODS = langgraph.ENTRY_POINT_METHODS
GRAPH_CONSTRUCTORS = langgraph.GRAPH_CONSTRUCTORS
COMPILE_FALSE_POSITIVES = langgraph.COMPILE_FALSE_POSITIVES

# -- Approval ----------------------------------------------------------------
APPROVAL_DECORATOR_PATTERNS = custom.APPROVAL_DECORATOR_PATTERNS
CONSENT_DECORATOR_PATTERNS = custom.CONSENT_DECORATOR_PATTERNS
APPROVAL_COMPILE_KWARGS = langgraph.APPROVAL_COMPILE_KWARGS

# -- Budget ------------------------------------------------------------------
BUDGET_KWARGS = langchain.BUDGET_KWARGS | langgraph.BUDGET_KWARGS
