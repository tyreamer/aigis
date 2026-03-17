"""OpenAI Agents SDK framework patterns.

Covers the openai-agents (agents) library:
- Agent() class as entry point
- Runner.run() / Runner.run_sync() as execution triggers
- @function_tool decorator for tool registration
- max_turns as budget control (constructor or execution time)
"""

# Tool registration: @function_tool
TOOL_DECORATORS = {"function_tool"}

# Entry points: Agent(...) creates the agent
# Note: "Agent" is ambiguous (CrewAI also uses it for role definitions).
# We use ENTRY_POINT_MODULES to disambiguate — the analyzer checks the
# import source for names that could be ambiguous.
ENTRY_POINT_NAMES = {"Agent"}

# Modules that qualify Agent as an entry point (not a role definition)
ENTRY_POINT_MODULES = {"agents", "openai.agents"}

# Budget kwargs on Agent() constructor
BUDGET_KWARGS = {"max_turns"}

# Execution-time budget patterns:
# Runner.run(agent, ..., max_turns=N) or Runner.run_sync(agent, ..., max_turns=N)
# The entry point variable is passed as the first positional argument.
EXECUTION_BUDGET_PATTERNS = [
    {
        "callers": {"Runner"},
        "methods": {"run", "run_sync", "run_streamed"},
        "entry_arg_index": 0,
        "budget_kwargs": {"max_turns"},
    },
]
