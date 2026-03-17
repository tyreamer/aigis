"""CrewAI framework patterns.

Covers the crewai library:
- Crew() as entry point (orchestrates agents/tasks)
- @tool decorator (shared with LangChain, already in langchain.py)
- max_iter as budget control on Crew or Task
"""

# Tool detection: CrewAI uses @tool from crewai.tools — same name as LangChain
# Already covered by langchain.TOOL_DECORATORS = {"tool"}

# Entry points: Crew(...) orchestrates execution
ENTRY_POINT_NAMES = {"Crew"}

# Budget kwargs
BUDGET_KWARGS = {"max_iter", "max_rpm", "max_execution_time"}

# Execution-time budget patterns:
# crew.kickoff() doesn't carry budget kwargs in practice, so no patterns here.
# CrewAI budgets are constructor-time only.
EXECUTION_BUDGET_PATTERNS = []
