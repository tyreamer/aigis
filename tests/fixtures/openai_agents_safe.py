"""Fixture: OpenAI Agents SDK — safe patterns.

Agent with approval decorator and budget control.
"""
from agents import Agent, function_tool


def requires_approval(fn):
    """Approval wrapper."""
    return fn


@function_tool
@requires_approval
def delete_file(path: str) -> str:
    """Delete a file with approval."""
    import os
    os.remove(path)
    return f"Deleted {path}"


@function_tool
def search(query: str) -> str:
    """Search — read-only, no sinks."""
    return f"results for {query}"


# Has max_turns budget
agent = Agent(
    name="safe-agent",
    instructions="You help with files.",
    tools=[delete_file, search],
    max_turns=10,
)
