"""Fixture: OpenAI Agents SDK — budget at execution time.

Agent() has no max_turns on constructor, but Runner.run() does.
AEG003 should NOT fire.
"""
from agents import Agent, Runner, function_tool


@function_tool
def search(query: str) -> str:
    """Search — no side effects."""
    return f"results for {query}"


agent = Agent(
    name="searcher",
    instructions="You search things.",
    tools=[search],
)

# Budget is here, at execution time
result = Runner.run(agent, input="find something", max_turns=10)
