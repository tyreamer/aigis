"""Fixture: OpenAI Agents SDK — no budget anywhere.

Agent() has no max_turns. Runner.run() also has no max_turns.
AIGIS003 SHOULD fire.
"""
from agents import Agent, Runner, function_tool


@function_tool
def search(query: str) -> str:
    """Search — no side effects."""
    return f"results for {query}"


agent = Agent(
    name="unbounded",
    instructions="You search things.",
    tools=[search],
)

# No max_turns on Runner.run either
result = Runner.run(agent, input="find something")
