"""Example: Unbounded agent execution without budget.

This agent has tools that can mutate the filesystem, but there is no
limit on how many turns/iterations the agent can take. Aigis flags
this as AEG003 (missing execution budget).

Run:  aeg scan examples/unbounded_agent.py
"""
from agents import Agent, Runner, function_tool


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    with open(path, "w") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {path}"


agent = Agent(
    name="file-writer",
    instructions="You write files as requested.",
    tools=[write_file],
)

# No max_turns — the agent can loop indefinitely
result = Runner.run(agent, input="Create 100 config files")
