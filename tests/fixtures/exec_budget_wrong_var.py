"""Fixture: budget on a different variable should NOT satisfy another entry point.

agent_a has no budget. Runner.run is called with agent_b and max_turns.
AEG003 SHOULD still fire on agent_a.
"""
from agents import Agent, Runner

agent_a = Agent(name="unbounded", instructions="Do stuff")
agent_b = Agent(name="bounded", instructions="Do other stuff")

# Budget applies to agent_b, NOT agent_a
Runner.run(agent_b, input="hello", max_turns=10)
