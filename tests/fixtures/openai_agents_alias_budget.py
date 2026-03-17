"""Fixture: OpenAI Agents SDK — budget via aliased variable.

agent is aliased to 'a', then Runner.run(a, max_turns=5).
AEG003 should NOT fire.
"""
from agents import Agent, Runner

agent = Agent(name="aliased", instructions="Do stuff")

# Alias the agent variable
a = agent

# Budget on the aliased variable
Runner.run(a, input="hello", max_turns=5)
