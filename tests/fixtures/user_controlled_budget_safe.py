"""Fixture: Budget parameter as constant or capped. AIGIS005 should NOT fire."""
from agents import Agent, Runner


agent = Agent(name="safe", instructions="Do stuff")

# Constant — safe
Runner.run(agent, input="go", max_turns=10)
