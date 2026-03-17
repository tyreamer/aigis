"""Fixture: Budget parameter from user variable. AIGIS005 should fire."""
from agents import Agent, Runner


def run_agent(user_max_turns: int):
    agent = Agent(name="dynamic", instructions="Do stuff")
    # max_turns comes from user input — no server-side cap
    Runner.run(agent, input="go", max_turns=user_max_turns)
