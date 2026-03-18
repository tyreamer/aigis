"""Fixture: Agent with static tool list. AIGIS015 should NOT fire."""
from agents import Agent, function_tool

@function_tool
def search(q: str) -> str:
    return q

agent = Agent(name="static", instructions="Do stuff", tools=[search])
