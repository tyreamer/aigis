"""Fixture: Agent with dynamic tool list. AIGIS015 should fire."""
from agents import Agent

def get_tools():
    return []

agent = Agent(name="dynamic", instructions="Do stuff", tools=get_tools())
