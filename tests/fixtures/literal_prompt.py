"""Fixture: System prompt as literal. AIGIS008 should NOT fire."""
from agents import Agent

agent = Agent(name="safe", instructions="You are a helpful assistant.")
