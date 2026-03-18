"""Fixture: System prompt from file. AIGIS008 should fire."""
from agents import Agent

agent = Agent(name="mutable", instructions=open("prompt.txt").read())
