"""Fixture: production code that should NOT be excluded.

Contains an AgentExecutor without budget — in production code.
"""
from langchain.agents import AgentExecutor

agent = AgentExecutor(agent=None, tools=[])
