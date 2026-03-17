"""Fixture: test file that should be excluded by default.

Contains an AgentExecutor without budget — but in a test directory.
"""
from langchain.agents import AgentExecutor

agent = AgentExecutor(agent=None, tools=[])
