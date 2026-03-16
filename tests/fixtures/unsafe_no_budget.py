"""Fixture: agent entry point with NO execution budget."""
from langchain.tools import tool
from langchain.agents import AgentExecutor


@tool
def search_web(query: str):
    """Search the web — read-only, no side effects."""
    return f"results for {query}"


# No max_iterations, no timeout — unbounded execution
agent = AgentExecutor(agent=None, tools=[search_web])
