"""Fixture: LangGraph with interrupt() function — safe HITL pattern.

Uses interrupt() from langgraph.types for human-in-the-loop approval.
This should be recognized as an approval signal and satisfy AIGIS001.
"""
from langgraph.graph import StateGraph
from langgraph.types import interrupt


def handle_request(state):
    """Ask user for approval via interrupt."""
    response = interrupt([{"question": "Approve this action?"}])
    return {"approved": response[0]}


def write_report(state):
    """Write a report after approval."""
    with open("report.txt", "w") as f:
        f.write(state["content"])
    return state


graph = StateGraph(dict)
graph.add_node("approval", handle_request)
graph.add_node("writer", write_report)
app = graph.compile(recursion_limit=25)
