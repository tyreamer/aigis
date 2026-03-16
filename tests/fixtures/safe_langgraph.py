"""Fixture: LangGraph with interrupt_before and recursion_limit."""
from langgraph.graph import StateGraph


def write_report(state):
    """Write a report to disk."""
    with open("report.txt", "w") as f:
        f.write(state["content"])
    return state


graph = StateGraph(dict)
graph.add_node("writer", write_report)
app = graph.compile(interrupt_before=["writer"], recursion_limit=25)
