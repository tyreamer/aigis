"""Fixture: LangGraph — budget at execution time via config.

compile() has no recursion_limit, but invoke() passes it in config.
AEG003 should NOT fire.
"""
from langgraph.graph import StateGraph


def process(state):
    return state


graph = StateGraph(dict)
graph.add_node("processor", process)
app = graph.compile()

# Budget at execution time via config dict
result = app.invoke({"input": "hello"}, config={"recursion_limit": 25})
