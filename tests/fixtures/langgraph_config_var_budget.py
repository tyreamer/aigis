"""Fixture: LangGraph — budget via config variable reference.

compile() has no recursion_limit, but invoke() uses a config variable.
AEG003 should NOT fire.
"""
from langgraph.graph import StateGraph


def process(state):
    return state


graph = StateGraph(dict)
graph.add_node("processor", process)
app = graph.compile()

# Budget via config variable
run_config = {"recursion_limit": 25, "tags": ["test"]}
result = app.invoke({"input": "hello"}, config=run_config)
