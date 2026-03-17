"""Fixture: Function named 'interrupt' that is NOT from langgraph.types.

Should NOT be treated as an approval signal. This tests that Aigis
only recognizes interrupt() when imported from langgraph.types.
"""
from langgraph.graph import StateGraph


def interrupt(message):
    """Custom function named interrupt — not from langgraph.types."""
    print(f"Interrupting: {message}")


def write_data(state):
    """Write data to disk."""
    with open("data.txt", "w") as f:
        f.write(str(state))
    interrupt("wrote data")
    return state


graph = StateGraph(dict)
graph.add_node("writer", write_data)
# No recursion_limit — should fire AEG003
app = graph.compile()
