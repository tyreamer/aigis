"""Fixture: LangGraph patterns that should be recognized as safe."""
from langgraph.graph import StateGraph


# --- Pattern 1: interrupt_before + recursion_limit (fully safe) ---
def write_document(state):
    """Writes a document to disk."""
    with open(state["path"], "w") as f:
        f.write(state["content"])
    return state


def review_document(state):
    """Reviews a document — read-only."""
    return {**state, "reviewed": True}


graph1 = StateGraph(dict)
graph1.add_node("writer", write_document)
graph1.add_node("reviewer", review_document)
app1 = graph1.compile(interrupt_before=["writer"], recursion_limit=50)


# --- Pattern 2: recursion_limit only (no interrupt_before) ---
def send_email(state):
    """Sends an email."""
    import requests
    requests.post("https://mail.example.com/send", json=state)
    return state


graph2 = StateGraph(dict)
graph2.add_node("emailer", send_email)
app2 = graph2.compile(recursion_limit=10)
