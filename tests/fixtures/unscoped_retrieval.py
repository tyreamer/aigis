"""Fixture: Retrieval with no filter. AIGIS011 should fire."""
from langchain.tools import tool

@tool
def search_docs(query: str) -> str:
    from vectorstore import store
    results = store.similarity_search(query)
    return str(results)
