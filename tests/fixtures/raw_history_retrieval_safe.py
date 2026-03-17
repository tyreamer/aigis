"""Fixture: Properly rewritten query for retrieval. AIGIS006 should NOT fire."""
from langchain.tools import tool


@tool
def search_docs_safe(user_query: str) -> str:
    """Search with a proper query, not raw history."""
    from some_vectorstore import store
    results = store.similarity_search(user_query)
    return str(results)
