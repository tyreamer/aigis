"""Fixture: Retrieval with tenant filter. AIGIS011 should NOT fire."""
from langchain.tools import tool

@tool
def search_docs(query: str, tenant_id: str) -> str:
    from vectorstore import store
    results = store.similarity_search(query, filter={"tenant": tenant_id})
    return str(results)
