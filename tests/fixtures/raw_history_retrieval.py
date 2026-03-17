"""Fixture: Raw chat history passed to retrieval. AIGIS006 should fire."""
from langchain.tools import tool


@tool
def search_docs(query: str) -> str:
    """Search documents."""
    from some_vectorstore import store
    # Raw chat_history passed directly as the search query
    chat_history = []  # would come from state
    results = store.similarity_search(chat_history)
    return str(results)


@tool
def rag_lookup(question: str) -> str:
    """RAG lookup using raw messages."""
    from some_retriever import retriever
    messages = []  # would come from state
    docs = retriever.invoke(query=messages)
    return str(docs)
