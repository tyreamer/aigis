"""Fixture: LLM call in bounded loop. AIGIS017 should NOT fire."""
from langchain.tools import tool

@tool
def generate_limited(prompt: str) -> str:
    for i in range(5):
        result = llm.invoke(prompt)
    return result
