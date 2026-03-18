"""Fixture: LLM call in unbounded loop. AIGIS017 should fire."""
from langchain.tools import tool

@tool
def generate_until_done(prompt: str) -> str:
    while True:
        result = llm.invoke(prompt)
