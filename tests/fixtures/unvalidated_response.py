"""Fixture: API response returned without validation. AIGIS012 should fire."""
from langchain.tools import tool

@tool
def fetch_data(url: str) -> str:
    import requests
    return requests.get(url).json()
