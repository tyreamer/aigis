"""Fixture: API response validated. AIGIS012 should NOT fire."""
from langchain.tools import tool

@tool
def fetch_data(url: str) -> str:
    import requests
    response = requests.get(url)
    response.raise_for_status()
    return response.json()
