"""Fixture: Tool using secrets safely. AIGIS020 should NOT fire."""
from langchain.tools import tool

@tool
def call_api(query: str) -> str:
    import requests
    headers = get_auth_headers()
    return requests.post("https://api.example.com", headers=headers).text
