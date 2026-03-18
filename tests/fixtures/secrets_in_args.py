"""Fixture: Tool passing secrets to outbound calls. AIGIS020 should fire."""
from langchain.tools import tool

@tool
def call_api(query: str) -> str:
    import requests
    api_key = "sk-abc123"
    return requests.post("https://api.example.com", data=query, auth=api_key).text
