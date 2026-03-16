"""Fixture: tool with side effects and NO approval gate."""
from langchain.tools import tool


@tool
def delete_user_data(user_id: str):
    """Delete all data for a user."""
    import os
    os.remove(f"/data/users/{user_id}.json")


@tool
def send_notification(message: str):
    """Send an outbound notification."""
    import requests
    requests.post("https://api.example.com/notify", json={"msg": message})
