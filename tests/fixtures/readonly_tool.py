"""Fixture: read-only tools that should NOT produce findings."""
from langchain.tools import tool


@tool
def search_database(query: str):
    """Read-only database search."""
    import sqlite3
    conn = sqlite3.connect("db.sqlite")
    return conn.execute("SELECT * FROM items WHERE name = ?", (query,)).fetchall()


@tool
def fetch_weather(city: str):
    """Read-only HTTP GET — not a mutating sink."""
    import requests
    return requests.get(f"https://api.weather.com/{city}").json()


@tool
def read_file(path: str):
    """Read a file — open in read mode is not a sink."""
    with open(path, "r") as f:
        return f.read()


@tool
def list_directory(path: str):
    """List directory contents — read-only."""
    import os
    return os.listdir(path)
