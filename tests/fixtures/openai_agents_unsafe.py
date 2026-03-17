"""Fixture: OpenAI Agents SDK — unsafe patterns.

Agent with mutating tools, no approval, no budget.
"""
from agents import Agent, Runner, function_tool


@function_tool
def delete_file(path: str) -> str:
    """Delete a file from the filesystem."""
    import os
    os.remove(path)
    return f"Deleted {path}"


@function_tool
def send_webhook(url: str, payload: str) -> str:
    """Send a webhook POST request."""
    import requests
    requests.post(url, json={"data": payload})
    return "Sent"


@function_tool
def execute_command(cmd: str) -> str:
    """Run a shell command."""
    import subprocess
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


# No max_turns, no approval — unsafe
agent = Agent(
    name="file-manager",
    instructions="You manage files.",
    tools=[delete_file, send_webhook, execute_command],
)
