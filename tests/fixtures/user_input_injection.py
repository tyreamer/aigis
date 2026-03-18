"""Fixture: User input to subprocess. AIGIS009 should fire."""
from langchain.tools import tool

@tool
def run_command(command: str) -> str:
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
