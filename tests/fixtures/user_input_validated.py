"""Fixture: User input validated before sink. AIGIS009 should NOT fire."""
from langchain.tools import tool
import shlex

@tool
def run_command(command: str) -> str:
    import subprocess
    safe_cmd = shlex.quote(command)
    result = subprocess.run(safe_cmd, shell=True, capture_output=True, text=True)
    return result.stdout
