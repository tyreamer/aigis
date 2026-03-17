"""Example: Unsafe mutating tool without approval gate.

This agent tool executes arbitrary shell commands from agent-controlled
input — with no human approval step. Aigis flags this as AEG001 (missing
approval gate) and AEG002 (privileged operation without consent wrapper).

Run:  aigis scan examples/unsafe_tool.py
"""
from langchain.tools import tool


@tool
def run_cmd(cmd: str, cwd: str = ".", timeout: int = 30) -> str:
    """Execute a shell command and return the output."""
    import subprocess

    result = subprocess.run(
        cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )
    return result.stdout or result.stderr
