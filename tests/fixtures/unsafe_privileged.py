"""Fixture: tool running subprocess without consent/policy wrapper."""
from langchain.tools import tool


def requires_approval(fn):
    """Generic approval — not a consent/policy wrapper."""
    def wrapper(*args, **kwargs):
        resp = input(f"Approve {fn.__name__}? [y/n] ")
        if resp.lower() == "y":
            return fn(*args, **kwargs)
    return wrapper


@tool
@requires_approval
def run_shell_command(cmd: str):
    """Execute an arbitrary shell command."""
    import subprocess
    subprocess.run(cmd, shell=True)
