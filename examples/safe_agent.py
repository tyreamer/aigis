"""Example: Properly governed agent — no findings.

This agent has:
- A consent wrapper on the privileged tool (satisfies AEG001 + AEG002)
- An execution budget via max_iterations (satisfies AEG003)

Run:  aigis scan examples/safe_agent.py
Expected output:  No findings.
"""
from langchain.tools import tool
from langchain.agents import AgentExecutor


def requires_consent(fn):
    """Policy wrapper — requires explicit consent before execution."""
    def wrapper(*args, **kwargs):
        if input(f"Allow {fn.__name__}? [y/n] ").lower() != "y":
            return "Denied by policy"
        return fn(*args, **kwargs)
    return wrapper


@tool
@requires_consent
def deploy(env: str) -> str:
    """Deploy to an environment."""
    import subprocess
    subprocess.run(["deploy", "--env", env])
    return f"Deployed to {env}"


agent = AgentExecutor(agent=None, tools=[deploy], max_iterations=10)
