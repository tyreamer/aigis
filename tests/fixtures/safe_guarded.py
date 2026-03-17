"""Fixture: properly guarded tools — should produce no findings."""
from langchain.tools import tool
from langchain.agents import AgentExecutor


def requires_consent(fn):
    """Consent/policy wrapper — satisfies both AIGIS001 and AIGIS002."""
    def wrapper(*args, **kwargs):
        resp = input(f"POLICY CHECK — consent to run {fn.__name__}? [y/n] ")
        if resp.lower() == "y":
            return fn(*args, **kwargs)
    return wrapper


@tool
@requires_consent
def delete_file(path: str):
    """Delete a file with explicit consent."""
    import os
    os.remove(path)


@tool
@requires_consent
def run_deploy(env: str):
    """Deploy to an environment with policy consent."""
    import subprocess
    subprocess.run(["deploy", "--env", env])


# Entry point with budget
agent = AgentExecutor(agent=None, tools=[delete_file, run_deploy], max_iterations=10)
