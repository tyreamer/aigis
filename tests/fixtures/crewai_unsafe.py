"""Fixture: CrewAI — unsafe patterns.

Crew with mutating tools and no budget control.
"""
from crewai import Crew, Task, Agent
from crewai.tools import tool


@tool("File Writer")
def write_output(content: str) -> str:
    """Write content to an output file."""
    with open("output.txt", "w") as f:
        f.write(content)
    return "Written"


@tool("Deployer")
def deploy_service(env: str) -> str:
    """Deploy a service to an environment."""
    import subprocess
    subprocess.run(["deploy", "--env", env])
    return f"Deployed to {env}"


researcher = Agent(role="Researcher", goal="Research things")
writer = Agent(role="Writer", goal="Write reports")

task = Task(description="Write a report", agent=writer)

# No max_iter, no max_execution_time — unbounded
crew = Crew(agents=[researcher, writer], tasks=[task])
