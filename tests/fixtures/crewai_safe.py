"""Fixture: CrewAI — safe patterns.

Crew with consent-wrapped tools and execution budget.
"""
from crewai import Crew, Task, Agent
from crewai.tools import tool


def requires_consent(fn):
    """Consent wrapper."""
    return fn


@tool("Safe Writer")
@requires_consent
def write_output(content: str) -> str:
    """Write content with consent."""
    with open("output.txt", "w") as f:
        f.write(content)
    return "Written"


researcher = Agent(role="Researcher", goal="Research")

task = Task(description="Research a topic", agent=researcher)

# Has max_iter budget
crew = Crew(agents=[researcher], tasks=[task], max_iter=5)
