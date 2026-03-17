"""Example: Tool with unbounded retry — no max attempts.

The @retry decorator has no stop condition. A transient failure
will cause infinite retries. Aigis flags this as AIGIS004.

Run:  aigis scan examples/unbounded_retry.py
"""
from langchain.tools import tool
from tenacity import retry


@tool
@retry
def fetch_api(url: str) -> str:
    """Fetch data from an API — retries forever on failure."""
    import requests
    return requests.post(url).text
