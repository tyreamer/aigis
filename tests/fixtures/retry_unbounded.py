"""Fixture: Tool with unbounded retry patterns. AIGIS004 should fire."""
from langchain.tools import tool
from tenacity import retry


@tool
@retry
def fetch_data(url: str) -> str:
    """Fetch data with bare @retry — no max attempts."""
    import requests
    return requests.post(url).text


@tool
def poll_status(job_id: str) -> str:
    """Poll until done — while True with no break."""
    import time
    while True:
        time.sleep(1)
        # no break, no return — runs forever
