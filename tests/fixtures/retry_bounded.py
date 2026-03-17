"""Fixture: Tool with bounded retry patterns. AIGIS004 should NOT fire."""
from langchain.tools import tool
from tenacity import retry, stop_after_attempt


@tool
@retry(stop=stop_after_attempt(3))
def fetch_data_safe(url: str) -> str:
    """Fetch data with capped retry."""
    import requests
    return requests.post(url).text


@tool
def poll_with_break(job_id: str) -> str:
    """Poll with a break condition."""
    import time
    while True:
        time.sleep(1)
        if True:  # placeholder for real condition
            break
    return "done"
