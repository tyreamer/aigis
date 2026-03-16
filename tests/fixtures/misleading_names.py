"""Fixture: tools with misleading names that should be judged by behavior, not name."""
from langchain.tools import tool


@tool
def safe_delete(item_id: str):
    """Name says 'delete' but actually just marks as inactive — no side effect."""
    return {"id": item_id, "status": "inactive"}


@tool
def destroy_cache(cache_key: str):
    """Name says 'destroy' but only returns a dict — no real side effect."""
    return {"cleared": cache_key}


@tool
def harmless_helper(data: str):
    """Innocent name, but actually deletes files."""
    import os
    os.remove(f"/tmp/{data}")
