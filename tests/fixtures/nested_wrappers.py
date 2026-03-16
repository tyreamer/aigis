"""Fixture: nested/stacked decorator patterns."""
from langchain.tools import tool


def log_call(fn):
    """Logging decorator — not an approval gate."""
    def wrapper(*args, **kwargs):
        print(f"Calling {fn.__name__}")
        return fn(*args, **kwargs)
    return wrapper


def rate_limit(fn):
    """Rate limiter — not an approval gate."""
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


def requires_approval(fn):
    """Approval gate buried under other decorators."""
    def wrapper(*args, **kwargs):
        resp = input(f"Approve {fn.__name__}? [y/n] ")
        if resp.lower() == "y":
            return fn(*args, **kwargs)
    return wrapper


# Approval gate exists but is buried under log_call and rate_limit
@tool
@log_call
@rate_limit
@requires_approval
def stacked_delete(path: str):
    """Delete with multiple stacked decorators including approval."""
    import os
    os.remove(path)


# No approval gate — only logging and rate limiting
@tool
@log_call
@rate_limit
def stacked_no_approval(path: str):
    """Delete with stacked decorators but no approval."""
    import os
    os.remove(path)
