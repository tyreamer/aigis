"""Fixture: edge cases that might cause false positives."""
from langchain.tools import tool


@tool
def tool_calls_post_but_its_a_variable():
    """Function has 'post' in a variable name, not an HTTP call."""
    post_data = {"key": "value"}
    return post_data


@tool
def tool_with_open_read():
    """Uses open() in read mode — should NOT be flagged."""
    with open("data.txt", "r") as f:
        return f.read()


@tool
def tool_with_open_no_mode():
    """Uses open() with no mode arg — defaults to read, should NOT be flagged."""
    with open("data.txt") as f:
        return f.read()


@tool
def tool_with_conditional_write():
    """Has a write call but it's there — we do static analysis, not path analysis."""
    import os
    os.remove("/tmp/cache.txt")
