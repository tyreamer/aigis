"""Fixture: inline suppression comments."""
from langchain.tools import tool


@tool  # aigis: disable=AIGIS001 -- reviewed and accepted risk
def suppressed_delete(path: str):
    """This tool has a side effect but is suppressed inline."""
    import os
    os.remove(path)


@tool  # noqa: AIGIS001
def noqa_style_suppressed(path: str):
    """Suppressed using noqa-style comment."""
    import shutil
    shutil.rmtree(path)


@tool
def not_suppressed(url: str):
    """This one has no suppression comment."""
    import requests
    requests.post(url, json={"action": "notify"})
