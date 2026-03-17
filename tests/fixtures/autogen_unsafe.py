"""Fixture: AutoGen / AG2 — unsafe patterns.

AssistantAgent and GroupChat without budget controls.
"""
from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager


def delete_temp_files(path: str) -> str:
    """Delete temporary files."""
    import os
    os.remove(path)
    return f"Deleted {path}"


assistant = AssistantAgent(
    name="coder",
    system_message="You write code.",
)

manager = GroupChatManager(
    groupchat=GroupChat(agents=[assistant]),
)
