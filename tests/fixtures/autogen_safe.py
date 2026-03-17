"""Fixture: AutoGen / AG2 — safe patterns.

Agents with budget controls.
"""
from autogen import AssistantAgent, GroupChat, GroupChatManager

assistant = AssistantAgent(
    name="coder",
    system_message="You write code.",
    max_consecutive_auto_reply=5,
)

chat = GroupChat(agents=[assistant], max_round=10)

manager = GroupChatManager(
    groupchat=chat,
    max_turns=20,
)
