"""Fixture: AutoGen / AG2 — no budget anywhere.

AssistantAgent with no budget on constructor or execution call.
AIGIS003 SHOULD fire.
"""
from autogen import AssistantAgent, GroupChat, GroupChatManager

assistant = AssistantAgent(
    name="unbounded",
    system_message="You write code.",
)

# No max_round on GroupChat, no max_turns on manager
chat = GroupChat(agents=[assistant])

manager = GroupChatManager(groupchat=chat)
