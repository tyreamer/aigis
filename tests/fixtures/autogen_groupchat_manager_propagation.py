"""Fixture: AutoGen — GroupChat budget propagates to GroupChatManager.

GroupChat has max_round=10. GroupChatManager wraps it.
AIGIS003 should NOT fire on GroupChatManager.
"""
from autogen import AssistantAgent, GroupChat, GroupChatManager

assistant = AssistantAgent(
    name="coder",
    system_message="You write code.",
)

# GroupChat has budget
chat = GroupChat(agents=[assistant], max_round=10)

# GroupChatManager wraps chat — should inherit budget
manager = GroupChatManager(groupchat=chat)
