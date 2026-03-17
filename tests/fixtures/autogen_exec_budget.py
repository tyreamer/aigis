"""Fixture: AutoGen / AG2 — budget at execution time.

AssistantAgent has no budget on constructor, but initiate_chat has max_turns.
GroupChat has max_round. AIGIS003 should NOT fire on any of these.
"""
from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager

assistant = AssistantAgent(
    name="coder",
    system_message="You write code.",
)

proxy = UserProxyAgent(
    name="user",
    human_input_mode="NEVER",
)

# Budget at execution time via initiate_chat
proxy.initiate_chat(assistant, message="Write hello world", max_turns=5)

# GroupChat with max_round — constructor budget
chat = GroupChat(agents=[assistant, proxy], max_round=10)

manager = GroupChatManager(groupchat=chat)
