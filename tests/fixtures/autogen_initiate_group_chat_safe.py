"""Fixture: AG2 initiate_group_chat with max_rounds — safe.

All agents in this file are bounded by the initiate_group_chat call.
AIGIS003 should NOT fire.
"""
from autogen import AssistantAgent, ConversableAgent
from autogen.agentchat import initiate_group_chat

analyst = AssistantAgent(name="analyst", system_message="Analyze data")
researcher = ConversableAgent(name="researcher", system_message="Research topics")

result, context, last = initiate_group_chat(
    pattern="round_robin",
    messages="Analyze market trends",
    max_rounds=5,
)
