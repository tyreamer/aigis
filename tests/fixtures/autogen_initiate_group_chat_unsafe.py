"""Fixture: AG2 initiate_group_chat WITHOUT max_rounds — unsafe.

The orchestration call has no budget. AEG003 SHOULD fire.
"""
from autogen import AssistantAgent
from autogen.agentchat import initiate_group_chat

agent = AssistantAgent(name="unbounded", system_message="Do stuff")

# No max_rounds — unbounded
result, context, last = initiate_group_chat(
    pattern="round_robin",
    messages="Do something",
)
