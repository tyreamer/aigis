"""AutoGen / AG2 framework patterns.

Covers the autogen / ag2 library:
- AssistantAgent, ConversableAgent as entry points
- GroupChat + GroupChatManager for multi-agent orchestration
- max_turns, max_round as budget controls
- register_for_llm / register_for_execution for tool registration
"""

# Entry points
ENTRY_POINT_NAMES = {"AssistantAgent", "ConversableAgent", "GroupChatManager", "GroupChat"}

# Budget kwargs on agents or GroupChat
BUDGET_KWARGS = {"max_turns", "max_round", "max_consecutive_auto_reply"}

# Tool registration method patterns (e.g. agent.register_for_llm)
TOOL_REGISTRATION_METHODS = {"register_for_llm", "register_for_execution"}

# Execution-time budget patterns:
# proxy.initiate_chat(assistant, ..., max_turns=N)
# The budget applies to the first positional arg (the target agent).
# Also covers receiver-is-entry patterns: manager.run(..., max_turns=N)
EXECUTION_BUDGET_PATTERNS = [
    {
        "methods": {"initiate_chat", "a_initiate_chat"},
        "budget_kwargs": {"max_turns", "max_round"},
        "entry_arg_index": 0,
        "any_receiver": True,
    },
    {
        "methods": {"run"},
        "budget_kwargs": {"max_turns", "max_round"},
        "receiver_is_entry": True,
    },
]

# Standalone orchestration functions that, when called with a budget kwarg,
# apply that budget to all entry points in the same file.
# e.g. initiate_group_chat(pattern=p, max_rounds=5)
FILE_LEVEL_BUDGET_FUNCTIONS = {
    "initiate_group_chat": {"max_rounds", "max_turns"},
    "a_initiate_group_chat": {"max_rounds", "max_turns"},
    "a_run_group_chat": {"max_rounds", "max_turns"},
    "run_group_chat": {"max_rounds", "max_turns"},
}
