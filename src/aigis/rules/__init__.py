"""Rule registry — run all governance rules against an ExecutionGraph."""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import RuleResult
from .aigis001_unguarded_mutating import check as check_aigis001
from .aigis002_privileged_no_consent import check as check_aigis002
from .aigis003_missing_budget import check as check_aigis003
from .aigis004_unbounded_retry import check as check_aigis004
from .aigis005_user_controlled_budget import check as check_aigis005
from .aigis006_raw_history_retrieval import check as check_aigis006
from .aigis007_unsanitized_tool_output import check as check_aigis007
from .aigis008_mutable_system_prompt import check as check_aigis008
from .aigis009_user_input_to_sink import check as check_aigis009
from .aigis010_agent_output_injection import check as check_aigis010
from .aigis011_unscoped_retrieval import check as check_aigis011
from .aigis012_unvalidated_tool_response import check as check_aigis012
from .aigis015_dynamic_tool_list import check as check_aigis015
from .aigis016_read_write_same_resource import check as check_aigis016
from .aigis017_llm_in_loop import check as check_aigis017
from .aigis018_generation_no_rate_limit import check as check_aigis018
from .aigis019_unbounded_embedding import check as check_aigis019
from .aigis020_secrets_in_tool_args import check as check_aigis020
from .aigis021_pii_in_llm_calls import check as check_aigis021
from .aigis022_full_records_to_agent import check as check_aigis022

ALL_RULES = [
    check_aigis001, check_aigis002, check_aigis003,
    check_aigis004, check_aigis005, check_aigis006,
    check_aigis007, check_aigis008, check_aigis009,
    check_aigis010, check_aigis011, check_aigis012,
    check_aigis015, check_aigis016, check_aigis017,
    check_aigis018, check_aigis019, check_aigis020,
    check_aigis021, check_aigis022,
]


def run_all_rules(graph: ExecutionGraph) -> list[RuleResult]:
    return [rule(graph) for rule in ALL_RULES]
