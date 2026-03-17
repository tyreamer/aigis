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

ALL_RULES = [
    check_aigis001,
    check_aigis002,
    check_aigis003,
    check_aigis004,
    check_aigis005,
    check_aigis006,
]


def run_all_rules(graph: ExecutionGraph) -> list[RuleResult]:
    return [rule(graph) for rule in ALL_RULES]
