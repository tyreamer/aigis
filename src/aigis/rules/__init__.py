"""Rule registry — run all governance rules against an ExecutionGraph."""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import RuleResult
from .aeg001_unguarded_mutating import check as check_aeg001
from .aeg002_privileged_no_consent import check as check_aeg002
from .aeg003_missing_budget import check as check_aeg003

ALL_RULES = [check_aeg001, check_aeg002, check_aeg003]


def run_all_rules(graph: ExecutionGraph) -> list[RuleResult]:
    return [rule(graph) for rule in ALL_RULES]
