"""AEG003: Missing max-iterations / execution budget.

Fires when an agent entry point (AgentExecutor, graph.compile, etc.)
does not specify any execution budget (max_iterations, recursion_limit,
timeout, etc.).
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AEG003"


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    entry_points = graph.nodes_by_kind(NodeKind.ENTRY_POINT)

    for ep in entry_points:
        wraps = graph.edges_to(ep.id, EdgeKind.WRAPS)
        has_budget = any(
            graph.nodes[e.source].kind == NodeKind.BUDGET_CONTROL for e in wraps
        )
        if not has_budget:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=f"Entry point '{ep.name}' has no execution budget (max_iterations, recursion_limit, timeout)",
                    location=ep.location,
                    severity=Severity.WARNING,
                    node_id=ep.id,
                    evidence=Evidence(
                        subject_name=ep.name,
                        budget_signal_found=TriState.NO,
                        confidence="high",
                        rationale=f"Entry point '{ep.name}' creates an agent execution loop with no iteration or budget limit. Without bounds, the agent could run indefinitely.",
                        remediation="Add an execution budget (e.g. max_iterations=N, recursion_limit=N, or timeout=N).",
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(entry_points))
