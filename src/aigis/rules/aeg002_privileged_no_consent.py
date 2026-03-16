"""AEG002: Privileged tool lacks explicit consent/policy wrapper.

Fires when a tool performs privileged operations (subprocess, OS commands)
without an explicit consent or policy wrapper.  A generic approval gate
does NOT satisfy this rule — it requires a consent/policy-specific pattern.
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AEG002"


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)

    for tool in tools:
        sink_edges = graph.edges_from(tool.id, EdgeKind.CALLS)
        privileged = [
            graph.nodes[e.target]
            for e in sink_edges
            if graph.nodes[e.target].metadata.get("privileged")
        ]
        if not privileged:
            continue

        # Check for consent/policy wrapper specifically
        if _has_consent_wrapper(graph, tool.id):
            continue

        priv_names = [s.name for s in privileged]
        priv_descs = [s.metadata.get("description", s.name) for s in privileged]

        # Check if there is a generic approval (not consent-level)
        approval_signal = _find_approval_signal(graph, tool.id)

        findings.append(
            Finding(
                rule_id=RULE_ID,
                message=f"Tool '{tool.name}' performs privileged operation(s) [{', '.join(priv_names)}] without a consent/policy wrapper",
                location=tool.location,
                severity=Severity.ERROR,
                node_id=tool.id,
                evidence=Evidence(
                    subject_name=tool.name,
                    sink_type=", ".join(priv_descs),
                    approval_signal_found=TriState.YES if approval_signal else TriState.NO,
                    approval_signal_kind=approval_signal or "",
                    confidence="high",
                    rationale=f"Tool '{tool.name}' performs privileged operation(s) ({', '.join(priv_descs)}) that could affect system integrity. "
                              + ("A generic approval gate was found but it does not meet the consent/policy standard required for privileged operations."
                                 if approval_signal else
                                 "No approval gate of any kind was detected."),
                    remediation="Add an explicit consent/policy decorator (e.g. @requires_consent, @policy_check). Generic @requires_approval is insufficient for privileged operations.",
                ),
            )
        )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(tools))


def _has_consent_wrapper(graph: ExecutionGraph, node_id: str) -> bool:
    wraps = graph.edges_to(node_id, EdgeKind.WRAPS)
    for edge in wraps:
        node = graph.nodes[edge.source]
        if node.kind == NodeKind.APPROVAL_GATE and node.metadata.get("is_consent"):
            return True
    return False


def _find_approval_signal(graph: ExecutionGraph, node_id: str) -> str | None:
    """Return the source description of any approval gate (even non-consent)."""
    wraps = graph.edges_to(node_id, EdgeKind.WRAPS)
    for edge in wraps:
        node = graph.nodes[edge.source]
        if node.kind == NodeKind.APPROVAL_GATE:
            return node.metadata.get("source", node.name)
    return None
