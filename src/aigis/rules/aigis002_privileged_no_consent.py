"""AIGIS002: System-Level Tool Without Consent Policy

Fires when a tool runs system commands (subprocess, os.system) without
an explicit consent or policy wrapper. A basic approval decorator is
not enough — system-level operations need a stricter consent check.
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AIGIS002"


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

        if _has_consent_wrapper(graph, tool.id):
            continue

        priv_descs = [s.metadata.get("description", s.name) for s in privileged]
        approval_signal = _find_approval_signal(graph, tool.id)

        if approval_signal:
            rationale = (
                f"'{tool.name}' can execute system-level operations "
                f"({', '.join(priv_descs)}). It has a basic approval check, "
                f"but system commands need a stronger consent policy — "
                f"a generic @requires_approval is not sufficient for operations "
                f"that can affect the host system."
            )
        else:
            rationale = (
                f"'{tool.name}' can execute system-level operations "
                f"({', '.join(priv_descs)}) with no consent check at all. "
                f"The agent can run arbitrary commands on the host system "
                f"without any policy gate."
            )

        findings.append(
            Finding(
                rule_id=RULE_ID,
                message=(
                    f"'{tool.name}' runs system commands without a consent policy"
                ),
                location=tool.location,
                severity=Severity.ERROR,
                node_id=tool.id,
                evidence=Evidence(
                    subject_name=tool.name,
                    sink_type=", ".join(priv_descs),
                    approval_signal_found=TriState.YES if approval_signal else TriState.NO,
                    approval_signal_kind=approval_signal or "",
                    confidence="high",
                    rationale=rationale,
                    remediation=(
                        "Wrap this tool with an explicit consent policy — for example "
                        "@requires_consent or @policy_check. A basic @requires_approval "
                        "is not enough for system-level operations. The consent wrapper "
                        "should enforce who can authorize execution and under what conditions."
                    ),
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
    wraps = graph.edges_to(node_id, EdgeKind.WRAPS)
    for edge in wraps:
        node = graph.nodes[edge.source]
        if node.kind == NodeKind.APPROVAL_GATE:
            return node.metadata.get("source", node.name)
    return None
