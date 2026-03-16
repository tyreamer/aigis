"""AEG001: Mutating tool reachable without approval gate.

Fires when a tool that performs side-effecting operations (file I/O,
HTTP mutations, subprocess, etc.) has no approval gate wrapping it.
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AEG001"


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)

    for tool in tools:
        sink_edges = graph.edges_from(tool.id, EdgeKind.CALLS)
        if not sink_edges:
            continue

        # Is it wrapped by an approval gate?
        if _has_approval(graph, tool.id):
            continue

        # Check if the entry point has an approval gate (e.g. interrupt_before)
        if _entry_point_has_approval(graph, tool.id):
            continue

        sinks = [graph.nodes[e.target] for e in sink_edges]
        sink_names = [s.name for s in sinks]
        sink_descs = [s.metadata.get("description", s.name) for s in sinks]

        findings.append(
            Finding(
                rule_id=RULE_ID,
                message=f"Tool '{tool.name}' reaches side-effecting sink(s) [{', '.join(sink_names)}] without an approval gate",
                location=tool.location,
                severity=Severity.ERROR,
                node_id=tool.id,
                evidence=Evidence(
                    subject_name=tool.name,
                    sink_type=", ".join(sink_descs),
                    approval_signal_found=TriState.NO,
                    approval_signal_kind="",
                    confidence="high",
                    rationale=f"Tool '{tool.name}' is registered as an agent tool and calls {', '.join(sink_names)}. No approval gate was detected in its decorator chain or function body.",
                    remediation="Add an approval decorator (e.g. @requires_approval) or wrap side-effecting calls with a confirmation/policy check.",
                ),
            )
        )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(tools))


def _has_approval(graph: ExecutionGraph, node_id: str) -> bool:
    wraps = graph.edges_to(node_id, EdgeKind.WRAPS)
    return any(graph.nodes[e.source].kind == NodeKind.APPROVAL_GATE for e in wraps)


def _entry_point_has_approval(graph: ExecutionGraph, tool_id: str) -> bool:
    reg_edges = graph.edges_to(tool_id, EdgeKind.REGISTERS)
    for edge in reg_edges:
        if _has_approval(graph, edge.source):
            return True
    return False
