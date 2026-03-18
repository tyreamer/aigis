"""AIGIS001: Dangerous Tool Without Approval

Fires when a tool that can modify files, run commands, or send data
has no human approval step before execution.
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AIGIS001"

# Human-readable descriptions for dangerous operations
_OP_LABELS: dict[str, str] = {
    "file deletion": "delete files",
    "directory deletion": "delete directories",
    "file rename": "rename files",
    "recursive deletion": "recursively delete files and folders",
    "file move": "move files",
    "file copy": "copy files",
    "subprocess execution": "run shell commands",
    "system command": "execute system commands",
    "outbound HTTP POST": "send HTTP POST requests",
    "outbound HTTP PUT": "send HTTP PUT requests",
    "outbound HTTP DELETE": "send HTTP DELETE requests",
    "outbound HTTP PATCH": "send HTTP PATCH requests",
    "side effect": "write to files",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)

    for tool in tools:
        sink_edges = graph.edges_from(tool.id, EdgeKind.CALLS)
        if not sink_edges:
            continue

        if _has_approval(graph, tool.id):
            continue

        if _entry_point_has_approval(graph, tool.id):
            continue

        sinks = [graph.nodes[e.target] for e in sink_edges]
        sink_descs = [s.metadata.get("description", s.name) for s in sinks]
        human_ops = [_OP_LABELS.get(d, d) for d in sink_descs]
        ops_str = ", ".join(dict.fromkeys(human_ops))

        findings.append(
            Finding(
                rule_id=RULE_ID,
                message=(
                    f"'{tool.name}' can {ops_str} — but nothing requires "
                    f"human approval before it runs"
                ),
                location=tool.location,
                severity=Severity.ERROR,
                node_id=tool.id,
                evidence=Evidence(
                    subject_name=tool.name,
                    sink_type=", ".join(sink_descs),
                    approval_signal_found=TriState.NO,
                    approval_signal_kind="",
                    confidence="high",
                    rationale=(
                        f"This tool is exposed to an AI agent and can {ops_str}. "
                        f"There is no approval check, confirmation prompt, or policy "
                        f"wrapper — the agent can call it freely. If the agent "
                        f"decides to use this tool, nothing stops it."
                    ),
                    remediation=(
                        f"Add an approval step before this tool can execute. "
                        f"For example: @requires_approval decorator, a confirmation "
                        f"prompt in the function body, or a human-in-the-loop gate "
                        f"in your agent framework."
                    ),
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
