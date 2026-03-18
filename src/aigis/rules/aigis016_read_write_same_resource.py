"""AIGIS016: Agent has both read and write access to the same resource.

Fires when an agent's tool set includes both read and write tools for
the same resource type (filesystem, database, HTTP). This creates a
read-modify-write loop risk where the agent can alter data it reads.
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS016"

# Classify sinks into resource categories
_WRITE_CATEGORIES: dict[str, str] = {
    "file deletion": "filesystem",
    "directory deletion": "filesystem",
    "file rename": "filesystem",
    "recursive deletion": "filesystem",
    "file move": "filesystem",
    "file copy": "filesystem",
    "side effect": "filesystem",
    "subprocess execution": "system",
    "system command": "system",
    "outbound HTTP POST": "http",
    "outbound HTTP PUT": "http",
    "outbound HTTP DELETE": "http",
    "outbound HTTP PATCH": "http",
}

# Tools whose names suggest read operations on these resources
_READ_NAME_PATTERNS: dict[str, list[str]] = {
    "filesystem": ["read", "load", "get_file", "list_files", "list_dir", "ls", "cat", "open"],
    "http": ["fetch", "get", "download", "request", "http_get", "api_get"],
    "system": ["check", "status", "info", "whoami", "pwd"],
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    entry_points = graph.nodes_by_kind(NodeKind.ENTRY_POINT)

    for ep in entry_points:
        reg_edges = graph.edges_from(ep.id, EdgeKind.REGISTERS)
        if len(reg_edges) < 2:
            continue

        tool_ids = [e.target for e in reg_edges]
        tools = [graph.nodes[tid] for tid in tool_ids if tid in graph.nodes]

        # Classify tools
        write_categories: dict[str, list[str]] = {}
        read_categories: dict[str, list[str]] = {}

        for tool in tools:
            # Check write via sinks
            sink_edges = graph.edges_from(tool.id, EdgeKind.CALLS)
            for edge in sink_edges:
                sink = graph.nodes.get(edge.target)
                if not sink:
                    continue
                desc = sink.metadata.get("description", "")
                cat = _WRITE_CATEGORIES.get(desc)
                if cat:
                    write_categories.setdefault(cat, []).append(tool.name)

            # Check read via name patterns
            tool_lower = tool.name.lower()
            for cat, patterns in _READ_NAME_PATTERNS.items():
                if any(p in tool_lower for p in patterns):
                    read_categories.setdefault(cat, []).append(tool.name)

        # Find overlapping categories
        for cat in set(write_categories) & set(read_categories):
            readers = read_categories[cat]
            writers = write_categories[cat]
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"This agent can both read and write {cat} resources "
                        f"— creating a modify-what-you-read risk"
                    ),
                    location=ep.location,
                    severity=Severity.WARNING,
                    node_id=ep.id,
                    evidence=Evidence(
                        subject_name=ep.name,
                        confidence="medium",
                        rationale=(
                            f"This agent has tools that read {cat} resources "
                            f"({', '.join(readers)}) and tools that write/delete "
                            f"them ({', '.join(writers)}). An agent with both "
                            f"capabilities can read data, decide to modify it, and "
                            f"write it back — potentially in a loop — without human "
                            f"oversight of the changes."
                        ),
                        remediation=(
                            f"Separate read and write capabilities into different "
                            f"agents, or add an approval step on the write tools. "
                            f"Consider making the agent read-only by default and "
                            f"requiring explicit human approval for modifications."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(entry_points))
