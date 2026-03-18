"""Attack surface analysis — aggregate governance posture summary."""

from __future__ import annotations

from dataclasses import dataclass, field

from .graph import ExecutionGraph
from .models import EdgeKind, NodeKind, RuleResult


@dataclass
class ToolCapability:
    name: str
    file: str
    line: int
    operations: list[str]
    has_approval: bool
    has_consent: bool
    is_privileged: bool
    agent_controlled_input: bool = False


@dataclass
class AgentSummary:
    name: str
    file: str
    line: int
    has_budget: bool
    tool_count: int


@dataclass
class SurfaceReport:
    total_tools: int = 0
    mutating_tools: int = 0
    privileged_tools: int = 0
    approved_tools: int = 0
    total_agents: int = 0
    bounded_agents: int = 0
    tools: list[ToolCapability] = field(default_factory=list)
    agents: list[AgentSummary] = field(default_factory=list)
    total_findings: int = 0
    errors: int = 0
    warnings: int = 0

    @property
    def posture(self) -> str:
        if self.total_tools == 0 and self.total_agents == 0:
            return "clean"
        issues = 0
        if self.mutating_tools > self.approved_tools:
            issues += 1
        if self.privileged_tools > 0:
            issues += 1
        if self.total_agents > self.bounded_agents:
            issues += 1
        if self.errors > 0:
            issues += 1
        if issues == 0:
            return "good"
        if issues <= 1:
            return "fair"
        return "poor"


def analyze_surface(graph: ExecutionGraph, rule_results: list[RuleResult]) -> SurfaceReport:
    report = SurfaceReport()

    # Analyze tools
    for tool in graph.nodes_by_kind(NodeKind.TOOL_DEF):
        report.total_tools += 1

        sink_edges = graph.edges_from(tool.id, EdgeKind.CALLS)
        sinks = [graph.nodes[e.target] for e in sink_edges]
        operations = [s.metadata.get("description", s.name) for s in sinks]
        is_privileged = any(s.metadata.get("privileged") for s in sinks)
        is_mutating = len(sinks) > 0

        # Check approval
        wraps = graph.edges_to(tool.id, EdgeKind.WRAPS)
        gates = [graph.nodes[e.source] for e in wraps if graph.nodes[e.source].kind == NodeKind.APPROVAL_GATE]
        has_approval = len(gates) > 0
        has_consent = any(g.metadata.get("is_consent") for g in gates)

        if is_mutating:
            report.mutating_tools += 1
        if is_privileged:
            report.privileged_tools += 1
        if has_approval:
            report.approved_tools += 1

        report.tools.append(ToolCapability(
            name=tool.name,
            file=tool.location.file,
            line=tool.location.line,
            operations=operations,
            has_approval=has_approval,
            has_consent=has_consent,
            is_privileged=is_privileged,
        ))

    # Analyze agents
    for ep in graph.nodes_by_kind(NodeKind.ENTRY_POINT):
        report.total_agents += 1
        wraps = graph.edges_to(ep.id, EdgeKind.WRAPS)
        has_budget = any(graph.nodes[e.source].kind == NodeKind.BUDGET_CONTROL for e in wraps)
        tools_registered = len(graph.edges_from(ep.id, EdgeKind.REGISTERS))

        if has_budget:
            report.bounded_agents += 1

        report.agents.append(AgentSummary(
            name=ep.name,
            file=ep.location.file,
            line=ep.location.line,
            has_budget=has_budget,
            tool_count=tools_registered,
        ))

    # Count findings
    from .models import Severity
    for r in rule_results:
        report.total_findings += len(r.findings)
        for f in r.findings:
            if f.severity == Severity.ERROR:
                report.errors += 1
            elif f.severity == Severity.WARNING:
                report.warnings += 1

    return report


def format_surface_console(report: SurfaceReport) -> str:
    lines = ["", "ATTACK SURFACE SUMMARY", "=" * 50, ""]

    # Posture
    posture_labels = {"clean": "CLEAN", "good": "GOOD", "fair": "FAIR", "poor": "POOR"}
    lines.append(f"Governance Posture: {posture_labels.get(report.posture, report.posture.upper())}")
    lines.append("")

    # Tools
    lines.append(f"Tools: {report.total_tools} total")
    if report.total_tools > 0:
        lines.append(f"  Mutating (can modify/delete/send):  {report.mutating_tools}")
        lines.append(f"  Privileged (system commands):       {report.privileged_tools}")
        lines.append(f"  With approval gate:                 {report.approved_tools}")
        unapproved = report.mutating_tools - report.approved_tools
        if unapproved > 0:
            lines.append(f"  UNGUARDED:                          {unapproved}")
    lines.append("")

    # Agents
    lines.append(f"Agents: {report.total_agents} total")
    if report.total_agents > 0:
        lines.append(f"  With execution budget:              {report.bounded_agents}")
        unbounded = report.total_agents - report.bounded_agents
        if unbounded > 0:
            lines.append(f"  UNBOUNDED:                          {unbounded}")
    lines.append("")

    # Findings
    lines.append(f"Findings: {report.total_findings} total ({report.errors} errors, {report.warnings} warnings)")
    lines.append("")

    # Tool detail
    dangerous = [t for t in report.tools if t.operations]
    if dangerous:
        lines.append("Dangerous Tools:")
        for t in dangerous:
            ops = ", ".join(t.operations)
            status = []
            if t.has_consent:
                status.append("consent")
            elif t.has_approval:
                status.append("approved")
            else:
                status.append("NO APPROVAL")
            if t.is_privileged:
                status.append("privileged")
            lines.append(f"  {t.name}: {ops} [{', '.join(status)}]")
        lines.append("")

    return "\n".join(lines)
