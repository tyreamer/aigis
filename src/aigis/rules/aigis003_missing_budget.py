"""AIGIS003: Missing max-iterations / execution budget.

Fires when an agent entry point (AgentExecutor, Agent, Crew, graph.compile, etc.)
is not linked to any execution budget — either at construction time (e.g.
max_iterations=N on the constructor) or at execution time (e.g.
Runner.run(agent, max_turns=N)).
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AIGIS003"

# Map entry point names to framework descriptions for evidence
_FRAMEWORK_HINTS: dict[str, tuple[str, str]] = {
    # name -> (framework, recommended fix)
    "Agent": ("OpenAI Agents SDK", "max_turns=N on Agent() or Runner.run(..., max_turns=N)"),
    "AgentExecutor": ("LangChain", "max_iterations=N on AgentExecutor()"),
    "create_react_agent": ("LangChain", "max_iterations=N"),
    "compile": ("LangGraph", "recursion_limit=N on compile() or in invoke(config={})"),
    "Crew": ("CrewAI", "max_iter=N on Crew()"),
    "AssistantAgent": ("AutoGen/AG2", "max_consecutive_auto_reply=N or max_turns=N on initiate_chat()"),
    "ConversableAgent": ("AutoGen/AG2", "max_consecutive_auto_reply=N or max_turns=N on initiate_chat()"),
    "GroupChat": ("AutoGen/AG2", "max_round=N on GroupChat()"),
    "GroupChatManager": ("AutoGen/AG2", "max_round=N on GroupChat() or max_turns=N on execution call"),
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    entry_points = graph.nodes_by_kind(NodeKind.ENTRY_POINT)

    for ep in entry_points:
        wraps = graph.edges_to(ep.id, EdgeKind.WRAPS)
        budget_nodes = [
            graph.nodes[e.source]
            for e in wraps
            if graph.nodes[e.source].kind == NodeKind.BUDGET_CONTROL
        ]

        if budget_nodes:
            continue

        framework, fix_hint = _FRAMEWORK_HINTS.get(
            ep.name, ("unknown", "max_iterations=N, max_turns=N, or recursion_limit=N")
        )

        findings.append(
            Finding(
                rule_id=RULE_ID,
                message=(
                    f"Entry point '{ep.name}' has no execution budget "
                    f"(max_iterations, recursion_limit, max_turns, timeout)"
                ),
                location=ep.location,
                severity=Severity.WARNING,
                node_id=ep.id,
                evidence=Evidence(
                    subject_name=ep.name,
                    budget_signal_found=TriState.NO,
                    confidence="high",
                    rationale=(
                        f"[{framework}] Entry point '{ep.name}' creates an agent "
                        f"execution loop with no budget limit. Checked constructor "
                        f"kwargs and same-file execution calls — no budget control "
                        f"found on either. Without bounds, the agent could run "
                        f"indefinitely."
                    ),
                    remediation=f"Add an execution budget: {fix_hint}.",
                ),
            )
        )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(entry_points))
