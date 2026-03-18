"""AIGIS003: Agent Can Run Forever

Fires when an agent has no limit on how many steps, turns, or iterations
it can take — meaning it could loop indefinitely.
"""

from __future__ import annotations

from ..graph import ExecutionGraph
from ..models import EdgeKind, Evidence, Finding, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AIGIS003"

# Map entry point names to framework-specific advice
_HINTS: dict[str, tuple[str, str]] = {
    "Agent": ("OpenAI Agents SDK", "Set max_turns on Agent() or Runner.run(..., max_turns=N)"),
    "AgentExecutor": ("LangChain", "Set max_iterations=N on AgentExecutor()"),
    "create_react_agent": ("LangChain", "Set max_iterations=N"),
    "compile": ("LangGraph", "Set recursion_limit=N on compile() or pass it in invoke(config={})"),
    "Crew": ("CrewAI", "Set max_iter=N on Crew()"),
    "AssistantAgent": ("AutoGen/AG2", "Set max_consecutive_auto_reply=N or pass max_turns=N to initiate_chat()"),
    "ConversableAgent": ("AutoGen/AG2", "Set max_consecutive_auto_reply=N or pass max_turns=N to initiate_chat()"),
    "GroupChat": ("AutoGen/AG2", "Set max_round=N on GroupChat()"),
    "GroupChatManager": ("AutoGen/AG2", "Set max_round=N on GroupChat() or max_turns=N on the execution call"),
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    entry_points = graph.nodes_by_kind(NodeKind.ENTRY_POINT)

    for ep in entry_points:
        wraps = graph.edges_to(ep.id, EdgeKind.WRAPS)
        has_budget = any(
            graph.nodes[e.source].kind == NodeKind.BUDGET_CONTROL for e in wraps
        )

        if has_budget:
            continue

        framework, fix = _HINTS.get(
            ep.name, ("this framework", "Set a max_iterations, max_turns, or recursion_limit")
        )

        findings.append(
            Finding(
                rule_id=RULE_ID,
                message=(
                    f"This agent ({ep.name}) has no limit on how long it can run"
                ),
                location=ep.location,
                severity=Severity.WARNING,
                node_id=ep.id,
                evidence=Evidence(
                    subject_name=ep.name,
                    budget_signal_found=TriState.NO,
                    confidence="high",
                    rationale=(
                        f"This {framework} agent has no maximum iteration or turn "
                        f"limit — not on the constructor and not on any execution "
                        f"call in this file. Without a limit, the agent could loop "
                        f"indefinitely, consuming resources and potentially taking "
                        f"repeated actions with no stop condition."
                    ),
                    remediation=f"{fix}.",
                ),
            )
        )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(entry_points))
