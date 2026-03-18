"""AIGIS017: LLM call inside a loop without iteration bound.

Fires when a tool function calls an LLM (invoke, generate, predict, etc.)
inside a while-True loop without a break condition. Each iteration costs
money and time — an unbounded loop can drain an API budget.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS017"

_LLM_METHODS = {
    "invoke", "ainvoke", "generate", "predict", "chat", "complete", "create",
}

_LLM_RECEIVERS = {
    "llm", "model", "client", "openai", "anthropic", "chat_model",
    "chat", "gpt", "claude",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)

    for tool in tools:
        issues = _check_function(tool.location.file, tool.name, tool.location.line)
        for line in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"'{tool.name}' calls an LLM inside a loop with no "
                        f"iteration limit — this could run up unbounded costs"
                    ),
                    location=Location(file=tool.location.file, line=line, col=0),
                    severity=Severity.WARNING,
                    node_id=tool.id,
                    evidence=Evidence(
                        subject_name=tool.name,
                        confidence="medium",
                        rationale=(
                            f"This tool makes LLM API calls inside a loop that "
                            f"has no visible stop condition. Each iteration costs "
                            f"money and adds latency. If the loop doesn't terminate, "
                            f"it will keep calling the LLM until the process is killed "
                            f"or the API budget is exhausted."
                        ),
                        remediation=(
                            "Add a maximum iteration count to the loop, or use a "
                            "for-loop with a fixed range. For example: "
                            "for i in range(max_iterations): ..."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(tools))


def _check_function(file_path: str, func_name: str, func_line: int) -> list[int]:
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    issues: list[int] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != func_name or node.lineno != func_line:
            continue

        for child in ast.walk(node):
            if not isinstance(child, ast.While):
                continue
            if not _is_while_true(child):
                continue
            if _has_break(child):
                continue
            if _has_llm_call(child):
                issues.append(child.lineno)

        break

    return issues


def _is_while_true(node: ast.While) -> bool:
    if isinstance(node.test, ast.Constant) and node.test.value is True:
        return True
    return False


def _has_break(node: ast.While) -> bool:
    for child in ast.walk(node):
        if isinstance(child, (ast.Break, ast.Return)):
            return True
    return False


def _has_llm_call(node: ast.While) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Attribute):
            method = child.func.attr.lower()
            if method not in _LLM_METHODS:
                continue
            if isinstance(child.func.value, ast.Name):
                receiver = child.func.value.id.lower()
                if any(p in receiver for p in _LLM_RECEIVERS):
                    return True
    return False
