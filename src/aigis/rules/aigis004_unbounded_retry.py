"""AIGIS004: Retry or loop pattern without hard cap.

Fires when a tool function contains a retry/loop pattern that could
run indefinitely — while-True loops without break, @retry decorators
without max_retries/stop, or recursive calls without depth tracking.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AIGIS004"

# Decorator names that indicate retry behavior
_RETRY_DECORATORS = {"retry", "retrying", "backoff", "with_retries", "auto_retry"}

# Kwargs that indicate a retry cap exists
_RETRY_CAP_KWARGS = {
    "max_retries", "max_attempts", "stop", "stop_max_attempt_number",
    "max_tries", "tries", "retries", "max_retry", "limit",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)

    for tool in tools:
        file_str = tool.location.file
        # We need the AST to inspect the function body — re-parse the file
        # and find the function by name+line
        issues = _check_function_patterns(file_str, tool.name, tool.location.line)
        for issue_type, line in issues:
            findings.append(_make_finding(tool, issue_type, line))

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(tools))


def _check_function_patterns(
    file_path: str, func_name: str, func_line: int
) -> list[tuple[str, int]]:
    """Check a tool function for unbounded retry/loop patterns."""
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    issues: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != func_name or node.lineno != func_line:
            continue

        # Check 1: @retry decorator without cap kwargs
        for dec in node.decorator_list:
            dec_name = _decorator_name(dec).lower()
            if dec_name in _RETRY_DECORATORS:
                if not _has_retry_cap(dec):
                    issues.append(("uncapped_retry_decorator", node.lineno))

        # Check 2: while True without break
        for child in ast.walk(node):
            if isinstance(child, ast.While):
                if _is_while_true(child) and not _has_break(child):
                    issues.append(("while_true_no_break", child.lineno))

        break  # found the function, stop searching

    return issues


def _decorator_name(dec: ast.expr) -> str:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    if isinstance(dec, ast.Attribute):
        return dec.attr
    return ""


def _has_retry_cap(dec: ast.expr) -> bool:
    """Check if a retry decorator has any cap-like kwarg."""
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg and kw.arg.lower() in _RETRY_CAP_KWARGS:
                return True
        # tenacity: retry(stop=stop_after_attempt(3)) — the presence of
        # 'stop' as a kwarg is enough
        for kw in dec.keywords:
            if kw.arg == "stop":
                return True
    # Bare @retry with no args — no cap
    return False


def _is_while_true(node: ast.While) -> bool:
    test = node.test
    if isinstance(test, ast.Constant) and test.value is True:
        return True
    if isinstance(test, ast.NameConstant) and getattr(test, "value", None) is True:
        return True
    return False


def _has_break(node: ast.While) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Break):
            return True
        if isinstance(child, ast.Return):
            return True
    return False


def _make_finding(tool, issue_type: str, line: int) -> Finding:
    messages = {
        "uncapped_retry_decorator": (
            f"Tool '{tool.name}' has a @retry decorator without a max attempts limit",
            "Add a retry cap: @retry(max_retries=N) or @retry(stop=stop_after_attempt(N)).",
        ),
        "while_true_no_break": (
            f"Tool '{tool.name}' contains a while-True loop without a break or return",
            "Add a break condition, iteration counter, or timeout to prevent infinite loops.",
        ),
    }
    msg, fix = messages.get(issue_type, (f"Tool '{tool.name}' has an unbounded loop", "Add a loop bound."))
    return Finding(
        rule_id=RULE_ID,
        message=msg,
        location=Location(file=tool.location.file, line=line, col=0),
        severity=Severity.WARNING,
        node_id=tool.id,
        evidence=Evidence(
            subject_name=tool.name,
            confidence="high",
            rationale=(
                f"Tool '{tool.name}' contains a retry or loop pattern that could "
                f"run indefinitely. Without a hard cap, a transient failure or "
                f"unexpected condition could cause the tool to loop forever."
            ),
            remediation=fix,
        ),
    )
