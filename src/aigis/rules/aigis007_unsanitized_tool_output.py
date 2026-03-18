"""AIGIS007: Tool output injected into prompt without sanitization.

Fires when a tool call result is used directly in string formatting
that builds a prompt or message — without passing through a sanitization
or cleaning step first. This is a prompt injection vector.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS007"

_PROMPT_KWARGS = {
    "content", "prompt", "system", "system_message", "instructions",
    "template", "human_message", "user_message",
}

_MESSAGE_CONSTRUCTORS = {
    "HumanMessage", "SystemMessage", "AIMessage",
    "ChatMessage", "UserMessage",
}

_SANITIZE_PATTERNS = {
    "sanitize", "clean", "strip", "escape", "validate",
    "filter", "redact", "truncate",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    checked_files: set[str] = set()

    for tool in graph.nodes_by_kind(NodeKind.TOOL_DEF):
        checked_files.add(tool.location.file)

    for file_path in checked_files:
        issues = _check_file(file_path)
        for loc, var_name, usage_desc, func_ctx in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"Tool output '{var_name}' is injected into a prompt "
                        f"without sanitization"
                    ),
                    location=loc,
                    severity=Severity.WARNING,
                    evidence=Evidence(
                        subject_name=func_ctx or var_name,
                        confidence="medium",
                        rationale=(
                            f"The variable '{var_name}' (assigned from a function call) "
                            f"is used in {usage_desc} without passing through a "
                            f"sanitization step first. If this value comes from a "
                            f"tool or external source, it could contain instructions "
                            f"that hijack the agent's behavior (prompt injection)."
                        ),
                        remediation=(
                            "Sanitize tool output before including it in prompts. "
                            "Strip control characters, limit length, or use "
                            "structured output parsing instead of string interpolation."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(checked_files))


def _check_file(file_path: str) -> list[tuple[Location, str, str, str]]:
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    issues: list[tuple[Location, str, str, str]] = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Track variables assigned from function calls
        call_vars: set[str] = set()
        sanitized: set[str] = set()

        for node in ast.walk(func):
            # Track assignments from calls
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        call_vars.add(t.id)

            # Track sanitization
            if isinstance(node, ast.Call):
                name = _call_name(node).lower()
                if any(p in name for p in _SANITIZE_PATTERNS):
                    for arg in node.args:
                        if isinstance(arg, ast.Name):
                            sanitized.add(arg.id)

        # Now check for unsanitized call vars in prompt construction
        for node in ast.walk(func):
            # f-string with call var in a message constructor kwarg
            if isinstance(node, ast.Call):
                ctor_name = _call_name(node)
                if ctor_name in _MESSAGE_CONSTRUCTORS:
                    for kw in node.keywords:
                        if kw.arg and kw.arg.lower() in _PROMPT_KWARGS:
                            for var in _find_vars_in_expr(kw.value):
                                if var in call_vars and var not in sanitized:
                                    loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                                    issues.append((loc, var, f"a {ctor_name} message", func.name))

            # f-string in prompt-named variable assignment
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and any(p in t.id.lower() for p in {"prompt", "message", "msg"}):
                        for var in _find_vars_in_expr(node.value):
                            if var in call_vars and var not in sanitized:
                                loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                                issues.append((loc, var, "a prompt string", func.name))

    return issues


def _find_vars_in_expr(node: ast.expr) -> list[str]:
    found: list[str] = []
    if isinstance(node, ast.Name):
        found.append(node.id)
    elif isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                found.extend(_find_vars_in_expr(val.value))
    elif isinstance(node, ast.BinOp):
        found.extend(_find_vars_in_expr(node.left))
        found.extend(_find_vars_in_expr(node.right))
    return found


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""
