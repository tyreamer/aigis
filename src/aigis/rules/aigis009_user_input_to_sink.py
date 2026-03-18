"""AIGIS009: User input flows directly into a dangerous operation.

Fires when a tool function's parameters are passed directly to
subprocess, system, or eval calls without validation. This is an
injection vector — the agent controls the input, not a human.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS009"

_DANGEROUS_SINKS = {
    "run", "call", "check_call", "check_output", "Popen",  # subprocess
    "system", "popen",  # os
    "eval", "exec",  # builtins
}

_SANITIZE_PATTERNS = {
    "sanitize", "validate", "escape", "clean", "filter",
    "allowlist", "whitelist", "shlex", "quote",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)

    for tool in tools:
        issues = _check_function(tool.location.file, tool.name, tool.location.line)
        for param_name, sink_name, line in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"'{tool.name}' passes its '{param_name}' parameter "
                        f"directly to {sink_name} — an injection risk"
                    ),
                    location=Location(file=tool.location.file, line=line, col=0),
                    severity=Severity.ERROR,
                    node_id=tool.id,
                    evidence=Evidence(
                        subject_name=tool.name,
                        sink_type=f"injection via {sink_name}",
                        confidence="high",
                        rationale=(
                            f"The parameter '{param_name}' flows directly from the "
                            f"tool's input to a call to '{sink_name}' with no "
                            f"validation or sanitization in between. Since the AI "
                            f"agent controls this input, it can inject arbitrary "
                            f"commands or code."
                        ),
                        remediation=(
                            f"Validate '{param_name}' before passing it to "
                            f"'{sink_name}'. Use an allowlist, escape the input "
                            f"(e.g. shlex.quote for shell commands), or avoid "
                            f"passing agent-controlled strings to execution functions."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(tools))


def _check_function(file_path: str, func_name: str, func_line: int) -> list[tuple[str, str, int]]:
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    issues: list[tuple[str, str, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != func_name or node.lineno != func_line:
            continue

        # Collect parameter names
        param_names = set()
        for arg in node.args.args:
            param_names.add(arg.arg)
        for arg in node.args.kwonlyargs:
            param_names.add(arg.arg)

        # Check if any param goes through sanitization
        sanitized = _find_sanitized_params(node, param_names)

        # Walk body for dangerous sink calls
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue

            sink_name = _call_name(child)
            if sink_name not in _DANGEROUS_SINKS:
                continue

            # For subprocess/os sinks, only the first positional arg (the command)
            # is an injection risk. kwargs like timeout, cwd are not.
            # For eval/exec, any arg is dangerous.
            check_all = sink_name in {"eval", "exec"}

            if check_all:
                for arg in child.args:
                    if isinstance(arg, ast.Name) and arg.id in param_names:
                        if arg.id not in sanitized:
                            issues.append((arg.id, sink_name, child.lineno))
            else:
                # Only first positional arg (the command string)
                if child.args:
                    arg = child.args[0]
                    if isinstance(arg, ast.Name) and arg.id in param_names:
                        if arg.id not in sanitized:
                            issues.append((arg.id, sink_name, child.lineno))

        break

    return issues


def _find_sanitized_params(func_node: ast.AST, param_names: set[str]) -> set[str]:
    """Find params that pass through a sanitization call before reaching sinks."""
    sanitized: set[str] = set()
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node).lower()
        if any(p in call_name for p in _SANITIZE_PATTERNS):
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in param_names:
                    sanitized.add(arg.id)
    return sanitized


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""
