"""AIGIS010: Agent/LLM output used in SQL, shell, or eval without escaping.

Fires when a variable assigned from an LLM call is passed to a dangerous
sink (eval, exec, subprocess, cursor.execute) without parameterization
or escaping. This is a code/command injection vector via LLM output.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS010"

_LLM_METHODS = {
    "invoke", "ainvoke", "generate", "predict", "chat",
    "complete", "create", "run",
}

_LLM_RECEIVERS = {
    "llm", "model", "client", "openai", "anthropic",
    "chat_model", "gpt", "claude", "agent",
}

_INJECTION_SINKS = {
    "eval", "exec", "system", "popen",
    "run", "call", "check_call", "check_output", "Popen",
    "execute",  # cursor.execute
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    checked_files: set[str] = set()

    for tool in graph.nodes_by_kind(NodeKind.TOOL_DEF):
        checked_files.add(tool.location.file)

    for file_path in checked_files:
        issues = _check_file(file_path)
        for loc, var_name, sink_name, func_ctx in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"LLM output '{var_name}' is passed to '{sink_name}' "
                        f"— the model's response could execute arbitrary code"
                    ),
                    location=loc,
                    severity=Severity.ERROR,
                    evidence=Evidence(
                        subject_name=func_ctx or sink_name,
                        sink_type=f"injection via {sink_name}",
                        confidence="high",
                        rationale=(
                            f"The variable '{var_name}' is assigned from an LLM call "
                            f"and then passed to '{sink_name}'. The LLM's response "
                            f"is not code-reviewed — it could contain malicious "
                            f"commands, SQL injection, or arbitrary code that gets "
                            f"executed with the application's privileges."
                        ),
                        remediation=(
                            f"Never pass raw LLM output to {sink_name}. Use "
                            f"parameterized queries for SQL, allowlists for commands, "
                            f"or a sandboxed execution environment. Parse and validate "
                            f"the LLM's output before acting on it."
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

        # Track variables assigned from LLM calls
        llm_vars: set[str] = set()

        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _is_llm_call(node.value):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            llm_vars.add(t.id)

        if not llm_vars:
            continue

        # Check if LLM output vars flow to injection sinks
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue

            sink_name = _call_name(node)
            if sink_name not in _INJECTION_SINKS:
                continue

            # Check first positional arg
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Name) and arg.id in llm_vars:
                    loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                    issues.append((loc, arg.id, sink_name, func.name))
                # f-string containing LLM var
                elif isinstance(arg, ast.JoinedStr):
                    for val in arg.values:
                        if isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                            if val.value.id in llm_vars:
                                loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                                issues.append((loc, val.value.id, sink_name, func.name))

    return issues


def _is_llm_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Attribute):
        method = call.func.attr.lower()
        if method not in _LLM_METHODS:
            return False
        if isinstance(call.func.value, ast.Name):
            receiver = call.func.value.id.lower()
            return any(p in receiver for p in _LLM_RECEIVERS)
    return False


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""
