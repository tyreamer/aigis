"""AIGIS020: Secrets or credentials passed as tool arguments.

Fires when a tool function passes variables with secret-like names
(api_key, token, password, etc.) directly to outbound calls. Secrets
in tool arguments can leak into logs, traces, and LLM context.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS020"

# Only flag secrets in outbound/network calls, not SDK constructors
_OUTBOUND_CALLS = {
    "post", "put", "patch", "delete", "get", "request",
    "send", "fetch", "urlopen", "execute", "connect",
    "log", "print", "write", "dump", "emit",
}

_SECRET_PATTERNS = {
    "api_key", "apikey", "secret", "secret_key", "token", "auth_token",
    "access_token", "access_key", "password", "passwd", "credential",
    "private_key", "client_secret", "api_secret",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)

    for tool in tools:
        issues = _check_function(tool.location.file, tool.name, tool.location.line)
        for var_name, call_name, line in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"'{tool.name}' passes '{var_name}' (likely a secret) "
                        f"directly to '{call_name}'"
                    ),
                    location=Location(file=tool.location.file, line=line, col=0),
                    severity=Severity.ERROR,
                    node_id=tool.id,
                    evidence=Evidence(
                        subject_name=tool.name,
                        sink_type=f"credential leak via {call_name}",
                        confidence="medium",
                        rationale=(
                            f"The variable '{var_name}' looks like a secret or "
                            f"credential, and it's passed directly to '{call_name}'. "
                            f"Secrets in tool arguments can leak into agent traces, "
                            f"LLM context windows, logging systems, and observability "
                            f"platforms."
                        ),
                        remediation=(
                            "Don't pass secrets as tool arguments. Use a secrets "
                            "manager, environment variables accessed at call time, "
                            "or a pre-configured client that has credentials built in."
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

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue

            call_name = _call_name(child)
            if not call_name:
                continue

            # Skip SDK constructors — passing api_key to ChatOpenAI() is expected
            if call_name[0:1].isupper():
                continue

            # Skip calls where the secret is passed to a kwarg with a matching
            # name (api_key=api_key) — this is the standard SDK pattern
            # Only flag when a secret goes to an outbound/sink call
            if call_name not in _OUTBOUND_CALLS:
                continue

            # Check args and kwargs for secret-named variables
            for arg in child.args:
                if isinstance(arg, ast.Name) and _is_secret_name(arg.id):
                    issues.append((arg.id, call_name, child.lineno))

            for kw in child.keywords:
                # Skip kwarg where the name itself is a secret pattern
                # (e.g. api_key=my_key — this is SDK config, not a leak)
                if kw.arg and _is_secret_name(kw.arg):
                    continue
                if isinstance(kw.value, ast.Name) and _is_secret_name(kw.value.id):
                    issues.append((kw.value.id, call_name, child.lineno))

        break

    return issues


def _is_secret_name(name: str) -> bool:
    lower = name.lower()
    return any(p in lower for p in _SECRET_PATTERNS)


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""
