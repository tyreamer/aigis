"""AIGIS012: External API response returned without validation.

Fires when a tool function returns an external API response directly
without checking status, validating content, or handling errors.
Unvalidated responses can inject unexpected data into the agent's context.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS012"

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "request", "fetch", "urlopen"}

_VALIDATION_PATTERNS = {
    "validate", "check", "assert", "verify", "status_code",
    "raise_for_status", "ok",
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
                        f"'{tool.name}' returns an external API response "
                        f"without validating it first"
                    ),
                    location=Location(file=tool.location.file, line=line, col=0),
                    severity=Severity.WARNING,
                    node_id=tool.id,
                    evidence=Evidence(
                        subject_name=tool.name,
                        confidence="medium",
                        rationale=(
                            f"This tool makes an external HTTP request and returns "
                            f"the response directly to the agent without checking "
                            f"the status code, validating the content, or handling "
                            f"errors. Malformed or malicious responses could corrupt "
                            f"the agent's reasoning."
                        ),
                        remediation=(
                            "Check the response status (response.raise_for_status() "
                            "or if response.ok), validate the content structure, "
                            "and handle error cases before returning data to the agent."
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

        # Track variables assigned from HTTP calls
        http_vars: set[str] = set()
        has_validation = False

        for child in ast.walk(node):
            # Track HTTP response assignments
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                call_name = _call_name(child.value)
                if call_name.lower() in _HTTP_METHODS:
                    for t in child.targets:
                        if isinstance(t, ast.Name):
                            http_vars.add(t.id)

            # Check for validation calls
            if isinstance(child, ast.Call):
                name = _call_name(child)
                if name.lower() in _VALIDATION_PATTERNS:
                    has_validation = True
            if isinstance(child, ast.Attribute):
                if child.attr.lower() in _VALIDATION_PATTERNS:
                    has_validation = True

        if has_validation:
            break

        # Check return statements for direct HTTP response returns
        for child in ast.walk(node):
            if not isinstance(child, ast.Return) or child.value is None:
                continue
            ret = child.value

            # return requests.get(url).json() — chained call
            if isinstance(ret, ast.Call) and isinstance(ret.func, ast.Attribute):
                if isinstance(ret.func.value, ast.Call):
                    inner_name = _call_name(ret.func.value)
                    if inner_name.lower() in _HTTP_METHODS:
                        issues.append(child.lineno)
                        continue

            # return response.json() where response is from HTTP
            if isinstance(ret, ast.Call) and isinstance(ret.func, ast.Attribute):
                if isinstance(ret.func.value, ast.Name) and ret.func.value.id in http_vars:
                    issues.append(child.lineno)
                    continue

            # return response (raw)
            if isinstance(ret, ast.Name) and ret.id in http_vars:
                issues.append(child.lineno)

        break

    return issues


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""
