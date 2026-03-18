"""AIGIS022: Full database records returned to agent without field filtering.

Fires when a tool returns raw database query results (fetchall, fetchone)
directly without selecting specific fields. Full records may contain
sensitive columns the agent doesn't need.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS022"

_FETCH_METHODS = {
    "fetchall", "fetchone", "fetchmany", "all", "first",
    "scalar", "scalars",
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
                        f"'{tool.name}' returns raw database records to the "
                        f"agent without filtering fields"
                    ),
                    location=Location(file=tool.location.file, line=line, col=0),
                    severity=Severity.WARNING,
                    node_id=tool.id,
                    evidence=Evidence(
                        subject_name=tool.name,
                        confidence="medium",
                        rationale=(
                            f"This tool fetches database records and returns them "
                            f"directly. Full records may include sensitive columns "
                            f"(passwords, tokens, PII) that the agent doesn't need. "
                            f"The agent's context window then contains data it "
                            f"shouldn't have access to."
                        ),
                        remediation=(
                            "Select only the fields the agent needs: "
                            "return [{{'name': r.name}} for r in results] "
                            "or use a SELECT with specific columns instead of SELECT *."
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

        # Track variables assigned from fetch calls
        fetch_vars: set[str] = set()
        has_field_filter = False

        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                if isinstance(child.value.func, ast.Attribute):
                    if child.value.func.attr in _FETCH_METHODS:
                        for t in child.targets:
                            if isinstance(t, ast.Name):
                                fetch_vars.add(t.id)

            # Check for field filtering (list/dict comprehension over fetch result)
            if isinstance(child, (ast.ListComp, ast.DictComp)):
                for gen in child.generators:
                    if isinstance(gen.iter, ast.Name) and gen.iter.id in fetch_vars:
                        has_field_filter = True

        if has_field_filter or not fetch_vars:
            break

        # Check return statements for direct fetch var return
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                ret = child.value
                # return rows (direct)
                if isinstance(ret, ast.Name) and ret.id in fetch_vars:
                    issues.append(child.lineno)
                # return cursor.fetchall() (chained)
                if isinstance(ret, ast.Call) and isinstance(ret.func, ast.Attribute):
                    if ret.func.attr in _FETCH_METHODS:
                        issues.append(child.lineno)

        break

    return issues
