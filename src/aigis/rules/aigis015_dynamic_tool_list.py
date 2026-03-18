"""AIGIS015: Agent tools loaded dynamically at runtime.

Fires when an agent's tool list is built from a variable, function call,
or other dynamic source rather than a static list of known functions.
A dynamic tool list means the agent's capabilities are unpredictable.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS015"


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    entry_points = graph.nodes_by_kind(NodeKind.ENTRY_POINT)

    for ep in entry_points:
        file_str = ep.location.file
        line = ep.location.line
        result = _check_tools_kwarg(file_str, line, ep.name)
        if result:
            source_desc = result
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"This agent's tool list is built dynamically — "
                        f"its capabilities are not predictable from the code"
                    ),
                    location=ep.location,
                    severity=Severity.WARNING,
                    node_id=ep.id,
                    evidence=Evidence(
                        subject_name=ep.name,
                        confidence="medium",
                        rationale=(
                            f"The tools available to this agent are loaded from "
                            f"{source_desc} rather than a fixed list. This means "
                            f"the agent's capabilities could change at runtime, "
                            f"making it impossible to review what it can do from "
                            f"the code alone."
                        ),
                        remediation=(
                            "Use a static tool list: tools=[func_a, func_b]. "
                            "If dynamic loading is required, add a validation "
                            "step that checks tools against an allowlist."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(entry_points))


def _check_tools_kwarg(file_path: str, target_line: int, ep_name: str) -> str | None:
    """Return a description of the dynamic source, or None if static."""
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if node.lineno != target_line:
            continue

        for kw in node.keywords:
            if kw.arg != "tools":
                continue
            val = kw.value

            # Static list of names → safe
            if isinstance(val, ast.List):
                if all(isinstance(e, ast.Name) for e in val.elts):
                    return None
                # List with dynamic elements
                return "a list with computed elements"

            # Function call → dynamic
            if isinstance(val, ast.Call):
                name = ""
                if isinstance(val.func, ast.Name):
                    name = val.func.id
                elif isinstance(val.func, ast.Attribute):
                    name = val.func.attr
                return f"a function call ({name})" if name else "a function call"

            # Variable → dynamic
            if isinstance(val, ast.Name):
                return f"a variable ({val.id})"

            # Anything else → dynamic
            return "a dynamic expression"

    return None
