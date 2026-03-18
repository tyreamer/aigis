"""AIGIS008: System prompt loaded from a mutable source.

Fires when an agent's system prompt or instructions come from a file,
environment variable, or database query rather than a string literal.
A mutable system prompt can be tampered with to change agent behavior.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS008"

_PROMPT_KWARGS = {
    "system_message", "system_prompt", "instructions",
    "system", "sys_msg", "system_instructions",
}

_MUTABLE_SOURCES = {"open", "getenv", "environ", "read", "load", "fetch"}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    entry_points = graph.nodes_by_kind(NodeKind.ENTRY_POINT)

    for ep in entry_points:
        issues = _check_prompt_source(ep.location.file, ep.location.line, ep.name)
        for source_desc, line in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"This agent's instructions come from {source_desc} "
                        f"— they could be changed without a code deploy"
                    ),
                    location=Location(file=ep.location.file, line=line, col=0),
                    severity=Severity.WARNING,
                    node_id=ep.id,
                    evidence=Evidence(
                        subject_name=ep.name,
                        confidence="medium",
                        rationale=(
                            f"The system prompt for this agent is loaded from "
                            f"{source_desc} rather than hardcoded in the source. "
                            f"If that source is writable (a file on disk, an env var, "
                            f"a database row), anyone with write access can change "
                            f"the agent's behavior without modifying or reviewing code."
                        ),
                        remediation=(
                            "Use a string literal for the system prompt, or load it "
                            "from a read-only, version-controlled source. If dynamic "
                            "prompts are required, add integrity checks (hash "
                            "validation, audit logging)."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(entry_points))


def _check_prompt_source(file_path: str, target_line: int, ep_name: str) -> list[tuple[str, int]]:
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    issues: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if node.lineno != target_line:
            continue

        for kw in node.keywords:
            if kw.arg and kw.arg.lower() not in _PROMPT_KWARGS:
                continue

            val = kw.value

            # String literal → safe
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                continue

            # JoinedStr (f-string) → safe enough (template in code)
            if isinstance(val, ast.JoinedStr):
                continue

            # Function call → check if it's a mutable source
            if isinstance(val, ast.Call):
                name = _deep_call_name(val)
                if any(s in name.lower() for s in _MUTABLE_SOURCES):
                    issues.append((f"a {name}() call", node.lineno))
                    continue
                # Chained: open(...).read()
                if isinstance(val.func, ast.Attribute):
                    if isinstance(val.func.value, ast.Call):
                        inner = _deep_call_name(val.func.value)
                        if any(s in inner.lower() for s in _MUTABLE_SOURCES):
                            issues.append((f"a file read ({inner})", node.lineno))
                            continue

            # Subscript: os.environ["KEY"]
            if isinstance(val, ast.Subscript):
                if isinstance(val.value, ast.Attribute):
                    if val.value.attr in ("environ",):
                        issues.append(("an environment variable", node.lineno))
                        continue

            # Variable → might be from a mutable source, but unknown
            # Don't fire on simple variables to avoid noise

    return issues


def _deep_call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""
