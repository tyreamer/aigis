"""AIGIS019: Embedding call on unbounded input.

Fires when an embedding function receives input without any visible
length check or truncation. Embedding large inputs costs more tokens
and can exceed model context limits.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS019"

_EMBEDDING_METHODS = {
    "embed_documents", "embed_query", "embed", "encode",
    "create_embedding", "embed_text",
}

_EMBEDDING_RECEIVERS = {
    "embeddings", "embedding", "encoder", "embed_model",
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
                        f"'{tool.name}' sends input to an embedding model "
                        f"without checking its length"
                    ),
                    location=Location(file=tool.location.file, line=line, col=0),
                    severity=Severity.NOTE,
                    node_id=tool.id,
                    evidence=Evidence(
                        subject_name=tool.name,
                        confidence="low",
                        rationale=(
                            f"This tool passes input to an embedding model without "
                            f"a visible length check or truncation step. Very large "
                            f"inputs can exceed the model's context window, increase "
                            f"costs, or cause API errors."
                        ),
                        remediation=(
                            "Add a length check before embedding: "
                            "text = text[:max_tokens] or check len(text) "
                            "against a maximum before calling the embedding API."
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

        has_embedding_call = False
        has_length_check = False
        embedding_line = func_line

        for child in ast.walk(node):
            # Check for embedding calls
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                method = child.func.attr.lower()
                if method in _EMBEDDING_METHODS:
                    if isinstance(child.func.value, ast.Name):
                        if any(p in child.func.value.id.lower() for p in _EMBEDDING_RECEIVERS):
                            has_embedding_call = True
                            embedding_line = child.lineno
                    elif method in {"embed_documents", "embed_query", "create_embedding"}:
                        has_embedding_call = True
                        embedding_line = child.lineno

            # Check for length checks / truncation
            if isinstance(child, ast.Subscript) and isinstance(child.slice, ast.Slice):
                has_length_check = True
            if isinstance(child, ast.Call):
                name = _call_name(child)
                if name in {"len", "truncate", "chunk", "split"}:
                    has_length_check = True

        if has_embedding_call and not has_length_check:
            issues.append(embedding_line)

        break

    return issues


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""
