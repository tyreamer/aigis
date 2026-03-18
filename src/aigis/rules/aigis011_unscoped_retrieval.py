"""AIGIS011: Retrieval query with no tenant or scope filter.

Fires when a vector search or retrieval call has no filter, where,
or namespace parameter. In multi-tenant systems, unscoped retrieval
can return data from other users or organizations.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS011"

_RETRIEVAL_METHODS = {
    "similarity_search", "similarity_search_with_score",
    "max_marginal_relevance_search", "get_relevant_documents",
    "retrieve", "vector_search", "semantic_search", "query",
}

_FILTER_KWARGS = {
    "filter", "filters", "where", "where_document", "metadata_filter",
    "namespace", "tenant_id", "tenant", "scope", "collection",
    "search_filter", "pre_filter", "post_filter",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    checked_files: set[str] = set()

    for tool in graph.nodes_by_kind(NodeKind.TOOL_DEF):
        checked_files.add(tool.location.file)

    for file_path in checked_files:
        issues = _check_file(file_path)
        for loc, method_name, func_ctx in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"'{method_name}' retrieves data with no scope or "
                        f"tenant filter — results may include other users' data"
                    ),
                    location=loc,
                    severity=Severity.WARNING,
                    evidence=Evidence(
                        subject_name=func_ctx or method_name,
                        sink_type=f"retrieval:{method_name}",
                        confidence="medium",
                        rationale=(
                            f"The retrieval call '{method_name}' has no filter, "
                            f"namespace, or tenant parameter. In a multi-tenant "
                            f"system, this means the search could return documents "
                            f"belonging to other users or organizations."
                        ),
                        remediation=(
                            "Add a scope filter to the retrieval call — for example: "
                            "filter={'tenant_id': current_tenant} or "
                            "namespace=user_namespace."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(checked_files))


def _check_file(file_path: str) -> list[tuple[Location, str, str]]:
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    issues: list[tuple[Location, str, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue

        method = node.func.attr.lower()
        if method not in _RETRIEVAL_METHODS:
            continue

        # Check if any filter-like kwarg is present
        has_filter = any(
            kw.arg and kw.arg.lower() in _FILTER_KWARGS
            for kw in node.keywords
        )

        if not has_filter:
            func_ctx = _enclosing_func(tree, node.lineno)
            loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
            issues.append((loc, node.func.attr, func_ctx))

    return issues


def _enclosing_func(tree: ast.AST, line: int) -> str:
    best = ""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= getattr(node, "end_lineno", line):
                best = node.name
    return best
