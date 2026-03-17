"""AIGIS006: Raw chat history used directly as retrieval query.

Fires when a retrieval/search/query function receives a chat history
variable directly without a rewriting, condensing, or extraction step.
Passing raw multi-turn conversation directly to retrieval degrades
relevance and can leak context across turns.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AIGIS006"

# Variable names that typically hold raw chat history
_HISTORY_NAMES = {
    "messages", "chat_history", "history", "conversation",
    "conversation_history", "chat_messages", "message_history",
    "dialog", "dialogue", "transcript", "turns",
}

# Function/method names that indicate retrieval operations
_RETRIEVAL_METHODS = {
    "retrieve", "search", "query", "similarity_search",
    "similarity_search_with_score", "as_retriever", "get_relevant_documents",
    "invoke", "ainvoke", "retrieve_documents", "vector_search",
    "semantic_search", "retriever", "rag_query",
}

# Kwarg names that indicate a query input
_QUERY_KWARGS = {"query", "input", "question", "search_query", "text", "prompt"}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    tools = graph.nodes_by_kind(NodeKind.TOOL_DEF)
    # Also check all functions in files with tools (for orchestration code)
    checked_files: set[str] = set()

    for tool in tools:
        checked_files.add(tool.location.file)
        issues = _check_file(tool.location.file)
        for loc, func_name, var_name, method_name in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"Raw chat history '{var_name}' passed directly to "
                        f"retrieval call '{method_name}' without rewriting"
                    ),
                    location=loc,
                    severity=Severity.WARNING,
                    evidence=Evidence(
                        subject_name=func_name or method_name,
                        sink_type=f"retrieval:{method_name}",
                        confidence="medium",
                        rationale=(
                            f"Variable '{var_name}' (likely raw chat history) is "
                            f"passed directly to '{method_name}' without a condensing "
                            f"or query rewriting step. Raw multi-turn transcripts "
                            f"degrade retrieval relevance and can leak conversational "
                            f"context into search results."
                        ),
                        remediation=(
                            "Add a query rewriting step before retrieval: extract the "
                            "latest user intent, condense the conversation, or use a "
                            "dedicated query formulation chain."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=len(checked_files))


def _check_file(file_path: str) -> list[tuple[Location, str, str, str]]:
    """Find instances of raw history variables passed to retrieval calls."""
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    issues: list[tuple[Location, str, str, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        method_name = _call_method_name(node)
        if not method_name or method_name.lower() not in _RETRIEVAL_METHODS:
            continue

        # Check positional args for history variable names
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id.lower() in _HISTORY_NAMES:
                func_ctx = _enclosing_func_name(tree, node.lineno)
                loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                issues.append((loc, func_ctx, arg.id, method_name))

        # Check keyword args
        for kw in node.keywords:
            if kw.arg and kw.arg.lower() in _QUERY_KWARGS:
                if isinstance(kw.value, ast.Name) and kw.value.id.lower() in _HISTORY_NAMES:
                    func_ctx = _enclosing_func_name(tree, node.lineno)
                    loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                    issues.append((loc, func_ctx, kw.value.id, method_name))

    return issues


def _call_method_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _enclosing_func_name(tree: ast.AST, target_line: int) -> str:
    """Find the name of the function containing a given line."""
    best = ""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= target_line <= node.end_lineno:
                best = node.name
    return best
