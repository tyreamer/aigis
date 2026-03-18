"""AIGIS021: PII-named variables passed to LLM calls.

Fires when variables with names suggesting personal data (ssn, email,
phone_number, etc.) are included in prompts or messages sent to an LLM.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS021"

_PII_NAMES = {
    "ssn", "social_security", "social_security_number",
    "email", "email_address", "phone", "phone_number",
    "dob", "date_of_birth", "birthday",
    "address", "home_address", "street_address",
    "credit_card", "card_number", "cc_number",
    "passport", "passport_number",
    "drivers_license", "license_number",
    "national_id", "bank_account", "routing_number",
    "tax_id", "ein", "itin",
}

_LLM_METHODS = {
    "invoke", "ainvoke", "generate", "predict", "chat",
    "complete", "create",
}

_LLM_RECEIVERS = {
    "llm", "model", "client", "openai", "anthropic",
    "chat_model", "chat", "gpt", "claude",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    checked_files: set[str] = set()

    for tool in graph.nodes_by_kind(NodeKind.TOOL_DEF):
        checked_files.add(tool.location.file)

    for file_path in checked_files:
        issues = _check_file(file_path)
        for loc, var_name, method_name, func_ctx in issues:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"'{var_name}' (likely personal data) is sent to "
                        f"an LLM via '{method_name}'"
                    ),
                    location=loc,
                    severity=Severity.WARNING,
                    evidence=Evidence(
                        subject_name=func_ctx or method_name,
                        sink_type=f"PII leak via {method_name}",
                        confidence="medium",
                        rationale=(
                            f"The variable '{var_name}' appears to contain personal "
                            f"data and is passed to an LLM call. LLM providers may "
                            f"log inputs, use them for training, or expose them "
                            f"through other API consumers. Sending raw PII to an LLM "
                            f"may violate privacy regulations (GDPR, CCPA, HIPAA)."
                        ),
                        remediation=(
                            f"Redact or mask '{var_name}' before sending it to the "
                            f"LLM. Use a PII redaction step, pseudonymization, or "
                            f"only send the data fields the LLM actually needs."
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

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        method = _method_name(node)
        if not method or method.lower() not in _LLM_METHODS:
            continue

        # Check receiver looks like an LLM
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if not any(p in node.func.value.id.lower() for p in _LLM_RECEIVERS):
                continue
        elif isinstance(node.func, ast.Name):
            pass  # bare function call like generate() — check args
        else:
            continue

        # Check args for PII variable names
        for arg in node.args:
            pii_vars = _find_pii_in_expr(arg)
            for var in pii_vars:
                func_ctx = _enclosing_func(tree, node.lineno)
                loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                issues.append((loc, var, method, func_ctx))

        for kw in node.keywords:
            pii_vars = _find_pii_in_expr(kw.value)
            for var in pii_vars:
                func_ctx = _enclosing_func(tree, node.lineno)
                loc = Location(file=file_path, line=node.lineno, col=node.col_offset)
                issues.append((loc, var, method, func_ctx))

    return issues


def _find_pii_in_expr(node: ast.expr) -> list[str]:
    """Find PII-named variables in an expression (including f-strings)."""
    found: list[str] = []
    if isinstance(node, ast.Name) and node.id.lower() in _PII_NAMES:
        found.append(node.id)
    elif isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                found.extend(_find_pii_in_expr(val.value))
    elif isinstance(node, ast.BinOp):
        found.extend(_find_pii_in_expr(node.left))
        found.extend(_find_pii_in_expr(node.right))
    return found


def _method_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _enclosing_func(tree: ast.AST, line: int) -> str:
    best = ""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= getattr(node, "end_lineno", line):
                best = node.name
    return best
