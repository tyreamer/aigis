"""AIGIS005: User-controlled execution budget without server-side cap.

Fires when an execution budget parameter (max_turns, recursion_limit, etc.)
receives its value from a function parameter or external input rather than
a hardcoded constant. Without a server-side ceiling, a caller can set
max_turns=999999 and run up unbounded cost/time.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity, TriState

RULE_ID = "AIGIS005"

# Budget kwargs we care about
_BUDGET_PARAMS = {
    "max_turns", "max_iterations", "max_steps", "recursion_limit",
    "max_round", "max_rounds", "max_iter", "max_retries",
    "max_consecutive_auto_reply", "timeout", "max_execution_time",
}


def check(graph: ExecutionGraph) -> RuleResult:
    findings: list[Finding] = []
    checked = 0

    # Check all BUDGET_CONTROL nodes — is the value a constant or a variable?
    for node in graph.nodes_by_kind(NodeKind.BUDGET_CONTROL):
        checked += 1
        # The budget control node has metadata with the source call info
        # We need to re-examine the AST to determine if the value is user-controlled
        file_str = node.location.file
        line = node.location.line
        param_name = node.name

        source_type = _classify_budget_value(file_str, line, param_name)
        if source_type == "variable":
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    message=(
                        f"Budget parameter '{param_name}' receives a variable value "
                        f"with no visible server-side cap"
                    ),
                    location=node.location,
                    severity=Severity.WARNING,
                    node_id=node.id,
                    evidence=Evidence(
                        subject_name=param_name,
                        confidence="medium",
                        rationale=(
                            f"The execution budget '{param_name}' at line {line} is set "
                            f"from a variable rather than a constant. If this variable "
                            f"comes from user input, the caller can set arbitrarily high "
                            f"values, leading to unbounded cost or execution time."
                        ),
                        remediation=(
                            f"Add a server-side cap: "
                            f"`{param_name} = min({param_name}, MAX_{param_name.upper()})` "
                            f"or use a hardcoded constant."
                        ),
                    ),
                )
            )

    return RuleResult(rule_id=RULE_ID, findings=findings, nodes_checked=checked)


def _classify_budget_value(file_path: str, target_line: int, param_name: str) -> str:
    """Determine if a budget kwarg at the given line uses a constant or variable."""
    try:
        source = open(file_path, encoding="utf-8").read()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return "unknown"

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if node.lineno != target_line:
            continue

        # Check kwargs on this call
        for kw in node.keywords:
            if kw.arg == param_name:
                return _classify_value(kw.value)

        # Check config dict kwargs
        for kw in node.keywords:
            if kw.arg == "config" and isinstance(kw.value, ast.Dict):
                for key, val in zip(kw.value.keys, kw.value.values):
                    if isinstance(key, ast.Constant) and key.value == param_name:
                        return _classify_value(val)

    return "unknown"


def _classify_value(node: ast.expr) -> str:
    """Classify whether an AST expression is a constant or variable."""
    if isinstance(node, ast.Constant):
        return "constant"
    if isinstance(node, ast.Name):
        # Variable — could be user-controlled
        name = node.id
        # Common safe patterns: module-level UPPER_CASE constants
        if name.isupper() or name.startswith("MAX_") or name.startswith("DEFAULT_"):
            return "constant"  # likely a config constant, not user input
        return "variable"
    if isinstance(node, ast.Call):
        # min(user_val, MAX) or int(request.param) — function call
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        if func_name == "min":
            return "constant"  # min() acts as a cap
        return "variable"
    if isinstance(node, ast.BinOp):
        return "variable"  # computed value
    if isinstance(node, ast.Attribute):
        return "variable"  # e.g. request.max_turns
    return "unknown"
