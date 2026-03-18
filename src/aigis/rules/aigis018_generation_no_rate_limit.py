"""AIGIS018: Image/audio generation tool with no rate limit.

Fires when a tool calls an expensive generation API (image, audio,
video) without any visible rate-limiting mechanism. Each generation
call can cost $0.01-$1+ — an unbounded tool can drain a budget fast.
"""

from __future__ import annotations

import ast

from ..graph import ExecutionGraph
from ..models import Evidence, Finding, Location, NodeKind, RuleResult, Severity

RULE_ID = "AIGIS018"

_GENERATION_METHODS = {
    "generate", "create_image", "create_images", "text_to_speech",
    "create_speech", "image_generate", "generate_image",
    "create_variation", "create_edit",
}

_GENERATION_RECEIVERS = {
    "images", "audio", "dalle", "stability", "elevenlabs",
    "replicate", "midjourney", "speech",
}

_RATE_LIMIT_SIGNALS = {
    "ratelimit", "throttle", "rate_limit", "sleep",
    "semaphore", "limiter", "cooldown", "backoff",
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
                        f"'{tool.name}' calls a generation API with no rate limit "
                        f"— each call costs money"
                    ),
                    location=Location(file=tool.location.file, line=line, col=0),
                    severity=Severity.WARNING,
                    node_id=tool.id,
                    evidence=Evidence(
                        subject_name=tool.name,
                        confidence="medium",
                        rationale=(
                            f"This tool calls an expensive generation API (image, "
                            f"audio, or similar) without any visible rate-limiting. "
                            f"If the agent calls this tool repeatedly, each call "
                            f"incurs cost. Without a rate limit, a runaway agent "
                            f"can quickly exhaust an API budget."
                        ),
                        remediation=(
                            "Add a rate limit to this tool. For example: "
                            "@ratelimit(calls=10, period=60), a time.sleep() "
                            "between calls, or a semaphore/counter."
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

        # Check decorators for rate limiting
        for dec in node.decorator_list:
            dec_name = _dec_name(dec).lower()
            if any(p in dec_name for p in _RATE_LIMIT_SIGNALS):
                return []  # has rate limit, skip

        has_generation_call = False
        has_rate_limit = False

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = _call_name(child).lower()
                # Check for generation call
                if name in _GENERATION_METHODS:
                    if isinstance(child.func, ast.Attribute) and isinstance(child.func.value, ast.Name):
                        if any(p in child.func.value.id.lower() for p in _GENERATION_RECEIVERS):
                            has_generation_call = True
                    elif name in {"generate_image", "create_image", "text_to_speech"}:
                        has_generation_call = True

                # Check for rate limiting
                if any(p in name for p in _RATE_LIMIT_SIGNALS):
                    has_rate_limit = True

        if has_generation_call and not has_rate_limit:
            issues.append(func_line)

        break

    return issues


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _dec_name(dec: ast.expr) -> str:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Call):
        return _dec_name(dec.func)
    if isinstance(dec, ast.Attribute):
        return dec.attr
    return ""
