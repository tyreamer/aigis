"""Policy enforcement — pass/fail governance checks."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import RuleResult


@dataclass
class PolicyCheck:
    name: str
    description: str
    passed: bool
    violation_count: int = 0


@dataclass
class PolicyReport:
    checks: list[PolicyCheck] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed)


# Built-in policies mapped to rule IDs
_BUILTIN_POLICIES: dict[str, tuple[str, str]] = {
    "all_tools_approved": (
        "AIGIS001",
        "All dangerous tools must have an approval gate",
    ),
    "all_privileged_consented": (
        "AIGIS002",
        "All system-level tools must have a consent policy",
    ),
    "all_agents_bounded": (
        "AIGIS003",
        "All agents must have an execution budget",
    ),
    "no_unbounded_retries": (
        "AIGIS004",
        "No retry/loop patterns without a hard cap",
    ),
    "no_uncapped_budgets": (
        "AIGIS005",
        "No execution limits set from uncapped user input",
    ),
    "no_raw_history_retrieval": (
        "AIGIS006",
        "No raw chat history passed directly to retrieval",
    ),
    "no_mutable_prompts": (
        "AIGIS008",
        "No system prompts loaded from mutable sources",
    ),
    "no_input_injection": (
        "AIGIS009",
        "No agent input passed directly to dangerous sinks",
    ),
    "all_retrieval_scoped": (
        "AIGIS011",
        "All retrieval queries must have a scope/tenant filter",
    ),
    "no_unvalidated_responses": (
        "AIGIS012",
        "No external API responses returned without validation",
    ),
    "no_dynamic_tools": (
        "AIGIS015",
        "No dynamically-loaded tool lists",
    ),
    "no_llm_in_unbounded_loop": (
        "AIGIS017",
        "No LLM calls inside unbounded loops",
    ),
    "no_secrets_in_tools": (
        "AIGIS020",
        "No credentials passed as tool arguments",
    ),
    "no_pii_to_llm": (
        "AIGIS021",
        "No PII-named variables sent to LLM calls",
    ),
}


def evaluate_policy(
    policy_names: list[str],
    rule_results: list[RuleResult],
) -> PolicyReport:
    """Evaluate named policies against rule results."""
    results_by_rule = {r.rule_id: r for r in rule_results}
    report = PolicyReport()

    for name in policy_names:
        if name not in _BUILTIN_POLICIES:
            continue
        rule_id, description = _BUILTIN_POLICIES[name]
        result = results_by_rule.get(rule_id)
        violations = len(result.findings) if result else 0

        report.checks.append(PolicyCheck(
            name=name,
            description=description,
            passed=violations == 0,
            violation_count=violations,
        ))

    return report


def evaluate_all_policies(rule_results: list[RuleResult]) -> PolicyReport:
    """Evaluate all built-in policies."""
    return evaluate_policy(list(_BUILTIN_POLICIES.keys()), rule_results)


def format_policy_console(report: PolicyReport) -> str:
    lines = ["", "GOVERNANCE POLICY", "=" * 50, ""]

    status = "PASS" if report.passed else "FAIL"
    lines.append(f"Status: {status} ({report.passed_count}/{report.total} checks passed)")
    lines.append("")

    for check in report.checks:
        icon = "PASS" if check.passed else "FAIL"
        line = f"  [{icon}] {check.description}"
        if not check.passed:
            line += f" ({check.violation_count} violation{'s' if check.violation_count != 1 else ''})"
        lines.append(line)

    lines.append("")
    return "\n".join(lines)
