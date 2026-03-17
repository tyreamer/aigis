"""Output formatters — console, JSON, SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .models import Finding, RuleResult, Severity


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

def format_console(
    results: list[RuleResult],
    target: str,
    suppressed_count: int = 0,
    baselined_count: int = 0,
) -> str:
    lines = [
        f"aigis v{__version__} - AI Execution Governance Linter",
        f"Scanning: {target}",
        "",
    ]

    all_findings = _collect_findings(results)

    if not all_findings:
        lines.append("  No findings.")
    else:
        for f in all_findings:
            sev = f.severity.value.upper()
            lines.append(f"  {f.rule_id}  {sev:7s}  {f.location}")
            lines.append(f"    {f.message}")
            if f.evidence:
                ev = f.evidence
                parts = []
                if ev.sink_type:
                    parts.append(f"sink={ev.sink_type}")
                if ev.approval_signal_found.value != "unknown":
                    parts.append(f"approval={ev.approval_signal_found.value}")
                if ev.approval_signal_kind:
                    parts.append(f"via={ev.approval_signal_kind}")
                if ev.budget_signal_found.value != "unknown" and f.rule_id == "AEG003":
                    parts.append(f"budget={ev.budget_signal_found.value}")
                parts.append(f"confidence={ev.confidence}")
                lines.append(f"    Evidence: {' | '.join(parts)}")
                if ev.remediation:
                    lines.append(f"    Fix: {ev.remediation}")
            lines.append("")

    # Summary by rule
    rule_counts: dict[str, dict[str, int]] = {}
    for f in all_findings:
        rc = rule_counts.setdefault(f.rule_id, {"error": 0, "warning": 0, "note": 0})
        rc[f.severity.value] += 1

    if rule_counts:
        lines.append("Summary by rule:")
        for rid in sorted(rule_counts):
            counts = rule_counts[rid]
            parts = []
            for sev_name in ("error", "warning", "note"):
                if counts[sev_name]:
                    parts.append(f"{counts[sev_name]} {sev_name}")
            lines.append(f"  {rid}  {', '.join(parts)}")
        lines.append("")

    errors = sum(1 for f in all_findings if f.severity == Severity.ERROR)
    warnings = sum(1 for f in all_findings if f.severity == Severity.WARNING)
    summary = f"Found {len(all_findings)} finding(s) ({errors} error, {warnings} warning)"
    extras = []
    if suppressed_count:
        extras.append(f"{suppressed_count} suppressed")
    if baselined_count:
        extras.append(f"{baselined_count} baselined")
    if extras:
        summary += f" | {', '.join(extras)}"
    lines.append(summary)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def format_json(
    results: list[RuleResult],
    target: str,
    suppressed_count: int = 0,
    baselined_count: int = 0,
) -> str:
    all_findings = _collect_findings(results)
    payload = {
        "version": __version__,
        "target": target,
        "findings": [_finding_to_json(f) for f in all_findings],
        "summary": {
            "total": len(all_findings),
            "errors": sum(1 for f in all_findings if f.severity == Severity.ERROR),
            "warnings": sum(1 for f in all_findings if f.severity == Severity.WARNING),
            "suppressed": suppressed_count,
            "baselined": baselined_count,
        },
    }
    return json.dumps(payload, indent=2)


def _finding_to_json(f: Finding) -> dict:
    d: dict = {
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "message": f.message,
        "location": {"file": f.location.file, "line": f.location.line, "col": f.location.col},
    }
    if f.evidence:
        d["evidence"] = f.evidence.to_dict()
    return d


# ---------------------------------------------------------------------------
# SARIF v2.1.0
# ---------------------------------------------------------------------------

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

RULE_METADATA = {
    "AEG001": {
        "name": "UnguardedMutatingSink",
        "shortDescription": "Mutating tool reachable without approval gate",
    },
    "AEG002": {
        "name": "PrivilegedNoConsent",
        "shortDescription": "Privileged tool lacks explicit consent/policy wrapper",
    },
    "AEG003": {
        "name": "MissingExecutionBudget",
        "shortDescription": "Missing max-iterations / execution budget",
    },
}

_SEV_TO_SARIF = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.NOTE: "note",
}


def format_sarif(
    results: list[RuleResult],
    target: str,
    suppressed_count: int = 0,
    baselined_count: int = 0,
) -> str:
    all_findings = _collect_findings(results)
    used_rules = sorted({f.rule_id for f in all_findings})

    rules = []
    for rid in used_rules:
        meta = RULE_METADATA.get(rid, {"name": rid, "shortDescription": rid})
        rules.append({
            "id": rid,
            "name": meta["name"],
            "shortDescription": {"text": meta["shortDescription"]},
            "defaultConfiguration": {
                "level": _SEV_TO_SARIF.get(
                    next((f.severity for f in all_findings if f.rule_id == rid), Severity.WARNING),
                    "warning",
                )
            },
        })

    sarif_results = []
    for f in all_findings:
        try:
            rel_path = str(Path(f.location.file).relative_to(Path(target).resolve()))
        except ValueError:
            rel_path = f.location.file

        entry: dict = {
            "ruleId": f.rule_id,
            "level": _SEV_TO_SARIF.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel_path},
                        "region": {"startLine": f.location.line, "startColumn": f.location.col + 1},
                    }
                }
            ],
        }
        if f.evidence:
            entry["properties"] = {"evidence": f.evidence.to_dict()}
        sarif_results.append(entry)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aigis",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _collect_findings(results: list[RuleResult]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        findings.extend(r.findings)
    return sorted(findings, key=lambda f: (f.location.file, f.location.line))
