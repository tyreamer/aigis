"""Baseline support — snapshot current findings, fail only on new ones."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import Finding


def fingerprint(finding: Finding, base_path: str) -> str:
    """Stable fingerprint based on rule + relative path + subject.

    Intentionally excludes line numbers so the baseline survives minor
    edits that shift code around.
    """
    try:
        rel = str(Path(finding.location.file).relative_to(Path(base_path).resolve()))
    except ValueError:
        rel = finding.location.file
    subject = finding.evidence.subject_name if finding.evidence else ""
    key = f"{finding.rule_id}:{rel}:{subject}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def create_baseline(findings: list[Finding], base_path: str) -> dict:
    entries = []
    for f in findings:
        fp = fingerprint(f, base_path)
        entries.append({
            "fingerprint": fp,
            "rule_id": f.rule_id,
            "subject": f.evidence.subject_name if f.evidence else "",
            "location": str(f.location),
            "message": f.message,
        })
    return {
        "version": "1",
        "base_path": str(base_path),
        "count": len(entries),
        "findings": entries,
    }


def save_baseline(baseline: dict, path: Path):
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def filter_by_baseline(
    findings: list[Finding], baseline: dict, base_path: str
) -> tuple[list[Finding], list[Finding]]:
    """Returns (new_findings, baselined_findings)."""
    known = {e["fingerprint"] for e in baseline.get("findings", [])}
    new: list[Finding] = []
    baselined: list[Finding] = []
    for f in findings:
        fp = fingerprint(f, base_path)
        if fp in known:
            baselined.append(f)
        else:
            new.append(f)
    return new, baselined
