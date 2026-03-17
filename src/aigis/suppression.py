"""Suppression logic — inline comments and config-based."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from .models import Finding

# Matches:  # aigis: disable=AIGIS001  or  # noqa: AIGIS001
# Optional reason after --:  # aigis: disable=AIGIS001 -- known safe
INLINE_RE = re.compile(
    r"#\s*(?:aigis:\s*disable|noqa)\s*[=:]\s*([A-Z0-9_,\s]+?)(?:\s+--\s*(.+))?$"
)


class SuppressionFilter:
    def __init__(self, config_suppressions: list[dict] | None = None):
        self.config_suppressions = config_suppressions or []
        self._file_cache: dict[str, list[str]] = {}

    def _get_lines(self, file_path: str) -> list[str]:
        if file_path not in self._file_cache:
            try:
                self._file_cache[file_path] = (
                    Path(file_path).read_text(encoding="utf-8").splitlines()
                )
            except (OSError, UnicodeDecodeError):
                self._file_cache[file_path] = []
        return self._file_cache[file_path]

    def is_inline_suppressed(self, finding: Finding) -> tuple[bool, str]:
        lines = self._get_lines(finding.location.file)
        line_idx = finding.location.line - 1

        # Check the finding's line and the line immediately above it
        for idx in (line_idx, line_idx - 1):
            if 0 <= idx < len(lines):
                match = INLINE_RE.search(lines[idx])
                if match:
                    rule_ids = {r.strip() for r in match.group(1).split(",")}
                    if finding.rule_id in rule_ids or "ALL" in rule_ids:
                        reason = (match.group(2) or "").strip()
                        return True, reason
        return False, ""

    def is_config_suppressed(self, finding: Finding) -> tuple[bool, str]:
        for supp in self.config_suppressions:
            rule = supp.get("rule", "")
            path_glob = supp.get("path", "")
            symbol = supp.get("symbol", "")
            reason = supp.get("reason", "")

            if rule and rule != finding.rule_id:
                continue
            if path_glob and not fnmatch.fnmatch(finding.location.file, path_glob):
                # Also try with forward slashes
                normalized = finding.location.file.replace("\\", "/")
                if not fnmatch.fnmatch(normalized, path_glob):
                    continue
            if symbol:
                subject = finding.evidence.subject_name if finding.evidence else ""
                if subject != symbol:
                    continue
            return True, reason
        return False, ""

    def filter(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Returns (active_findings, suppressed_findings)."""
        active: list[Finding] = []
        suppressed: list[Finding] = []

        for f in findings:
            is_supp, _ = self.is_inline_suppressed(f)
            if is_supp:
                suppressed.append(f)
                continue
            is_supp, _ = self.is_config_suppressed(f)
            if is_supp:
                suppressed.append(f)
                continue
            active.append(f)

        return active, suppressed
