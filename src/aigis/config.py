"""YAML configuration loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Default patterns for test file exclusion.
# These are applied unless explicitly overridden with exclude_defaults: false.
DEFAULT_EXCLUDE_PATTERNS = [
    "tests/",
    "test/",
    "test_*.py",
    "*_test.py",
    "conftest.py",
]


@dataclass
class AigisConfig:
    suppressions: list[dict] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    exclude_defaults: bool = True

    @classmethod
    def load(cls, path: Path | None = None) -> AigisConfig:
        if path is None:
            path = Path(".aigis.yaml")
        if not path.exists():
            return cls()
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(
            suppressions=data.get("suppressions", []),
            exclude_patterns=data.get("exclude_patterns", []),
            exclude_defaults=data.get("exclude_defaults", True),
        )

    @property
    def effective_excludes(self) -> list[str]:
        """Return the combined list of exclusion patterns."""
        base = list(DEFAULT_EXCLUDE_PATTERNS) if self.exclude_defaults else []
        return base + self.exclude_patterns
