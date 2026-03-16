"""YAML configuration loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AigisConfig:
    suppressions: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None = None) -> AigisConfig:
        if path is None:
            path = Path(".aigis.yaml")
        if not path.exists():
            return cls()
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(suppressions=data.get("suppressions", []))
