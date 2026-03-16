"""Core data models for the AI Execution Graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TriState(Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"

    def __bool__(self):
        return self == TriState.YES


class NodeKind(Enum):
    TOOL_DEF = "tool_definition"
    ENTRY_POINT = "entry_point"
    APPROVAL_GATE = "approval_gate"
    SINK = "sink"
    BUDGET_CONTROL = "budget_control"


class EdgeKind(Enum):
    CALLS = "calls"
    REGISTERS = "registers"
    WRAPS = "wraps"


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


SEVERITY_RANK = {
    Severity.NOTE: 0,
    Severity.WARNING: 1,
    Severity.ERROR: 2,
}


@dataclass(frozen=True)
class Location:
    file: str
    line: int
    col: int = 0

    def __str__(self):
        return f"{self.file}:{self.line}:{self.col}"


@dataclass
class Node:
    id: str
    kind: NodeKind
    name: str
    location: Location
    metadata: dict = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    kind: EdgeKind


@dataclass
class Evidence:
    subject_name: str
    sink_type: str = ""
    approval_signal_found: TriState = TriState.NO
    approval_signal_kind: str = ""
    budget_signal_found: TriState = TriState.NO
    confidence: str = "high"
    rationale: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "subject_name": self.subject_name,
            "sink_type": self.sink_type,
            "approval_signal_found": self.approval_signal_found.value,
            "approval_signal_kind": self.approval_signal_kind,
            "budget_signal_found": self.budget_signal_found.value,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "remediation": self.remediation,
        }


@dataclass
class Finding:
    rule_id: str
    message: str
    location: Location
    severity: Severity
    node_id: str | None = None
    evidence: Evidence | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class RuleResult:
    rule_id: str
    findings: list[Finding] = field(default_factory=list)
    nodes_checked: int = 0
