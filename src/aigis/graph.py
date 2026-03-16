"""AI Execution Graph — intermediate representation for governance analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Edge, EdgeKind, Node, NodeKind


@dataclass
class ExecutionGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node):
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge):
        self.edges.append(edge)

    def nodes_by_kind(self, kind: NodeKind) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def edges_from(self, node_id: str, kind: EdgeKind | None = None) -> list[Edge]:
        return [
            e
            for e in self.edges
            if e.source == node_id and (kind is None or e.kind == kind)
        ]

    def edges_to(self, node_id: str, kind: EdgeKind | None = None) -> list[Edge]:
        return [
            e
            for e in self.edges
            if e.target == node_id and (kind is None or e.kind == kind)
        ]
