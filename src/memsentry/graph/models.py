"""Graph data models for forensic relationship visualization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

NodeType = Literal["evidence", "process", "network", "finding"]


@dataclass(slots=True)
class GraphNode:
    """A single node representing an artifact or entity in the investigation graph."""

    id: str
    node_type: NodeType
    label: str
    subtitle: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    # Layout coordinates
    x: float = 0.0
    y: float = 0.0


@dataclass(slots=True)
class GraphEdge:
    """A directed relationship between two entities."""

    source_id: str
    target_id: str
    label: str
    relationship_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphData:
    """Container for the current graph snapshot."""

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set, init=False, repr=False)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source_id in self.nodes and edge.target_id in self.nodes:
            key = (edge.source_id, edge.target_id, edge.relationship_type)
            if key not in self._edge_keys:
                self._edge_keys.add(key)
                self.edges.append(edge)
