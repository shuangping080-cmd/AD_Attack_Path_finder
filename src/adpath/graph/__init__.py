"""Graph construction and query utilities."""

from __future__ import annotations

import json
from pathlib import Path

from adpath.models.edge import Edge
from adpath.models.node import Node


class ADGraph:
    """In-memory normalized AD graph with de-duplicated nodes and edges."""

    def __init__(self, nodes: list[Node] | None = None, edges: list[Edge] | None = None) -> None:
        self._nodes: dict[str, Node] = {}
        self._name_index: dict[str, set[str]] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}
        self._out_edges: dict[str, list[Edge]] = {}
        self._in_edges: dict[str, list[Edge]] = {}
        for node in nodes or []:
            self.add_node(node)
        for edge in edges or []:
            self.add_edge(edge)

    @property
    def nodes(self) -> list[Node]:
        """Return nodes sorted by stable identifier."""
        return [self._nodes[node_id] for node_id in sorted(self._nodes)]

    @property
    def edges(self) -> list[Edge]:
        """Return edges sorted by source, relationship, target."""
        return [self._edges[key] for key in sorted(self._edges)]

    def add_node(self, node: Node) -> None:
        """Add or merge a node."""
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
        else:
            existing.properties.update(node.properties)
            if not existing.name and node.name:
                existing.name = node.name
            if existing.domain is None and node.domain:
                existing.domain = node.domain
        self._name_index.setdefault(node.name.casefold(), set()).add(node.id)
        short_name = node.name.split("@", 1)[0].casefold()
        self._name_index.setdefault(short_name, set()).add(node.id)
        sam = node.properties.get("samaccountname")
        if sam:
            sam_name = str(sam).casefold()
            self._name_index.setdefault(sam_name, set()).add(node.id)
            if node.domain:
                self._name_index.setdefault(f"{sam_name}@{node.domain.casefold()}", set()).add(node.id)
            if sam_name.endswith("$"):
                hostname = sam_name.rstrip("$")
                self._name_index.setdefault(hostname, set()).add(node.id)
                if node.domain:
                    self._name_index.setdefault(f"{hostname}.{node.domain.casefold()}", set()).add(node.id)

    def add_edge(self, edge: Edge) -> None:
        """Add an edge if it is not already present."""
        key = (edge.source, edge.relationship, edge.target)
        if key in self._edges:
            return
        self._edges[key] = edge
        self._out_edges.setdefault(edge.source, []).append(edge)
        self._in_edges.setdefault(edge.target, []).append(edge)

    def get_node(self, node_id: str) -> Node | None:
        """Find a node by ID."""
        return self._nodes.get(node_id)

    def find_nodes_by_name(self, name: str) -> list[Node]:
        """Find nodes by full BloodHound name or short account name."""
        ids = self._name_index.get(name.casefold(), set())
        return [self._nodes[node_id] for node_id in sorted(ids)]

    def resolve_node(self, ref: str) -> Node | None:
        """Resolve an ID or unique name reference to one node."""
        if ref in self._nodes:
            return self._nodes[ref]
        matches = self.find_nodes_by_name(ref)
        return matches[0] if matches else None

    def out_edges(self, node_id: str, relationship: str | None = None) -> list[Edge]:
        """Return outgoing edges, optionally filtered by relationship."""
        edges = self._out_edges.get(node_id, [])
        if relationship is None:
            return list(edges)
        return [edge for edge in edges if edge.relationship == relationship]

    def in_edges(self, node_id: str, relationship: str | None = None) -> list[Edge]:
        """Return incoming edges, optionally filtered by relationship."""
        edges = self._in_edges.get(node_id, [])
        if relationship is None:
            return list(edges)
        return [edge for edge in edges if edge.relationship == relationship]

    def edges_by_relationship(self, relationship: str) -> list[Edge]:
        """Return all edges with the requested relationship."""
        return [edge for edge in self.edges if edge.relationship == relationship]

    def to_dict(self) -> dict[str, object]:
        """Return normalized graph JSON."""
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ADGraph:
        """Build a graph from normalized graph JSON."""
        nodes = [Node.from_dict(item) for item in data.get("nodes", [])]  # type: ignore[arg-type]
        edges = [Edge.from_dict(item) for item in data.get("edges", [])]  # type: ignore[arg-type]
        return cls(nodes=nodes, edges=edges)

    def write_normalized(self, output_dir: Path | str) -> None:
        """Write nodes.json, edges.json, and graph.json."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        nodes_json = [node.to_dict() for node in self.nodes]
        edges_json = [edge.to_dict() for edge in self.edges]
        (out / "nodes.json").write_text(json.dumps(nodes_json, indent=2), encoding="utf-8")
        (out / "edges.json").write_text(json.dumps(edges_json, indent=2), encoding="utf-8")
        (out / "graph.json").write_text(
            json.dumps({"nodes": nodes_json, "edges": edges_json}, indent=2),
            encoding="utf-8",
        )

    @classmethod
    def read_normalized(cls, path: Path | str) -> ADGraph:
        """Read graph.json, or nodes.json and edges.json from a directory."""
        base = Path(path)
        graph_path = base / "graph.json" if base.is_dir() else base
        if graph_path.exists():
            return cls.from_dict(json.loads(graph_path.read_text(encoding="utf-8")))
        nodes = json.loads((base / "nodes.json").read_text(encoding="utf-8"))
        edges = json.loads((base / "edges.json").read_text(encoding="utf-8"))
        return cls.from_dict({"nodes": nodes, "edges": edges})


__all__ = ["ADGraph"]
