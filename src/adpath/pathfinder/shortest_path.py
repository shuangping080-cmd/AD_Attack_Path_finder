"""Shortest confirmed path finder."""

from __future__ import annotations

from collections import deque

from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.node import Node
from adpath.models.path import AttackPath, PathType


class ShortestPathFinder:
    """Find confirmed paths from existing complete graph relationships."""

    def find(
        self,
        start: str,
        target: str,
        nodes: list[Node],
        edges: list[Edge],
        max_depth: int | None = None,
    ) -> list[AttackPath]:
        """Return confirmed shortest paths."""
        graph = ADGraph(nodes, edges)
        start_node = graph.resolve_node(start)
        target_node = graph.resolve_node(target)
        if start_node is None or target_node is None:
            return []
        path_edges = self.shortest_edges(graph, start_node.id, target_node.id, max_depth=max_depth)
        if path_edges is None:
            return []
        node_ids = [start_node.id] + [edge.target for edge in path_edges]
        path_nodes = [graph.get_node(node_id) for node_id in node_ids]
        return [
            AttackPath(
                start=start_node.id,
                target=target_node.id,
                nodes=[node for node in path_nodes if node is not None],
                edges=path_edges,
                path_type=PathType.CONFIRMED,
                score=float(len(path_edges)),
                confidence=1.0,
            )
        ]

    def shortest_edges(
        self,
        graph: ADGraph,
        start_id: str,
        target_id: str,
        max_depth: int | None = None,
    ) -> list[Edge] | None:
        """Return the shortest edge chain between two node IDs."""
        if start_id == target_id:
            return []
        queue = deque([(start_id, [])])
        visited = {start_id}
        while queue:
            node_id, path = queue.popleft()
            if max_depth is not None and len(path) >= max_depth:
                continue
            for edge in graph.out_edges(node_id):
                if edge.target in visited:
                    continue
                next_path = [*path, edge]
                if edge.target == target_id:
                    return next_path
                visited.add(edge.target)
                queue.append((edge.target, next_path))
        return None

    def reachable(
        self,
        graph: ADGraph,
        start: str,
        max_depth: int | None = None,
    ) -> list[Node]:
        """Return all nodes reachable from a start ID or name."""
        start_node = graph.resolve_node(start)
        if start_node is None:
            return []
        queue = deque([(start_node.id, 0)])
        visited = {start_node.id}
        reachable_ids: list[str] = []
        while queue:
            node_id, depth = queue.popleft()
            if max_depth is not None and depth >= max_depth:
                continue
            for edge in graph.out_edges(node_id):
                if edge.target in visited:
                    continue
                visited.add(edge.target)
                reachable_ids.append(edge.target)
                queue.append((edge.target, depth + 1))
        return [node for node_id in reachable_ids if (node := graph.get_node(node_id)) is not None]
