"""Privilege-oriented path finder."""

from __future__ import annotations

from collections import deque

from adpath.detectors.privilege import PrivilegeDetector
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import dedupe_missing
from adpath.models.node import Node
from adpath.models.path import AttackPath, PathType
from adpath.models.privilege import PrivilegeTier, PrivilegeTransition


class PrivilegePathFinder:
    """Find paths that cross privilege tiers or reach high-value targets."""

    def __init__(self, detector: PrivilegeDetector | None = None) -> None:
        self.detector = detector or PrivilegeDetector()

    def find(
        self,
        start: str,
        nodes: list[Node],
        edges: list[Edge],
        max_depth: int | None = None,
        target_type: str | None = None,
        high_value_only: bool = False,
        top_n: int | None = None,
    ) -> list[AttackPath]:
        """Return privilege-oriented paths."""
        graph = ADGraph(nodes, edges)
        start_node = graph.resolve_node(start)
        if start_node is None:
            return []
        transition_by_edge = {
            (item.source, item.relationship, item.target): item
            for item in self.detector.transitions(graph)
        }
        queue = deque([(start_node.id, [], [], {start_node.id})])
        best_by_target: dict[str, AttackPath] = {}
        while queue:
            node_id, path_edges, path_transitions, visited = queue.popleft()
            if max_depth is not None and len(path_edges) >= max_depth:
                continue
            for edge in graph.out_edges(node_id):
                if edge.target in visited:
                    continue
                key = (edge.source, edge.relationship, edge.target)
                transition = transition_by_edge.get(key)
                if transition is None:
                    continue
                next_edges = [*path_edges, edge]
                next_transitions = [*path_transitions, transition]
                target_node = graph.get_node(edge.target)
                if target_node and self._is_interesting_target(target_node, transition, target_type, high_value_only):
                    path = self._build_path(graph, start_node.id, next_edges, next_transitions)
                    current_best = best_by_target.get(path.target)
                    if current_best is None or path.score > current_best.score:
                        best_by_target[path.target] = path
                queue.append((edge.target, next_edges, next_transitions, {*visited, edge.target}))
        results = sorted(best_by_target.values(), key=lambda path: path.score, reverse=True)
        if top_n is not None:
            return results[:top_n]
        return results

    def _is_interesting_target(
        self,
        target: Node,
        transition: PrivilegeTransition,
        target_type: str | None,
        high_value_only: bool,
    ) -> bool:
        if target_type and str(target.type).casefold() != target_type.casefold():
            return False
        if high_value_only and not target.properties.get("highvalue") and transition.target_tier != PrivilegeTier.TIER0:
            return False
        return transition.gain > 0 or transition.key_edge

    def _build_path(
        self,
        graph: ADGraph,
        start_id: str,
        edges: list[Edge],
        transitions: list[PrivilegeTransition],
    ) -> AttackPath:
        node_ids = [start_id] + [edge.target for edge in edges]
        nodes = [node for node_id in node_ids if (node := graph.get_node(node_id)) is not None]
        missing = []
        for transition in transitions:
            missing.extend(transition.missing_information)
        missing = dedupe_missing(missing)
        gain = sum(transition.gain for transition in transitions)
        gain -= self._duplicate_semantic_gain_penalty(edges, transitions)
        confidence = min((transition.confidence for transition in transitions), default=1.0)
        boundary_crossings = sum(1 for transition in transitions if transition.boundary and transition.boundary.crosses)
        high_value_bonus = 1 if nodes and nodes[-1].properties.get("highvalue") else 0
        confirmed_edges = sum(1 for transition in transitions if transition.confirmed)
        score = gain + (boundary_crossings * 2) + high_value_bonus + confidence + (confirmed_edges * 0.25) - len(edges) - len(missing) * 0.25
        path_type = PathType.INCOMPLETE if missing else PathType.CANDIDATE
        return AttackPath(
            start=start_id,
            target=edges[-1].target,
            nodes=nodes,
            edges=edges,
            path_type=path_type,
            score=score,
            confidence=confidence,
            missing_information=missing,
        )

    def _duplicate_semantic_gain_penalty(
        self,
        edges: list[Edge],
        transitions: list[PrivilegeTransition],
    ) -> int:
        """Avoid scoring multiple semantic interpretations derived from the same raw edge."""
        seen: set[str] = set()
        penalty = 0
        for edge, transition in zip(edges, transitions, strict=False):
            derived_from = edge.properties.get("derived_from") if edge.source_tool == "semantic" else None
            if not derived_from:
                continue
            key = "|".join(str(item) for item in derived_from)
            if key in seen:
                penalty += transition.gain
            seen.add(key)
        return penalty
