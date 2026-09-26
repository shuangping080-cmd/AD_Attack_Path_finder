"""Match observed records against reusable attack pattern definitions."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adpath.graph import ADGraph
from adpath.knowledge.loader import KnowledgeBaseLoader
from adpath.models.edge import Edge
from adpath.models.node import Node
from adpath.models.primitive import AttackPrimitive


@dataclass(slots=True)
class PatternStep:
    """One ordered attack-pattern step."""

    order: int
    source_type: str
    target_type: str
    relationship: str | None = None
    primitive: str | None = None
    required: bool = True
    confirmed_if_edge_exists: bool = True
    missing_if_absent: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: dict[str, Any], order: int) -> "PatternStep":
        """Build a step from YAML."""
        return cls(
            order=int(data.get("order") or order),
            source_type=str(data.get("source_type") or "*"),
            target_type=str(data.get("target_type") or "*"),
            relationship=str(data["relationship"]) if data.get("relationship") else None,
            primitive=str(data["primitive"]) if data.get("primitive") else None,
            required=bool(data.get("required", True)),
            confirmed_if_edge_exists=bool(data.get("confirmed_if_edge_exists", True)),
            missing_if_absent=dict(data.get("missing_if_absent") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable step data."""
        return {
            "order": self.order,
            "source_type": self.source_type,
            "relationship": self.relationship,
            "target_type": self.target_type,
            "primitive": self.primitive,
            "required": self.required,
            "confirmed_if_edge_exists": self.confirmed_if_edge_exists,
            "missing_if_absent": self.missing_if_absent,
        }


@dataclass(slots=True)
class PatternMatch:
    """Structural attack-pattern match result."""

    name: str
    pattern_key: str
    score: float
    confidence: float = 0.0
    matched_nodes: list[Node] = field(default_factory=list)
    matched_edges: list[Edge] = field(default_factory=list)
    matched_steps: list[PatternStep] = field(default_factory=list)
    missing_steps: list[PatternStep] = field(default_factory=list)
    matched_primitives: list[str] = field(default_factory=list)
    missing_relationships: list[str] = field(default_factory=list)
    missing_primitives: list[str] = field(default_factory=list)
    examples: list[dict[str, Any]] = field(default_factory=list)

    @property
    def partial(self) -> bool:
        """Return whether this is a partial structural match."""
        return bool(self.missing_steps or self.missing_relationships or self.missing_primitives)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable match data."""
        return {
            "pattern_name": self.name,
            "pattern_key": self.pattern_key,
            "score": self.score,
            "confidence": self.confidence,
            "matched_nodes": [node.to_dict() for node in self.matched_nodes],
            "confirmed_edges": [edge.to_dict() for edge in self.matched_edges],
            "matched_steps": [step.to_dict() for step in self.matched_steps],
            "missing_steps": [step.to_dict() for step in self.missing_steps],
            "matched_primitives": self.matched_primitives,
            "missing_relationships": self.missing_relationships,
            "missing_primitives": self.missing_primitives,
            "examples": self.examples,
        }


AttackPatternMatch = PatternMatch


class AttackPatternMatcher:
    """Conservative pattern matcher for reviewed evidence-backed records."""

    def __init__(self, root: Path | str = "knowledge-base") -> None:
        self.loader = KnowledgeBaseLoader(root)

    def match_machine(self, machine_record: dict[str, Any]) -> list[str]:
        """Return names of patterns whose required relationships and primitives are present."""
        relationships = {item.get("relation") for item in machine_record.get("relationships", [])}
        primitives = {item.get("name") for item in machine_record.get("attack_primitives", [])}
        matches: list[str] = []
        for key, pattern in self.loader.attack_patterns().items():
            required_relationships = set(pattern.get("required_relationships", []))
            required_primitives = set(pattern.get("required_primitives", []))
            if required_relationships <= relationships and required_primitives <= primitives:
                matches.append(pattern.get("name", key))
        return matches

    def match_graph(
        self,
        nodes: list[Node],
        edges: list[Edge],
        primitives: list[AttackPrimitive] | None = None,
        allow_partial: bool = True,
    ) -> list[AttackPatternMatch]:
        """Match graph paths against ordered relationship and node-type patterns."""
        graph = ADGraph(nodes, edges)
        primitive_names = {primitive.name for primitive in primitives or []}
        matches: list[PatternMatch] = []
        for key, pattern in self.loader.attack_patterns().items():
            steps = self._steps_for_pattern(pattern)
            required_steps = [step for step in steps if step.required]
            if not steps:
                continue
            pattern_matches = self._match_relationship_sequence(
                graph,
                steps,
                allow_partial,
            )
            required_primitives = [step.primitive for step in steps if step.primitive]
            for matched_nodes, matched_edges, matched_steps, missing_steps in pattern_matches:
                missing_primitives = [item for item in required_primitives if item not in primitive_names]
                missing_relationships = [step.relationship for step in missing_steps if step.relationship]
                if not allow_partial and (missing_relationships or missing_primitives):
                    continue
                score = self._score(pattern, required_steps, matched_edges, missing_steps, missing_primitives)
                matches.append(
                    PatternMatch(
                        name=str(pattern.get("name") or key),
                        pattern_key=key,
                        score=score,
                        confidence=self._confidence(pattern, matched_steps, missing_steps),
                        matched_nodes=matched_nodes,
                        matched_edges=matched_edges,
                        matched_steps=matched_steps,
                        missing_steps=missing_steps,
                        matched_primitives=[item for item in required_primitives if item in primitive_names],
                        missing_relationships=missing_relationships,
                        missing_primitives=missing_primitives,
                        examples=[dict(item) for item in pattern.get("examples", []) if isinstance(item, dict)],
                    )
                )
        return sorted(matches, key=lambda item: item.score, reverse=True)

    def _match_relationship_sequence(
        self,
        graph: ADGraph,
        steps: list[PatternStep],
        allow_partial: bool,
    ) -> list[tuple[list[Node], list[Edge], list[PatternStep], list[PatternStep]]]:
        matches: list[tuple[list[Node], list[Edge], list[PatternStep], list[PatternStep]]] = []
        start_type = steps[0].source_type if steps else None
        for start in graph.nodes:
            if start_type and not self._type_matches(start, start_type):
                continue
            self._walk_pattern(
                graph,
                steps,
                start,
                [],
                [start],
                [],
                allow_partial,
                matches,
            )
        return matches

    def _walk_pattern(
        self,
        graph: ADGraph,
        steps: list[PatternStep],
        current: Node,
        matched_edges: list[Edge],
        matched_nodes: list[Node],
        matched_steps: list[PatternStep],
        allow_partial: bool,
        matches: list[tuple[list[Node], list[Edge], list[PatternStep], list[PatternStep]]],
    ) -> None:
        index = len(matched_edges)
        if index == len(steps):
            matches.append((matched_nodes, matched_edges, matched_steps, []))
            return
        step = steps[index]
        if not self._type_matches(current, step.source_type):
            return
        if not step.relationship:
            if allow_partial:
                matches.append((matched_nodes, matched_edges, matched_steps, steps[index:]))
            return
        candidates = [
            edge
            for edge in graph.out_edges(current.id, step.relationship)
            if graph.get_node(edge.target) is not None
            and self._type_matches(graph.get_node(edge.target), step.target_type)
        ]
        if not candidates:
            if not step.required:
                if allow_partial and matched_edges:
                    matches.append((matched_nodes, matched_edges, matched_steps, steps[index:]))
                return
            if allow_partial and matched_edges:
                matches.append((matched_nodes, matched_edges, matched_steps, steps[index:]))
            return
        for edge in candidates:
            target = graph.get_node(edge.target)
            if target is None or target.id in {node.id for node in matched_nodes}:
                continue
            self._walk_pattern(
                graph,
                steps,
                target,
                [*matched_edges, edge],
                [*matched_nodes, target],
                [*matched_steps, step],
                allow_partial,
                matches,
            )

    def _type_matches(self, node: Node | None, expected: str) -> bool:
        if node is None:
            return False
        if expected == "*":
            return True
        return str(node.type).casefold() == expected.casefold()

    def _steps_for_pattern(self, pattern: dict[str, Any]) -> list[PatternStep]:
        raw_steps = pattern.get("steps") or []
        if raw_steps:
            return [
                PatternStep.from_mapping(step, index)
                for index, step in enumerate(raw_steps, start=1)
                if isinstance(step, dict)
            ]
        relationships = [str(item) for item in pattern.get("required_relationships", [])]
        nodes = [str(item) for item in pattern.get("required_nodes", [])]
        primitives = [str(item) for item in pattern.get("required_primitives", [])]
        steps = []
        for index, relationship in enumerate(relationships, start=1):
            source_type = nodes[index - 1] if index - 1 < len(nodes) else "*"
            target_type = nodes[index] if index < len(nodes) else "*"
            steps.append(
                PatternStep(
                    order=index,
                    source_type=source_type,
                    relationship=relationship,
                    target_type=target_type,
                    primitive=primitives[index - 1] if index - 1 < len(primitives) else None,
                )
            )
        return steps

    def _score(
        self,
        pattern: dict[str, Any],
        required_steps: list[PatternStep],
        matched_edges: list[Edge],
        missing_steps: list[PatternStep],
        missing_primitives: list[str],
    ) -> float:
        confidence_bonus = {"high": 0.3, "medium": 0.2, "low": 0.1}.get(str(pattern.get("confidence", "")).casefold(), 0.0)
        coverage = len(matched_edges) / max(len(required_steps), 1)
        single_source_penalty = 0.1 if int(pattern.get("source_count") or 0) <= 1 else 0.0
        return coverage + confidence_bonus - (len(missing_steps) * 0.2) - (len(missing_primitives) * 0.1) - single_source_penalty

    def _confidence(
        self,
        pattern: dict[str, Any],
        matched_steps: list[PatternStep],
        missing_steps: list[PatternStep],
    ) -> float:
        base = {"high": 0.85, "medium": 0.65, "low": 0.4}.get(str(pattern.get("confidence", "")).casefold(), 0.5)
        coverage = len(matched_steps) / max(len(matched_steps) + len(missing_steps), 1)
        return round(base * coverage, 3)
