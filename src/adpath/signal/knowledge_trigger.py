"""Knowledge-base pattern-card trigger engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adpath.knowledge.loader import KnowledgeBaseLoader
from adpath.models.edge import Edge
from adpath.models.node import Node


@dataclass(slots=True)
class PatternCard:
    """Reusable interesting-object pattern extracted from historical knowledge."""

    id: str
    machine: str
    category: str
    primitive: str
    source_object_type: str
    trigger_keywords: list[str] = field(default_factory=list)
    object_indicators: list[str] = field(default_factory=list)
    hypothesis: dict[str, Any] = field(default_factory=dict)
    validation: dict[str, Any] = field(default_factory=dict)
    required_evidence: list[str] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
    confidence: dict[str, Any] = field(default_factory=dict)
    next_steps: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> PatternCard:
        """Build a pattern card from YAML data."""
        return cls(
            id=str(data.get("id") or ""),
            machine=str(data.get("machine") or ""),
            category=str(data.get("category") or ""),
            primitive=str(data.get("primitive") or ""),
            source_object_type=str(data.get("source_object_type") or ""),
            trigger_keywords=[str(item) for item in data.get("trigger_keywords", []) or []],
            object_indicators=[str(item) for item in data.get("object_indicators", []) or []],
            hypothesis=dict(data.get("hypothesis") or {}),
            validation=dict(data.get("validation") or {}),
            required_evidence=[str(item) for item in data.get("required_evidence", []) or []],
            missing_information=[str(item) for item in data.get("missing_information", []) or []],
            confidence=dict(data.get("confidence") or {}),
            next_steps=[str(item) for item in data.get("next_steps", []) or []],
        )

    def to_match(self, node: Node, score: float) -> dict[str, Any]:
        """Return a compact historical pattern match."""
        return {
            "id": self.id,
            "machine": self.machine,
            "category": self.category,
            "primitive": self.primitive,
            "confidence": self.confidence.get("initial") or "medium",
            "support_strength": "pattern",
            "score": round(score, 2),
            "matched_object": node.name,
        }


class KnowledgeTriggerEngine:
    """Match graph objects against entry-point pattern cards."""

    def __init__(self, root: Path | str = "knowledge-base") -> None:
        self.loader = KnowledgeBaseLoader(root)

    def pattern_cards(self) -> list[PatternCard]:
        """Load pattern-card YAML records."""
        records = self.loader.load_yaml_dir("pattern-cards")
        return [PatternCard.from_mapping(record) for record in records.values()]

    def matches_for_object(
        self,
        node: Node,
        *,
        relationships: list[Edge] | None = None,
    ) -> list[tuple[PatternCard, float]]:
        """Return pattern cards triggered by object type, name, properties, or relationships."""
        relationships = relationships or []
        matches: list[tuple[PatternCard, float]] = []
        for card in self.pattern_cards():
            score = self._score(card, node, relationships)
            if score > 0:
                matches.append((card, score))
        return sorted(matches, key=lambda item: (-item[1], item[0].id))

    def _score(self, card: PatternCard, node: Node, relationships: list[Edge]) -> float:
        score = 0.0
        if card.source_object_type and card.source_object_type.casefold() == str(node.type).casefold():
            score += 2.0
        haystack = self._object_text(node, relationships)
        for keyword in card.trigger_keywords:
            if keyword.casefold() in haystack:
                score += 1.0
        for indicator in card.object_indicators:
            if self._indicator_matches(indicator, node, relationships):
                score += 1.5
        return score

    def _object_text(self, node: Node, relationships: list[Edge]) -> str:
        values = [node.name, node.id, str(node.type), node.domain or ""]
        values.extend(str(value) for value in node.properties.values() if value is not None)
        values.extend(edge.relationship for edge in relationships)
        return " ".join(values).casefold()

    def _indicator_matches(self, indicator: str, node: Node, relationships: list[Edge]) -> bool:
        normalized = indicator.casefold()
        sam = str(node.properties.get("samaccountname") or node.name.split("@", 1)[0])
        host = sam.rstrip("$")
        if "samaccountname endswith" in normalized and sam.endswith("$"):
            return True
        if "hostname-like" in normalized and host.replace("-", "").isalnum():
            return True
        if "computer name" in normalized and str(node.type).casefold() == "computer":
            return True
        if "pre-windows" in normalized:
            return any("pre-windows 2000 compatible access" in edge.target.casefold() for edge in relationships)
        return indicator.casefold() in self._object_text(node, relationships)
