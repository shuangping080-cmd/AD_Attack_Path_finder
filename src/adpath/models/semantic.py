"""Semantic edge model for inferred attack primitive relationships."""

from dataclasses import dataclass, field
from typing import Any

from adpath.models.edge import Edge


@dataclass(slots=True)
class SemanticEdge:
    """Inferred relationship derived from raw graph facts without mutating the raw graph."""

    source: str
    target: str
    primitive: str
    status: str = "candidate"
    confidence: float = 0.0
    raw_edges: list[dict[str, Any]] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_edge(self) -> Edge:
        """Return a normalized edge representation marked as semantic."""
        return Edge(
            source=self.source,
            target=self.target,
            relationship=self.primitive,
            properties={
                "status": self.status,
                "raw_edges": self.raw_edges,
                "derived_from": self.derived_from,
                "evidence": self.evidence,
            },
            confidence=self.confidence,
            source_tool="semantic",
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable semantic edge evidence."""
        return {
            "source": self.source,
            "target": self.target,
            "primitive": self.primitive,
            "status": self.status,
            "confidence": self.confidence,
            "raw_edges": self.raw_edges,
            "derived_from": self.derived_from,
            "evidence": self.evidence,
        }
