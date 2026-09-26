"""Shared detector interfaces."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingInformation
from adpath.models.node import Node
from adpath.models.primitive import AttackPrimitive


@dataclass(slots=True)
class Finding:
    """Analysis finding that may produce an attack primitive candidate."""

    name: str
    description: str
    source: str | None = None
    target: str | None = None
    relationship: str | None = None
    primitive: AttackPrimitive | None = None
    result: str | None = None
    status: str = "candidate"
    confidence: float = 0.0
    missing_information: list[MissingInformation] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable finding."""
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "primitive": self.primitive.to_dict() if self.primitive else None,
            "result": self.result,
            "status": self.status,
            "confidence": self.confidence,
            "missing_information": [item.to_dict() for item in self.missing_information],
            "evidence": self.evidence,
        }


class BaseDetector(ABC):
    """Abstract detector that maps graph facts to findings or primitive candidates."""

    name: str

    @abstractmethod
    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Analyze graph elements and return findings without executing attack actions."""

    def detect_graph(self, graph: ADGraph) -> list[Finding]:
        """Analyze a graph."""
        return self.detect(graph.nodes, graph.edges)
