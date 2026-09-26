"""Attack path model."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from adpath.models.edge import Edge
from adpath.models.evidence import HistoricalSupport, PathEvidence
from adpath.models.missing import MissingInformation
from adpath.models.node import Node
from adpath.models.primitive import AttackPrimitive


class PathType(StrEnum):
    """Supported analysis path types."""

    CONFIRMED = "Confirmed Path"
    CANDIDATE = "Candidate Path"
    INCOMPLETE = "Incomplete Path"


@dataclass(slots=True)
class AttackPath:
    """A derived path with supporting graph elements and missing information notes."""

    start: str
    target: str
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    confirmed_edges: list[Edge] = field(default_factory=list)
    candidate_edges: list[Edge] = field(default_factory=list)
    primitives: list[AttackPrimitive] = field(default_factory=list)
    historical_support: list[HistoricalSupport] = field(default_factory=list)
    path_type: PathType | str = PathType.CANDIDATE
    score: float = 0.0
    confidence: float | None = None
    missing_information: list[MissingInformation] = field(default_factory=list)
    evidence: PathEvidence | dict[str, Any] = field(default_factory=PathEvidence)
    reason: str = ""

    def __post_init__(self) -> None:
        """Normalize Phase 4 path fields while preserving legacy construction."""
        if self.path_type not in {PathType.CONFIRMED, PathType.CANDIDATE, PathType.INCOMPLETE}:
            self.path_type = PathType.CANDIDATE
        if self.confidence is None:
            edge_confidences = [edge.confidence for edge in self.edges]
            self.confidence = min(edge_confidences, default=0.5)
        if isinstance(self.evidence, dict):
            self.evidence = PathEvidence.from_mapping(self.evidence)
        if not self.confirmed_edges:
            self.confirmed_edges = [
                edge
                for edge in self.edges
                if edge.source_tool not in {"knowledge", "semantic", "pattern"}
            ]
        if not self.candidate_edges:
            self.candidate_edges = [edge for edge in self.edges if edge.source_tool == "knowledge"]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable path data."""
        return {
            "start": self.start,
            "target": self.target,
            "path_type": str(self.path_type),
            "score": self.score,
            "confidence": self.confidence,
            "reason": self.reason,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "confirmed_edges": [edge.to_dict() for edge in self.confirmed_edges],
            "candidate_edges": [edge.to_dict() for edge in self.candidate_edges],
            "primitives": [primitive.to_dict() for primitive in self.primitives],
            "historical_support": [support.to_dict() for support in self.historical_support],
            "missing_information": [item.to_dict() for item in self.missing_information],
            "evidence": self.evidence.to_dict() if isinstance(self.evidence, PathEvidence) else self.evidence,
        }
