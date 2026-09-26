"""Normalization helpers for parser output."""

from dataclasses import dataclass, field

from adpath.models.edge import Edge
from adpath.models.node import Node


@dataclass(slots=True)
class NormalizationResult:
    """Container for normalized nodes and edges."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def extend(self, other: "NormalizationResult") -> None:
        """Append another normalization result."""
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)
        self.warnings.extend(other.warnings)


def normalize_bloodhound_record(record: dict) -> NormalizationResult:
    """Normalize a single BloodHound-style record.

    TODO: Implement record-type-specific normalization.
    """
    return NormalizationResult(warnings=[f"Unsupported record type: {record.get('type', 'unknown')}"])
