"""Edge model for normalized Active Directory relationships."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Edge:
    """Directed relationship between two normalized AD graph nodes."""

    source: str
    target: str
    relationship: str
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source_tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "properties": self.properties,
            "confidence": self.confidence,
            "source_tool": self.source_tool,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Edge":
        """Build an edge from normalized JSON data."""
        return cls(
            source=str(data["source"]),
            target=str(data["target"]),
            relationship=str(data["relationship"]),
            properties=dict(data.get("properties") or {}),
            confidence=float(data.get("confidence", 1.0)),
            source_tool=data.get("source_tool"),
        )
