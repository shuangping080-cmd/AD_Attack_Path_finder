"""Attack primitive model."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AttackPrimitive:
    """Analysis-only mapping from AD relationships to possible attack primitives."""

    name: str
    source_type: str = "*"
    target_type: str = "*"
    source_types: list[str] = field(default_factory=list)
    target_types: list[str] = field(default_factory=list)
    category: str = "General"
    required_relationships: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    result: str | None = None
    confidence: float = 1.0
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    follow_up_information: list[str] = field(default_factory=list)
    observed_examples: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable primitive."""
        return {
            "name": self.name,
            "category": self.category,
            "source_type": self.source_type,
            "target_type": self.target_type,
            "source_types": self.source_types or [self.source_type],
            "target_types": self.target_types or [self.target_type],
            "required_relationships": self.required_relationships,
            "preconditions": self.preconditions,
            "result": self.result,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "follow_up_information": self.follow_up_information,
            "observed_examples": self.observed_examples,
        }

    @classmethod
    def from_yaml(cls, data: dict[str, Any]) -> "AttackPrimitive":
        """Build a primitive from a knowledge-base YAML entry."""
        source_types = data.get("source_types") or [data.get("source_type") or "*"]
        target_types = data.get("target_types") or [data.get("target_type") or "*"]
        results = data.get("results") or [data.get("result")]
        return cls(
            name=str(data["name"]),
            category=str(data.get("category") or "General"),
            source_type=str(source_types[0]),
            target_type=str(target_types[0]),
            source_types=[str(item) for item in source_types],
            target_types=[str(item) for item in target_types],
            required_relationships=[str(item) for item in data.get("required_relationships", [])],
            preconditions=[str(item) for item in data.get("preconditions", [])],
            result=str(results[0]) if results and results[0] is not None else None,
            confidence=float(data.get("confidence", 1.0)),
            description=str(data.get("description") or ""),
            evidence=dict(data.get("evidence") or {}),
            follow_up_information=[str(item) for item in data.get("follow_up_information", [])],
            observed_examples=[
                dict(item)
                for item in data.get("observed_examples", [])
                if isinstance(item, dict)
            ],
        )
