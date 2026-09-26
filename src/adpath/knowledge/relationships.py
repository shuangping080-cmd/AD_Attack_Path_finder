"""Relationship catalog loaded from the knowledge base."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adpath.knowledge.loader import KnowledgeBaseLoader


@dataclass(slots=True)
class RelationshipDefinition:
    """Knowledge-base definition for one graph relationship."""

    name: str
    description: str = ""
    source_types: list[str] = field(default_factory=list)
    target_types: list[str] = field(default_factory=list)
    direct_control: bool = False
    maps_to_primitives: list[str] = field(default_factory=list)
    extra_conditions: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, data: dict[str, Any]) -> RelationshipDefinition:
        """Build a relationship definition from YAML."""
        return cls(
            name=str(data["name"]),
            description=str(data.get("description") or ""),
            source_types=[str(item) for item in data.get("source_types", [])],
            target_types=[str(item) for item in data.get("target_types", [])],
            direct_control=bool(data.get("direct_control", False)),
            maps_to_primitives=[str(item) for item in data.get("maps_to_primitives", [])],
            extra_conditions=[str(item) for item in data.get("extra_conditions", [])],
        )


@dataclass(slots=True)
class RelationshipCatalog:
    """Lookup table for relationship metadata and primitive mappings."""

    relationships: dict[str, RelationshipDefinition] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, root: Path | str = "knowledge-base") -> RelationshipCatalog:
        """Load relationship YAML files."""
        loader = KnowledgeBaseLoader(root)
        catalog = cls()
        for stem, raw in loader.relationships().items():
            if not isinstance(raw, dict):
                catalog.warnings.append(f"{stem}: relationship YAML is not an object")
                continue
            if not raw.get("name"):
                catalog.warnings.append(f"{stem}: missing relationship name")
                continue
            relationship = RelationshipDefinition.from_yaml(raw)
            catalog.relationships[relationship.name] = relationship
        return catalog

    def get(self, relationship: str) -> RelationshipDefinition | None:
        """Return one relationship definition."""
        return self.relationships.get(relationship)

    def primitives_for(self, relationship: str) -> list[str]:
        """Return primitive names mapped from a relationship."""
        definition = self.get(relationship)
        return list(definition.maps_to_primitives) if definition else []

    def valid_source_types(self, relationship: str) -> list[str]:
        """Return source types allowed by the relationship definition."""
        definition = self.get(relationship)
        return list(definition.source_types) if definition else []

    def valid_target_types(self, relationship: str) -> list[str]:
        """Return target types allowed by the relationship definition."""
        definition = self.get(relationship)
        return list(definition.target_types) if definition else []
