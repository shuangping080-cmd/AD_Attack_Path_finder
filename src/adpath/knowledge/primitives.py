"""Primitive catalog loaded from the knowledge base."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from adpath.knowledge.loader import KnowledgeBaseLoader
from adpath.models.edge import Edge
from adpath.models.node import Node
from adpath.models.primitive import AttackPrimitive


@dataclass(slots=True)
class PrimitiveCatalog:
    """Lookup table for relationship-to-primitive matching."""

    primitives: list[AttackPrimitive] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, root: Path | str = "knowledge-base") -> PrimitiveCatalog:
        """Load and validate primitive YAML files."""
        loader = KnowledgeBaseLoader(root)
        catalog = cls()
        for stem, raw in loader.primitives().items():
            if not isinstance(raw, dict):
                catalog.warnings.append(f"{stem}: primitive YAML is not an object")
                continue
            missing = [key for key in ("name", "required_relationships") if not raw.get(key)]
            if missing:
                catalog.warnings.append(f"{stem}: missing required primitive fields: {', '.join(missing)}")
                continue
            catalog.primitives.append(AttackPrimitive.from_yaml(raw))
        return catalog

    def by_relationship(self, relationship: str) -> list[AttackPrimitive]:
        """Return primitives that require a relationship."""
        return [
            primitive
            for primitive in self.primitives
            if relationship in primitive.required_relationships
        ]

    def candidates_for(
        self,
        edge: Edge,
        source: Node | None,
        target: Node | None,
    ) -> list[AttackPrimitive]:
        """Return primitive candidates matching relationship, types, and simple preconditions."""
        candidates = []
        for primitive in self.by_relationship(edge.relationship):
            source_types = primitive.source_types or [primitive.source_type]
            target_types = primitive.target_types or [primitive.target_type]
            if not any(self._type_matches(source_type, source) for source_type in source_types):
                continue
            if not any(self._type_matches(target_type, target) for target_type in target_types):
                continue
            candidates.append(primitive)
        return candidates

    def _type_matches(self, expected: str, node: Node | None) -> bool:
        if expected == "*" or node is None:
            return True
        node_type = str(node.type)
        if expected == "ServiceAccount" and node_type == "User":
            return bool(node.properties.get("hasspn") or node.properties.get("serviceprincipalnames"))
        return expected == node_type

    def names(self) -> list[str]:
        """Return primitive names sorted for display."""
        return sorted(primitive.name for primitive in self.primitives)
