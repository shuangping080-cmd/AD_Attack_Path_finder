"""Generate global indexes from normalized and reviewed records."""

from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from adpath.knowledge.loader import KnowledgeBaseLoader


class KnowledgeBaseIndexer:
    """Build machine, primitive, relationship, attack-pattern, and tag indexes."""

    def __init__(self, root: Path | str = "knowledge-base") -> None:
        self.root = Path(root)
        self.loader = KnowledgeBaseLoader(self.root)

    def build_indexes(self) -> dict[str, dict[str, Any]]:
        """Return all generated indexes."""
        machines = self.loader.machines()
        return {
            "machines-index": self._machine_index(machines),
            "primitive-index": self._field_index(machines, "attack_primitives", "name"),
            "relationship-index": self._field_index(machines, "relationships", "relation"),
            "tag-index": self._tag_index(machines),
            "attack-pattern-index": self._pattern_index(),
        }

    def write_indexes(self) -> None:
        """Write generated indexes to htb/index."""
        index_dir = self.root / "htb" / "index"
        index_dir.mkdir(parents=True, exist_ok=True)
        for name, data in self.build_indexes().items():
            with (index_dir / f"{name}.yaml").open("w", encoding="utf-8") as handle:
                yaml.safe_dump(data, handle, sort_keys=True, allow_unicode=True)

    def _machine_index(self, machines: dict[str, Any]) -> dict[str, Any]:
        return {
            name: {
                "review_status": record.get("review_status", "unknown"),
                "entity_count": len(record.get("entities", [])),
                "relationship_count": len(record.get("relationships", [])),
                "primitive_count": len(record.get("attack_primitives", [])),
            }
            for name, record in sorted(machines.items())
        }

    def _field_index(self, machines: dict[str, Any], list_key: str, field_key: str) -> dict[str, Any]:
        index: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"machines": []})
        for machine, record in machines.items():
            for item in record.get(list_key, []):
                value = item.get(field_key)
                if value and machine not in index[value]["machines"]:
                    index[value]["machines"].append(machine)
        return dict(sorted(index.items()))

    def _tag_index(self, machines: dict[str, Any]) -> dict[str, Any]:
        index: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"machines": []})
        for machine, record in machines.items():
            for tag in record.get("tags", []):
                if machine not in index[tag]["machines"]:
                    index[tag]["machines"].append(machine)
        return dict(sorted(index.items()))

    def _pattern_index(self) -> dict[str, Any]:
        patterns = self.loader.attack_patterns()
        return {
            pattern.get("name", key): {
                "examples": pattern.get("examples", []),
                "source_count": pattern.get("source_count", 0),
                "confidence": pattern.get("confidence", "unknown"),
            }
            for key, pattern in sorted(patterns.items())
        }
