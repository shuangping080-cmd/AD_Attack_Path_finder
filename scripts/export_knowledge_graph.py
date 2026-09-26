"""Export knowledge-base dictionaries and observations as graph JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from adpath.knowledge.loader import KnowledgeBaseLoader


def main() -> int:
    """Write knowledge graph node and edge JSON files."""
    kb_root = PROJECT_ROOT / "knowledge-base"
    output_dir = PROJECT_ROOT / "data" / "graphs"
    output_dir.mkdir(parents=True, exist_ok=True)

    loader = KnowledgeBaseLoader(kb_root)
    nodes: list[dict] = []
    edges: list[dict] = []

    for machine, record in loader.machines().items():
        nodes.append({"id": f"machine:{machine}", "type": "Machine", "name": machine})
        for primitive in record.get("attack_primitives", []):
            primitive_name = primitive.get("name")
            if primitive_name:
                edges.append({
                    "source": f"primitive:{primitive_name}",
                    "target": f"machine:{machine}",
                    "type": "OBSERVED_IN",
                })

    for key, primitive in loader.primitives().items():
        primitive_name = primitive.get("name", key)
        nodes.append({"id": f"primitive:{primitive_name}", "type": "Primitive", "name": primitive_name})
        for relation in primitive.get("required_relationships", []):
            edges.append({
                "source": f"relationship:{relation}",
                "target": f"primitive:{primitive_name}",
                "type": "REQUIRES",
            })
        for related in primitive.get("related_primitives", []):
            edges.append({
                "source": f"primitive:{primitive_name}",
                "target": f"primitive:{related}",
                "type": "RELATED_TO",
            })

    for key, relationship in loader.relationships().items():
        relationship_name = relationship.get("name", key)
        nodes.append({"id": f"relationship:{relationship_name}", "type": "Relationship", "name": relationship_name})
        for primitive in relationship.get("maps_to_primitives", []):
            edges.append({
                "source": f"relationship:{relationship_name}",
                "target": f"primitive:{primitive}",
                "type": "LEADS_TO",
            })

    for key, pattern in loader.attack_patterns().items():
        pattern_name = pattern.get("name", key)
        nodes.append({"id": f"pattern:{pattern_name}", "type": "AttackPattern", "name": pattern_name})
        for primitive in pattern.get("required_primitives", []):
            edges.append({
                "source": f"pattern:{pattern_name}",
                "target": f"primitive:{primitive}",
                "type": "REQUIRES",
            })

    (output_dir / "knowledge-nodes.json").write_text(
        json.dumps(nodes, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (output_dir / "knowledge-edges.json").write_text(
        json.dumps(edges, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Exported {len(nodes)} nodes and {len(edges)} edges.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
