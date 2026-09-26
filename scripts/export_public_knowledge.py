"""Export public-safe historical AD chain knowledge from the local SQLite KB.

The local KB may contain raw writeup copies, local paths, excerpts, and analyst
notes. This exporter intentionally writes only sanitized structural knowledge
that is safe to commit:

- machine names
- ordered chain steps
- source/target object names and types
- relationships, primitives, status, preconditions, missing information
- source URLs/titles for attribution

It never exports raw writeup text, local markdown paths, SQLite files, or raw
BloodHound data.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

import yaml

DEFAULT_OUT = Path("knowledge-base") / "htb" / "structured"
DEFAULT_INDEX = Path("knowledge-base") / "htb" / "public-index.json"


def slugify(value: str) -> str:
    out = []
    previous_dash = False
    for char in value.strip().lower():
        if char.isalnum():
            out.append(char)
            previous_dash = False
        elif not previous_dash:
            out.append("-")
            previous_dash = True
    return "".join(out).strip("-") or "record"


def load_json(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def entity_map(db: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    rows = db.execute(
        """
        SELECT entity_id, machine_id, name, entity_type, domain, properties_json
        FROM entities
        """
    ).fetchall()
    return {
        entity_id: {
            "id": entity_id,
            "machine_id": machine_id,
            "name": name,
            "type": entity_type,
            "domain": domain,
            "properties": load_json(properties_json, {}),
        }
        for entity_id, machine_id, name, entity_type, domain, properties_json in rows
    }


def clean_entity(entity_id: str | None, entities: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not entity_id:
        return None
    entity = entities.get(entity_id)
    if not entity:
        return {"id": entity_id}
    data = {
        "name": entity["name"],
        "type": entity["type"],
    }
    if entity.get("domain"):
        data["domain"] = entity["domain"]
    properties = entity.get("properties") or {}
    if properties:
        data["properties"] = properties
    return data


def source_map(db: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    rows = db.execute(
        """
        SELECT e.evidence_id, s.url, s.author, s.role, s.trust_level
        FROM evidence_items e
        JOIN sources s ON s.source_id = e.source_id
        """
    ).fetchall()
    return {
        evidence_id: {
            "url": url,
            "author": author,
            "role": role,
            "trust_level": trust_level,
        }
        for evidence_id, url, author, role, trust_level in rows
    }


def machine_sources(db: sqlite3.Connection, machine: str) -> list[dict[str, Any]]:
    rows = db.execute(
        """
        SELECT DISTINCT url, author, role, trust_level
        FROM sources
        WHERE machine = ? AND status = 'downloaded'
        ORDER BY CASE role WHEN 'primary' THEN 0 ELSE 1 END, title, url
        """,
        (machine,),
    ).fetchall()
    return [
        {
            "url": url,
            "author": author,
            "role": role,
            "trust_level": trust_level,
        }
        for url, author, role, trust_level in rows
    ]


def export_machine(
    db: sqlite3.Connection,
    machine_id: str,
    machine_name: str,
    source_status: str,
    entities: dict[str, dict[str, Any]],
    sources_by_evidence: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    step_rows = db.execute(
        """
        SELECT step_order, phase, source_entity_id, relationship, target_entity_id,
               primitive, result, evidence_id, visible_in_bloodhound,
               external_action_required, confidence, preconditions_json,
               missing_information_json
        FROM chain_steps
        WHERE machine_id = ?
        ORDER BY step_order
        """,
        (machine_id,),
    ).fetchall()

    steps: list[dict[str, Any]] = []
    entity_ids: set[str] = set()
    relationships: set[str] = set()
    primitives: set[str] = set()

    for row in step_rows:
        (
            step_order,
            phase,
            source_entity_id,
            relationship,
            target_entity_id,
            primitive,
            result,
            evidence_id,
            visible_in_bloodhound,
            external_action_required,
            confidence,
            preconditions_json,
            missing_json,
        ) = row
        if source_entity_id:
            entity_ids.add(source_entity_id)
        if target_entity_id:
            entity_ids.add(target_entity_id)
        if relationship:
            relationships.add(relationship)
        if primitive:
            primitives.add(primitive)

        evidence = sources_by_evidence.get(evidence_id or "", {})
        step = {
            "order": step_order,
            "phase": phase,
            "source": clean_entity(source_entity_id, entities),
            "relationship": relationship,
            "target": clean_entity(target_entity_id, entities),
            "primitive": primitive,
            "result": result,
            "status": confidence,
            "bloodhound_visible": None if visible_in_bloodhound is None else bool(visible_in_bloodhound),
            "external_action_required": bool(external_action_required),
            "preconditions": load_json(preconditions_json, []),
            "missing_information": load_json(missing_json, []),
            "evidence": {
                "boundary": "historical_writeup_reference",
                "source_url": evidence.get("url"),
                "source_role": evidence.get("role"),
            },
        }
        steps.append(step)

    return {
        "machine": {
            "name": machine_name,
            "source_status": source_status,
            "environment": "ActiveDirectory",
        },
        "public_safety": {
            "contains_raw_writeup_text": False,
            "contains_bloodhound_raw_data": False,
            "contains_private_sqlite_data": False,
            "evidence_boundary": "historical examples only; never current confirmed evidence",
        },
        "sources": machine_sources(db, machine_name),
        "entities": [
            clean_entity(entity_id, entities)
            for entity_id in sorted(entity_ids)
            if clean_entity(entity_id, entities)
        ],
        "relationships": sorted(relationships),
        "primitives": sorted(primitives),
        "attack_chain": steps,
        "review_status": "sanitized_historical_draft",
    }


def export(db_path: Path, out_dir: Path, index_path: Path) -> None:
    if not db_path.exists():
        raise SystemExit(f"Local SQLite KB not found: {db_path}")

    out_dir.mkdir(parents=True, exist_ok=True)
    index_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as db:
        entities = entity_map(db)
        sources_by_evidence = source_map(db)
        machines = db.execute(
            """
            SELECT DISTINCT m.machine_id, m.name, m.source_status
            FROM machines m
            JOIN chain_steps c ON c.machine_id = m.machine_id
            ORDER BY lower(m.name)
            """
        ).fetchall()

        index_records: list[dict[str, Any]] = []
        for machine_id, machine_name, source_status in machines:
            record = export_machine(
                db,
                machine_id,
                machine_name,
                source_status or "unknown",
                entities,
                sources_by_evidence,
            )
            output_path = out_dir / f"{slugify(machine_name)}.yaml"
            output_path.write_text(
                yaml.safe_dump(record, sort_keys=False, allow_unicode=True, width=120),
                encoding="utf-8",
            )
            index_records.append(
                {
                    "machine": machine_name,
                    "path": str(output_path.as_posix()),
                    "steps": len(record["attack_chain"]),
                    "relationships": record["relationships"],
                    "primitives": record["primitives"],
                    "review_status": record["review_status"],
                }
            )

    index = {
        "schema": "adpath.public_historical_chains.v1",
        "public_safety": {
            "raw_writeups_included": False,
            "raw_bloodhound_included": False,
            "sqlite_included": False,
        },
        "machine_count": len(index_records),
        "machines": index_records,
    }
    index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Exported {len(index_records)} public historical chain records to {out_dir}")
    print(f"Wrote index: {index_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export sanitized public HTB knowledge records.")
    parser.add_argument("--db", type=Path, required=True, help="Path to the private local SQLite knowledge base")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    export(args.db, args.out, args.index)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
