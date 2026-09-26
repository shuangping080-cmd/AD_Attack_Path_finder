"""Local analyst evidence store for hypothesis validation results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CONTROLLED_EVIDENCE_TYPES = {"credential_valid", "shell_obtained", "hash_obtained", "cert_obtained"}


@dataclass(slots=True)
class EvidenceRecord:
    """One analyst-supplied validation result."""

    principal: str
    type: str
    method: str
    note: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable evidence data."""
        return {
            "principal": self.principal,
            "type": self.type,
            "method": self.method,
            "note": self.note,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        """Build an evidence record from JSON data."""
        return cls(
            principal=str(data["principal"]),
            type=str(data["type"]),
            method=str(data.get("method") or ""),
            note=str(data.get("note") or ""),
            timestamp=str(data.get("timestamp") or datetime.now(UTC).isoformat()),
        )


class EvidenceStore:
    """Read and write evidence.json beside a normalized graph."""

    def __init__(self, graph_path: Path | str) -> None:
        base = Path(graph_path)
        self.path = base if base.suffix.casefold() == ".json" else base / "evidence.json"

    def load(self) -> dict[str, Any]:
        """Load evidence store data."""
        if not self.path.exists():
            return {"evidence": [], "controlled_principals": []}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data.setdefault("evidence", [])
        data.setdefault("controlled_principals", [])
        return data

    def records(self) -> list[EvidenceRecord]:
        """Return all evidence records."""
        return [EvidenceRecord.from_dict(item) for item in self.load().get("evidence", [])]

    def controlled_principals(self) -> list[str]:
        """Return principals validated as controlled."""
        return sorted({str(item) for item in self.load().get("controlled_principals", [])})

    def add(self, record: EvidenceRecord) -> dict[str, Any]:
        """Add a record and update controlled principals when appropriate."""
        data = self.load()
        records = [EvidenceRecord.from_dict(item) for item in data.get("evidence", [])]
        records.append(record)
        data["evidence"] = [item.to_dict() for item in records]
        controlled = {str(item) for item in data.get("controlled_principals", [])}
        if record.type in CONTROLLED_EVIDENCE_TYPES:
            controlled.add(record.principal)
        if record.type == "credential_invalid" and record.principal in controlled:
            controlled.remove(record.principal)
        data["controlled_principals"] = sorted(controlled)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data
