"""Structured missing-information model."""

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any


class MissingImportance(IntEnum):
    """Importance used to prioritize analyst follow-up."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


class MissingSource(StrEnum):
    """Suggested source for missing information."""

    BLOODHOUND = "BloodHound"
    LDAP = "LDAP"
    SMB = "SMB"
    HOST = "Host"


@dataclass(frozen=True, slots=True)
class MissingInformation:
    """One structured question the analyzer cannot answer from current graph data."""

    question: str
    object: str
    reason: str
    suggested_source: MissingSource | str
    importance: MissingImportance = MissingImportance.MEDIUM
    blocks_path: bool = True
    missing_relationship: str | None = None
    expected_source_type: str | None = None
    expected_target_type: str | None = None
    possible_collector: str | None = None

    @property
    def key(self) -> tuple[str, str, str, str | None]:
        """Return a de-duplication key."""
        return (
            self.question.casefold(),
            self.object.casefold(),
            str(self.suggested_source).casefold(),
            self.missing_relationship,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable missing information."""
        return {
            "question": self.question,
            "object": self.object,
            "reason": self.reason,
            "suggested_source": str(self.suggested_source),
            "importance": self.importance.name.lower(),
            "blocks_path": self.blocks_path,
            "missing_relationship": self.missing_relationship,
            "expected_source_type": self.expected_source_type,
            "expected_target_type": self.expected_target_type,
            "possible_collector": self.possible_collector or str(self.suggested_source),
        }


def dedupe_missing(items: list[MissingInformation]) -> list[MissingInformation]:
    """Deduplicate missing-information records, keeping the highest importance."""
    by_key: dict[tuple[str, str, str, str | None], MissingInformation] = {}
    for item in items:
        existing = by_key.get(item.key)
        if existing is None or item.importance > existing.importance:
            by_key[item.key] = item
    return sorted(by_key.values(), key=lambda item: (-int(item.importance), item.object, item.question))
