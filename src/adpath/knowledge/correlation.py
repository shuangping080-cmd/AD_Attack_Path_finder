"""Correlate live graph identities with historical HTB knowledge records."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adpath.knowledge.loader import KnowledgeBaseLoader


@dataclass(slots=True)
class KnowledgeHint:
    """A historical knowledge-base hint related to a graph principal."""

    machine: str
    source: str
    target: str | None
    relationship: str | None
    primitive: str | None
    result: str | None
    confidence: str = "unknown"
    graph_confirmed: bool = False
    review_status: str = "normalized"
    support_strength: str = "weak"
    evidence: dict[str, Any] = field(default_factory=dict)


class KnowledgeCorrelator:
    """Match current graph identities to normalized HTB knowledge chains."""

    def __init__(self, root: Path | str = "knowledge-base", include_normalized: bool = True) -> None:
        self.loader = KnowledgeBaseLoader(root)
        self.include_normalized = include_normalized

    def hints_for_identity(self, identity: str) -> list[KnowledgeHint]:
        """Return historical chain hints where source exactly matches an identity.

        This is a helper for analyst lookup. Candidate-path scoring should prefer
        structural pattern matches because short account names can collide across
        domains and HTB machines.
        """
        identity_keys = self._identity_keys(identity)
        hints = [
            hint
            for hint in self.all_hints()
            if self._hint_matches_identity(identity, identity_keys, hint)
        ]
        return self._dedupe(hints)

    def historical_examples_for_pattern(
        self,
        pattern: str,
        relationships: list[str] | None = None,
        primitives: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return HTB examples whose relationships or primitives resemble a pattern."""
        relationship_set = {item.casefold() for item in relationships or [] if item}
        primitive_set = {item.casefold() for item in primitives or [] if item}
        examples: list[dict[str, Any]] = []
        for key, record in self.loader.load_candidate_machines(self.include_normalized).items():
            machine = str((record.get("machine") or {}).get("name") or key)
            review_status = self.loader.review_status(record)
            support_strength = "strong" if review_status == "reviewed" else "weak"
            matched_steps = []
            for step in record.get("attack_chain", []) or []:
                if not isinstance(step, dict):
                    continue
                relation = str(step.get("relationship") or "")
                primitive = str(step.get("primitive") or "")
                if (
                    relation.casefold() in relationship_set
                    or primitive.casefold() in primitive_set
                    or pattern.casefold() in {relation.casefold(), primitive.casefold()}
                ):
                    matched_steps.append(step)
            if not matched_steps:
                continue
            examples.append(
                {
                    "machine": machine,
                    "pattern": pattern,
                    "review_status": review_status,
                    "support_strength": support_strength,
                    "confidence": str(record.get("confidence") or "unknown"),
                    "steps": [
                        {
                            "source": item.get("source"),
                            "relationship": item.get("relationship"),
                            "target": item.get("target"),
                            "primitive": item.get("primitive"),
                            "result": item.get("result"),
                        }
                        for item in matched_steps[:5]
                    ],
                }
            )
        return examples

    def all_hints(self) -> list[KnowledgeHint]:
        """Return normalized relationship, primitive, and chain hints from reviewed KB."""
        hints: list[KnowledgeHint] = []
        for key, record in self.loader.load_candidate_machines(self.include_normalized).items():
            machine = str((record.get("machine") or {}).get("name") or key)
            record_confidence = str(record.get("confidence") or "unknown")
            review_status = self.loader.review_status(record)
            support_strength = "strong" if review_status == "reviewed" else "weak"
            for relationship in record.get("relationships", []) or []:
                if not isinstance(relationship, dict):
                    continue
                source = self._resolve_entity_ref(record, relationship.get("source"))
                relation = relationship.get("relation") or relationship.get("relationship")
                if not source or not relation:
                    continue
                hints.append(
                    KnowledgeHint(
                        machine=machine,
                        source=source,
                        target=self._resolve_entity_ref(record, relationship.get("target")),
                        relationship=str(relation),
                        primitive=None,
                        result=relationship.get("result") or "HistoricalRelationshipCandidate",
                        confidence=str(relationship.get("confidence") or record_confidence),
                        graph_confirmed=False,
                        review_status=review_status,
                        support_strength=support_strength,
                        evidence=dict(relationship.get("evidence") or {}),
                    )
                )
            for step in record.get("attack_chain", []) or []:
                if not isinstance(step, dict):
                    continue
                source = self._resolve_entity_ref(record, step.get("source"))
                if not source or source.casefold() == "unknown":
                    continue
                hints.append(
                    KnowledgeHint(
                        machine=machine,
                        source=source,
                        target=self._resolve_entity_ref(record, step.get("target")),
                        relationship=step.get("relationship"),
                        primitive=step.get("primitive"),
                        result=step.get("result"),
                        confidence=str(step.get("confidence") or record_confidence),
                        graph_confirmed=False,
                        review_status=review_status,
                        support_strength=support_strength,
                        evidence=dict(step.get("evidence") or {}),
                    )
                )
            for primitive in record.get("attack_primitives", []) or []:
                if not isinstance(primitive, dict):
                    continue
                source = self._resolve_entity_ref(record, primitive.get("source"))
                if not source or source.casefold() == "unknown":
                    continue
                hints.append(
                    KnowledgeHint(
                        machine=machine,
                        source=source,
                        target=self._resolve_entity_ref(record, primitive.get("target")),
                        relationship=None,
                        primitive=primitive.get("name"),
                        result=primitive.get("result"),
                        confidence=str(primitive.get("confidence") or record_confidence),
                        graph_confirmed=False,
                        review_status=review_status,
                        support_strength=support_strength,
                        evidence=dict(primitive.get("evidence") or {}),
                    )
                )
        return self._dedupe(hints)

    def _resolve_entity_ref(self, record: dict[str, Any], value: Any) -> str | None:
        if value is None:
            return None
        raw_value = str(value)
        if not raw_value:
            return ""
        lookup = self._entity_lookup(record)
        return lookup.get(raw_value.casefold(), raw_value)

    def _entity_lookup(self, record: dict[str, Any]) -> dict[str, str]:
        lookup: dict[str, str] = {}
        for entity in record.get("entities", []) or []:
            if not isinstance(entity, dict):
                continue
            display = str(entity.get("name") or entity.get("id") or "")
            if not display:
                continue
            for key in [entity.get("id"), entity.get("name"), *(entity.get("aliases") or [])]:
                if key:
                    lookup[str(key).casefold()] = display
        return lookup

    def _identity_keys(self, value: str) -> set[str]:
        normalized = value.strip().casefold()
        if not normalized:
            return set()
        keys = {normalized}
        if "@" in normalized or "\\" in normalized:
            keys.add(normalized.split("\\", 1)[-1])
        return {item for item in keys if item and item != "unknown"}

    def _hint_matches_identity(self, identity: str, identity_keys: set[str], hint: KnowledgeHint) -> bool:
        hint_keys = self._identity_keys(hint.source)
        if hint_keys & identity_keys:
            return True
        normalized = identity.casefold()
        if "@" not in normalized and "\\" not in normalized:
            return False
        domain = normalized.split("@", 1)[-1] if "@" in normalized else normalized.split("\\", 1)[0]
        machine_key = hint.machine.casefold()
        source_short = hint.source.casefold().split("@", 1)[0].split("\\", 1)[-1]
        identity_short = normalized.split("@", 1)[0].split("\\", 1)[-1]
        return source_short == identity_short and machine_key in domain

    def _dedupe(self, hints: list[KnowledgeHint]) -> list[KnowledgeHint]:
        seen = set()
        deduped = []
        for hint in hints:
            key = (hint.machine, hint.source, hint.target, hint.relationship, hint.primitive, hint.result)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(hint)
        return deduped
