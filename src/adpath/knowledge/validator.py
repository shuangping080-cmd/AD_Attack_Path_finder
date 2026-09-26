"""Validate AD attack path knowledge-base records."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from adpath.knowledge.loader import KnowledgeBaseLoader


@dataclass(slots=True)
class ValidationIssue:
    """One validation issue found in the knowledge base."""

    severity: str
    machine: str | None
    message: str


class KnowledgeBaseValidator:
    """Run structural checks over normalized machine records."""

    allowed_confidence: ClassVar[set[str]] = {"unknown", "low", "medium", "high"}

    def __init__(self, root: Path | str = "knowledge-base") -> None:
        self.root = Path(root)
        self.loader = KnowledgeBaseLoader(self.root)

    def validate(self) -> list[ValidationIssue]:
        """Validate all normalized machine records."""
        issues: list[ValidationIssue] = []
        relationship_names = self._dictionary_names(self.loader.relationships())
        primitive_names = self._dictionary_names(self.loader.primitives())
        machines = self.loader.machines()
        for machine_name, record in machines.items():
            issues.extend(self._validate_machine(machine_name, record, relationship_names, primitive_names))
        return issues

    def _validate_machine(
        self,
        machine_name: str,
        record: dict[str, Any],
        relationship_names: set[str],
        primitive_names: set[str],
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        entity_ids = [entity.get("id") for entity in record.get("entities", []) if entity.get("id")]
        entity_set = self._entity_references(record)
        if len(entity_ids) != len(entity_set):
            id_set = {entity_id for entity_id in entity_ids if entity_id}
            if len(entity_ids) != len(id_set):
                issues.append(ValidationIssue("error", machine_name, "Duplicate entity ids found."))

        for relationship in record.get("relationships", []):
            relation = relationship.get("relation")
            if relation and relation not in relationship_names:
                issues.append(ValidationIssue("error", machine_name, f"Unknown relationship: {relation}"))
            issues.extend(self._validate_reference(machine_name, entity_set, relationship.get("source"), "relationship source"))
            issues.extend(self._validate_reference(machine_name, entity_set, relationship.get("target"), "relationship target"))
            if not relationship.get("evidence"):
                issues.append(ValidationIssue("warning", machine_name, f"Relationship lacks evidence: {relation}"))

        chain_orders = []
        for step in record.get("attack_chain", []):
            chain_orders.append(step.get("order"))
            primitive = step.get("primitive")
            relation = step.get("relationship")
            if primitive and primitive not in primitive_names:
                issues.append(ValidationIssue("error", machine_name, f"Unknown chain primitive: {primitive}"))
            if relation and relation not in relationship_names:
                issues.append(ValidationIssue("error", machine_name, f"Unknown chain relationship: {relation}"))
            issues.extend(self._validate_reference(machine_name, entity_set, step.get("source"), "chain source"))
            issues.extend(self._validate_reference(machine_name, entity_set, step.get("target"), "chain target"))
            if not step.get("evidence"):
                issues.append(ValidationIssue("warning", machine_name, f"Chain step lacks evidence: {step.get('order')}"))

        expected_orders = list(range(1, len(chain_orders) + 1))
        if chain_orders and chain_orders != expected_orders:
            issues.append(ValidationIssue("error", machine_name, "Attack chain order is not consecutive."))

        for primitive in record.get("attack_primitives", []):
            name = primitive.get("name")
            if name and name not in primitive_names:
                issues.append(ValidationIssue("error", machine_name, f"Unknown primitive: {name}"))
            if primitive.get("observed") and primitive.get("candidate"):
                issues.append(ValidationIssue("error", machine_name, f"Primitive is both observed and candidate: {name}"))
            if not primitive.get("evidence"):
                issues.append(ValidationIssue("warning", machine_name, f"Primitive lacks evidence: {name}"))

        confidence = record.get("confidence")
        if confidence not in self.allowed_confidence:
            issues.append(ValidationIssue("warning", machine_name, f"Unexpected confidence value: {confidence}"))
        return issues

    def _validate_reference(
        self,
        machine: str,
        entity_refs: set[str],
        value: str | None,
        label: str,
    ) -> list[ValidationIssue]:
        if value and entity_refs and value.casefold() not in entity_refs:
            return [ValidationIssue("error", machine, f"Unknown {label} entity reference: {value}")]
        return []

    def _entity_references(self, record: dict[str, Any]) -> set[str]:
        refs: set[str] = set()
        for entity in record.get("entities", []) or []:
            if not isinstance(entity, dict):
                continue
            for value in [entity.get("id"), entity.get("name"), *(entity.get("aliases") or [])]:
                if value:
                    refs.add(str(value).casefold())
        return refs

    def _dictionary_names(self, records: dict[str, Any]) -> set[str]:
        return {record.get("name", key) for key, record in records.items()}
