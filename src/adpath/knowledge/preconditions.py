"""Primitive precondition evaluator."""

from __future__ import annotations

from dataclasses import dataclass, field

from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingInformation, MissingSource
from adpath.models.node import Node
from adpath.models.primitive import AttackPrimitive


@dataclass(slots=True)
class PreconditionResult:
    """Result of evaluating primitive preconditions."""

    satisfied: bool
    status: str
    confidence_adjustment: float = 0.0
    missing_information: list[MissingInformation] = field(default_factory=list)


class PreconditionEvaluator:
    """Evaluate a conservative subset of preconditions used by primitive YAML."""

    def evaluate(
        self,
        primitive: AttackPrimitive,
        edge: Edge,
        source: Node | None,
        target: Node | None,
        graph: ADGraph | None = None,
    ) -> PreconditionResult:
        """Evaluate known precondition phrases without assuming exploit success."""
        missing: list[MissingInformation] = []
        status = "confirmed"
        confidence_adjustment = 0.0
        for precondition in primitive.preconditions:
            normalized = precondition.casefold()
            if "write spn" in normalized or "spn" in normalized and "writable" in normalized:
                if edge.relationship == "WriteSPN":
                    confidence_adjustment += 0.1
                    continue
                status = "incomplete"
                confidence_adjustment -= 0.2
                missing.append(
                    self._missing(
                        "Is servicePrincipalName writable?",
                        target.name if target else edge.target,
                        "GenericWrite does not prove the SPN attribute is writable.",
                        MissingSource.LDAP,
                        MissingImportance.HIGH,
                    )
                )
            elif "target has spn" in normalized:
                if target and (target.properties.get("hasspn") or target.properties.get("serviceprincipalnames")):
                    continue
                status = "candidate"
                missing.append(
                    self._missing(
                        "Does the target currently have an SPN?",
                        target.name if target else edge.target,
                        "Kerberoastability depends on SPN state.",
                        MissingSource.LDAP,
                    )
                )
            elif "neighbor" in normalized and graph is not None:
                if graph.out_edges(edge.target) or graph.in_edges(edge.target):
                    continue
                status = "candidate"
                missing.append(
                    self._missing(
                        "What neighboring graph relationships exist?",
                        target.name if target else edge.target,
                        "This primitive depends on adjacent graph evidence.",
                        MissingSource.BLOODHOUND,
                    )
                )
        if missing and status == "confirmed":
            status = "candidate"
        return PreconditionResult(
            satisfied=not missing,
            status=status,
            confidence_adjustment=confidence_adjustment,
            missing_information=missing,
        )

    def _missing(
        self,
        question: str,
        object_name: str,
        reason: str,
        source: MissingSource,
        importance: MissingImportance = MissingImportance.MEDIUM,
    ) -> MissingInformation:
        return MissingInformation(
            question=question,
            object=object_name,
            reason=reason,
            suggested_source=source,
            importance=importance,
        )
