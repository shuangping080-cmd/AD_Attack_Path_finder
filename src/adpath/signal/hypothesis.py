"""Signal findings and hypothesis models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from adpath.models.node import Node


class SignalStatus(StrEnum):
    """Evidence level for interesting-object signals."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    PATTERN_MATCHED = "pattern_matched"
    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"


@dataclass(slots=True)
class SignalFinding:
    """A conservative interesting-object finding for initial foothold analysis."""

    object_id: str
    object_name: str
    object_type: str
    signal: str
    hypothesis: str
    status: SignalStatus = SignalStatus.HYPOTHESIS
    confidence: str = "medium"
    risk_if_valid: str = "foothold"
    score: float = 0.0
    observed_evidence: list[str] = field(default_factory=list)
    pattern_matches: list[dict[str, Any]] = field(default_factory=list)
    suggested_validation: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def for_node(
        cls,
        node: Node,
        signal: str,
        hypothesis: str,
        *,
        status: SignalStatus = SignalStatus.HYPOTHESIS,
        confidence: str = "medium",
        risk_if_valid: str = "foothold",
        score: float = 0.0,
        observed_evidence: list[str] | None = None,
        pattern_matches: list[dict[str, Any]] | None = None,
        suggested_validation: list[str] | None = None,
        next_steps: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SignalFinding:
        """Build a signal finding from a graph node."""
        return cls(
            object_id=node.id,
            object_name=node.name,
            object_type=str(node.type),
            signal=signal,
            hypothesis=hypothesis,
            status=status,
            confidence=confidence,
            risk_if_valid=risk_if_valid,
            score=score,
            observed_evidence=observed_evidence or [],
            pattern_matches=pattern_matches or [],
            suggested_validation=suggested_validation or [],
            next_steps=next_steps or [],
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable signal data."""
        return {
            "object_id": self.object_id,
            "object_name": self.object_name,
            "object_type": self.object_type,
            "signal": self.signal,
            "hypothesis": self.hypothesis,
            "status": str(self.status),
            "confidence": self.confidence,
            "risk_if_valid": self.risk_if_valid,
            "score": self.score,
            "observed_evidence": self.observed_evidence,
            "pattern_matches": self.pattern_matches,
            "suggested_validation": self.suggested_validation,
            "next_steps": self.next_steps,
            "metadata": self.metadata,
        }
