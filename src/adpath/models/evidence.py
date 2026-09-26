"""Evidence models for path-level reasoning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HistoricalSupport:
    """Historical KB support attached to a candidate path."""

    pattern: str | None = None
    machine: str | None = None
    examples: list[dict[str, Any]] = field(default_factory=list)
    source_count: int = 0
    confidence: str = "unknown"
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable support."""
        return {
            "pattern": self.pattern,
            "machine": self.machine,
            "examples": self.examples,
            "source_count": self.source_count,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class PathEvidence:
    """Structured evidence explaining why a path was produced."""

    current_graph_edges: list[dict[str, Any]] = field(default_factory=list)
    semantic_findings: list[dict[str, Any] | str] = field(default_factory=list)
    historical_patterns: list[dict[str, Any]] = field(default_factory=list)
    missing_information: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    score_breakdown: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable evidence."""
        return {
            "current_graph": self.current_graph_edges,
            "semantic_findings": self.semantic_findings,
            "historical_patterns": self.historical_patterns,
            "missing": self.missing_information,
            "notes": self.notes,
            "score_breakdown": self.score_breakdown,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> PathEvidence:
        """Build evidence from the legacy dictionary shape."""
        return cls(
            current_graph_edges=list(data.get("current_graph") or data.get("current_graph_edges") or []),
            semantic_findings=list(data.get("semantic_findings") or []),
            historical_patterns=list(data.get("historical_patterns") or data.get("historical_support") or []),
            missing_information=list(data.get("missing") or data.get("missing_information") or []),
            notes=list(data.get("notes") or []),
            score_breakdown=dict(data.get("score_breakdown") or data.get("score_components") or {}),
        )

    def get(self, key: str, default: Any = None) -> Any:
        """Dictionary-compatible getter."""
        return self.to_dict().get(key, default)

    def setdefault(self, key: str, default: Any) -> Any:
        """Dictionary-compatible setter for legacy callers."""
        current = self.get(key)
        if current:
            return current
        if key in {"current_graph", "current_graph_edges"}:
            self.current_graph_edges = list(default)
            return self.current_graph_edges
        if key == "semantic_findings":
            self.semantic_findings = list(default)
            return self.semantic_findings
        if key in {"historical_patterns", "historical_support"}:
            self.historical_patterns = list(default)
            return self.historical_patterns
        if key in {"missing", "missing_information"}:
            self.missing_information = list(default)
            return self.missing_information
        if key in {"score_components", "score_breakdown"}:
            self.score_breakdown = dict(default)
            return self.score_breakdown
        if key == "notes":
            self.notes = list(default)
            return self.notes
        return default

    def __getitem__(self, key: str) -> Any:
        """Dictionary-compatible indexing."""
        return self.to_dict()[key]
