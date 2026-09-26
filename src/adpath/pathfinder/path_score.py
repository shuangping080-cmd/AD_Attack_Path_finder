"""Phase 4 path scoring helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingInformation
from adpath.models.node import Node


@dataclass(slots=True)
class PathScore:
    """Score value with explainable components."""

    value: float
    breakdown: dict[str, float] = field(default_factory=dict)


class PathScorer:
    """Rule-based Phase 4 path scorer."""

    def score(
        self,
        confirmed_edges: list[Edge],
        candidate_edges: list[Edge],
        missing: list[MissingInformation],
        target: Node | None = None,
        confirmed_primitives: int = 0,
        historical_pattern_matches: int = 0,
        reviewed_examples: int = 0,
        example_count: int = 0,
        tier_crossings: int = 0,
        incomplete_preconditions: int = 0,
    ) -> PathScore:
        """Score a path without relying on shortest-path length."""
        high_missing = sum(1 for item in missing if item.importance == MissingImportance.HIGH)
        medium_missing = sum(1 for item in missing if item.importance == MissingImportance.MEDIUM)
        low_missing = sum(1 for item in missing if item.importance == MissingImportance.LOW)
        single_source_penalty = 1 if historical_pattern_matches and example_count <= 1 else 0
        high_value_target = 1 if target and target.properties.get("highvalue") else 0
        breakdown = {
            "confirmed_edge": len(confirmed_edges) * 2.0,
            "confirmed_primitive": confirmed_primitives * 2.0,
            "historical_pattern_match": historical_pattern_matches * 1.0,
            "reviewed_example": reviewed_examples * 1.0,
            "multiple_examples": 1.0 if example_count > 1 else 0.0,
            "high_value_target": high_value_target * 2.0,
            "tier_crossing": tier_crossings * 2.0,
            "missing_high": high_missing * -2.0,
            "missing_medium": medium_missing * -1.0,
            "missing_low": low_missing * -0.5,
            "single_source_pattern": single_source_penalty * -1.0,
            "incomplete_precondition": incomplete_preconditions * -2.0,
            "candidate_edge_penalty": len(candidate_edges) * -0.25,
        }
        return PathScore(value=sum(breakdown.values()), breakdown=breakdown)
