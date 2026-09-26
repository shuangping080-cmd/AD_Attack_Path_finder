"""Ranking helpers for signal findings."""

from adpath.signal.hypothesis import SignalFinding


def rank_signals(findings: list[SignalFinding], top_n: int | None = None) -> list[SignalFinding]:
    """Rank findings by score, confidence, and object name."""
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    ranked = sorted(
        findings,
        key=lambda item: (
            -item.score,
            -confidence_rank.get(item.confidence, 0),
            item.object_name,
        ),
    )
    return ranked[:top_n] if top_n else ranked
