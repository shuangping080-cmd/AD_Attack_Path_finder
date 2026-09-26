"""Interesting signal and foothold hypothesis engine."""

from adpath.signal.evidence_store import EvidenceRecord, EvidenceStore
from adpath.signal.hypothesis import SignalFinding, SignalStatus
from adpath.signal.ranking import rank_signals

__all__ = [
    "EvidenceRecord",
    "EvidenceStore",
    "SignalFinding",
    "SignalStatus",
    "rank_signals",
]
