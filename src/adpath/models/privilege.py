"""Privilege level and transition models."""

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any


class PrivilegeLevel(IntEnum):
    """Coarse privilege levels used for Phase 2 path scoring."""

    NORMAL_USER = 1
    CONTROLLED_USER = 2
    SERVICE_ACCOUNT = 3
    PRIVILEGED_GROUP = 4
    LOCAL_PRIVILEGE = 5
    DOMAIN_PRIVILEGE = 6

    @property
    def label(self) -> str:
        """Return a stable display label."""
        return {
            PrivilegeLevel.NORMAL_USER: "NormalUser",
            PrivilegeLevel.CONTROLLED_USER: "ControlledUser",
            PrivilegeLevel.SERVICE_ACCOUNT: "ServiceAccount",
            PrivilegeLevel.PRIVILEGED_GROUP: "PrivilegedGroup",
            PrivilegeLevel.LOCAL_PRIVILEGE: "LocalPrivilege",
            PrivilegeLevel.DOMAIN_PRIVILEGE: "DomainPrivilege",
        }[self]


class PrivilegeTier(StrEnum):
    """Coarse enterprise tier inspired by tiered administration models."""

    TIER0 = "Tier0"
    TIER1 = "Tier1"
    TIER2 = "Tier2"
    UNKNOWN = "Unknown"


@dataclass(frozen=True, slots=True)
class PrivilegeBoundary:
    """A privilege boundary crossing on one edge."""

    source_tier: PrivilegeTier
    target_tier: PrivilegeTier
    reason: str

    @property
    def crosses(self) -> bool:
        """Return whether this is a lower-to-higher tier crossing."""
        order = {
            PrivilegeTier.TIER2: 1,
            PrivilegeTier.TIER1: 2,
            PrivilegeTier.TIER0: 3,
            PrivilegeTier.UNKNOWN: 0,
        }
        return order[self.target_tier] > order[self.source_tier]


@dataclass(slots=True)
class PrivilegeTransition:
    """Privilege meaning derived from one graph edge."""

    source: str
    target: str
    relationship: str
    from_level: PrivilegeLevel
    to_level: PrivilegeLevel
    result: str
    source_tier: PrivilegeTier = PrivilegeTier.UNKNOWN
    target_tier: PrivilegeTier = PrivilegeTier.UNKNOWN
    boundary: PrivilegeBoundary | None = None
    key_edge: bool = False
    confirmed: bool = False
    confidence: float = 1.0
    missing_information: list[Any] = field(default_factory=list)

    @property
    def gain(self) -> int:
        """Return positive privilege gain."""
        return max(0, int(self.to_level) - int(self.from_level))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable transition."""
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "from_level": self.from_level.label,
            "to_level": self.to_level.label,
            "result": self.result,
            "source_tier": self.source_tier,
            "target_tier": self.target_tier,
            "boundary_crossing": self.boundary.crosses if self.boundary else False,
            "key_edge": self.key_edge,
            "confirmed": self.confirmed,
            "confidence": self.confidence,
            "missing_information": [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.missing_information
            ],
            "gain": self.gain,
        }
