"""Node model for normalized Active Directory graph objects."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NodeType(StrEnum):
    """Supported normalized AD node types."""

    USER = "User"
    GROUP = "Group"
    COMPUTER = "Computer"
    DOMAIN = "Domain"
    OU = "OU"
    GPO = "GPO"
    CONTAINER = "Container"
    SERVICE_ACCOUNT = "ServiceAccount"
    GMSA = "gMSA"
    DMSA = "dMSA"
    CERTIFICATE_TEMPLATE = "CertificateTemplate"
    CA = "CA"
    CERTIFICATE_AUTHORITY = "CertificateAuthority"


@dataclass(slots=True)
class Node:
    """Normalized graph node representing an AD object or security-relevant entity."""

    id: str
    name: str
    type: NodeType | str
    domain: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "id": self.id,
            "name": self.name,
            "type": str(self.type),
            "domain": self.domain,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Node":
        """Build a node from normalized JSON data."""
        return cls(
            id=str(data["id"]),
            name=str(data.get("name") or data["id"]),
            type=data.get("type", "Unknown"),
            domain=data.get("domain"),
            properties=dict(data.get("properties") or {}),
        )
