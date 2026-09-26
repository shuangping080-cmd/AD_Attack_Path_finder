"""Group membership detector placeholder."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.models.edge import Edge
from adpath.models.node import Node


class GroupsDetector(BaseDetector):
    """Detect group membership and privileged group relationship candidates."""

    name = "groups"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return group-related findings."""
        # TODO: Identify privileged group reachability and nested membership implications.
        return []
