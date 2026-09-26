"""Privilege transition detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingInformation, MissingSource
from adpath.models.node import Node
from adpath.models.privilege import (
    PrivilegeBoundary,
    PrivilegeLevel,
    PrivilegeTier,
    PrivilegeTransition,
)

CONTROL_RELATIONSHIPS = {
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "ForceChangePassword",
    "WriteSPN",
}
ADVANCED_RELATIONSHIP_LEVELS = {
    "ASREPRoast": PrivilegeLevel.CONTROLLED_USER,
    "Kerberoast": PrivilegeLevel.SERVICE_ACCOUNT,
    "TargetedKerberoast": PrivilegeLevel.SERVICE_ACCOUNT,
    "SilverTicketCandidate": PrivilegeLevel.LOCAL_PRIVILEGE,
    "GoldenTicketCandidate": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "CreateChild": PrivilegeLevel.SERVICE_ACCOUNT,
    "RBCD": PrivilegeLevel.LOCAL_PRIVILEGE,
    "ConstrainedDelegation": PrivilegeLevel.LOCAL_PRIVILEGE,
    "S4U": PrivilegeLevel.LOCAL_PRIVILEGE,
    "UnconstrainedDelegation": PrivilegeLevel.LOCAL_PRIVILEGE,
    "ReadGMSAPassword": PrivilegeLevel.SERVICE_ACCOUNT,
    "ReadDMSAPassword": PrivilegeLevel.SERVICE_ACCOUNT,
    "BadSuccessor": PrivilegeLevel.SERVICE_ACCOUNT,
    "OUControl": PrivilegeLevel.CONTROLLED_USER,
    "GPOControl": PrivilegeLevel.LOCAL_PRIVILEGE,
    "ESC1": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "ESC4": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "ESC6": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "ESC7": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "ESC8": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "ESC9": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "ESC11": PrivilegeLevel.DOMAIN_PRIVILEGE,
    "ESC15": PrivilegeLevel.DOMAIN_PRIVILEGE,
}
DOMAIN_PRIVILEGE_NAMES = {
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
    "DOMAIN CONTROLLERS",
}
PRIVILEGED_GROUP_NAMES = {
    "ADMINISTRATORS",
    "ACCOUNT OPERATORS",
    "BACKUP OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "KEY ADMINS",
    "ENTERPRISE KEY ADMINS",
}
LOCAL_PRIVILEGE_NAMES = {"REMOTE MANAGEMENT USERS", "REMOTE DESKTOP USERS", "DNSADMINS"}


class PrivilegeDetector(BaseDetector):
    """Detect privilege tier and high-value relationship candidates."""

    name = "privilege"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return privilege findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for transition in self.transitions(graph):
            if transition.gain <= 0:
                continue
            source = graph.get_node(transition.source)
            target = graph.get_node(transition.target)
            findings.append(
                Finding(
                    name=f"Privilege transition: {transition.relationship}",
                    description=transition.result,
                    source=transition.source,
                    target=transition.target,
                    relationship=transition.relationship,
                    result=transition.result,
                    status="confirmed" if transition.confirmed else "candidate",
                    confidence=transition.confidence,
                    missing_information=transition.missing_information,
                    evidence={
                        "source_name": source.name if source else None,
                        "target_name": target.name if target else None,
                        "transition": transition.to_dict(),
                    },
                )
            )
        return findings

    def transitions(self, graph: ADGraph) -> list[PrivilegeTransition]:
        """Return privilege transitions for graph edges."""
        transitions: list[PrivilegeTransition] = []
        for edge in graph.edges:
            source = graph.get_node(edge.source)
            target = graph.get_node(edge.target)
            if source is None or target is None:
                continue
            from_level = self.node_level(source)
            to_level = self.transition_level(edge, target)
            if to_level is None:
                continue
            source_tier = self.node_tier(source)
            target_tier = self.node_tier(target, to_level)
            boundary = PrivilegeBoundary(
                source_tier=source_tier,
                target_tier=target_tier,
                reason=f"{edge.relationship} crosses {source_tier} -> {target_tier}",
            )
            transitions.append(
                PrivilegeTransition(
                    source=edge.source,
                    target=edge.target,
                    relationship=edge.relationship,
                    from_level=from_level,
                    to_level=to_level,
                    result=self._result(edge, target, to_level),
                    source_tier=source_tier,
                    target_tier=target_tier,
                    boundary=boundary,
                    key_edge=boundary.crosses or to_level > from_level,
                    confirmed=edge.relationship in {"MemberOf", "AdminTo"},
                    confidence=self._confidence(edge, target, from_level, to_level),
                    missing_information=self._missing(edge, target),
                )
            )
        return transitions

    def node_level(self, node: Node) -> PrivilegeLevel:
        """Classify a node's baseline privilege tier."""
        node_type = str(node.type)
        name = node.name.split("@", 1)[0].upper()
        if node_type == "Group" and name in DOMAIN_PRIVILEGE_NAMES:
            return PrivilegeLevel.DOMAIN_PRIVILEGE
        if node_type == "Group" and (name in PRIVILEGED_GROUP_NAMES or node.properties.get("highvalue")):
            return PrivilegeLevel.PRIVILEGED_GROUP
        if node_type == "Group" and name in LOCAL_PRIVILEGE_NAMES:
            return PrivilegeLevel.LOCAL_PRIVILEGE
        if node_type == "User" and (node.properties.get("hasspn") or node.properties.get("serviceprincipalnames")):
            return PrivilegeLevel.SERVICE_ACCOUNT
        return PrivilegeLevel.NORMAL_USER

    def node_tier(self, node: Node, level: PrivilegeLevel | None = None) -> PrivilegeTier:
        """Classify a node into a coarse enterprise administration tier."""
        level = level or self.node_level(node)
        name = node.name.split("@", 1)[0].upper()
        if level == PrivilegeLevel.DOMAIN_PRIVILEGE or name in DOMAIN_PRIVILEGE_NAMES:
            return PrivilegeTier.TIER0
        if level in {PrivilegeLevel.PRIVILEGED_GROUP, PrivilegeLevel.LOCAL_PRIVILEGE}:
            return PrivilegeTier.TIER1
        if level in {PrivilegeLevel.NORMAL_USER, PrivilegeLevel.CONTROLLED_USER, PrivilegeLevel.SERVICE_ACCOUNT}:
            return PrivilegeTier.TIER2
        return PrivilegeTier.UNKNOWN

    def transition_level(self, edge: Edge, target: Node) -> PrivilegeLevel | None:
        """Classify the privilege level produced by an edge."""
        if edge.relationship in CONTROL_RELATIONSHIPS and str(target.type) == "User":
            if edge.relationship == "WriteSPN":
                return PrivilegeLevel.SERVICE_ACCOUNT
            if target.properties.get("hasspn") or target.properties.get("serviceprincipalnames"):
                return PrivilegeLevel.SERVICE_ACCOUNT
            return PrivilegeLevel.CONTROLLED_USER
        if edge.relationship in CONTROL_RELATIONSHIPS:
            return max(self.node_level(target), PrivilegeLevel.CONTROLLED_USER)
        if edge.relationship == "MemberOf":
            return self.node_level(target)
        if edge.relationship == "AdminTo":
            return PrivilegeLevel.LOCAL_PRIVILEGE
        if edge.relationship in ADVANCED_RELATIONSHIP_LEVELS:
            return max(ADVANCED_RELATIONSHIP_LEVELS[edge.relationship], self.node_level(target))
        return None

    def _result(self, edge: Edge, target: Node, level: PrivilegeLevel) -> str:
        return f"{edge.relationship} may move analysis toward {level.label} via {target.name}"

    def _confidence(
        self,
        edge: Edge,
        target: Node,
        from_level: PrivilegeLevel,
        to_level: PrivilegeLevel,
    ) -> float:
        confidence = 0.9 if edge.relationship in {"MemberOf", "AdminTo"} else 0.65
        if edge.relationship == "MemberOf" and to_level <= from_level:
            confidence = 0.35
        if edge.relationship in {"WriteDACL", "WriteOwner"}:
            confidence = 0.55
        if target.properties.get("highvalue") and to_level != PrivilegeLevel.DOMAIN_PRIVILEGE:
            confidence += 0.05
        if edge.source_tool == "semantic":
            confidence = min(confidence, edge.confidence)
        return min(confidence, 1.0)

    def _missing(self, edge: Edge, target: Node) -> list[MissingInformation]:
        if edge.relationship == "AdminTo":
            return [
                MissingInformation(
                    question="Who has sessions on this host?",
                    object=target.name,
                    reason="AdminTo is local privilege; domain impact depends on exposed credentials.",
                    suggested_source=MissingSource.BLOODHOUND,
                    importance=MissingImportance.HIGH,
                ),
                MissingInformation(
                    question="Are domain credentials stored on this host?",
                    object=target.name,
                    reason="Stored credentials can cross from local privilege into domain exposure.",
                    suggested_source=MissingSource.HOST,
                    importance=MissingImportance.HIGH,
                ),
            ]
        if edge.relationship == "MemberOf" and not target.properties.get("highvalue"):
            return [
                MissingInformation(
                    question="What privilege tier is this group?",
                    object=target.name,
                    reason="Ordinary group membership is not automatically privilege gain.",
                    suggested_source=MissingSource.BLOODHOUND,
                )
            ]
        if edge.relationship == "GenericWrite":
            return [
                MissingInformation(
                    question="Which attributes are writable?",
                    object=target.name,
                    reason="GenericWrite impact depends on target object type and writable attributes.",
                    suggested_source=MissingSource.LDAP,
                ),
                MissingInformation(
                    question="What downstream privileges does the target have?",
                    object=target.name,
                    reason="Identity or object control matters through downstream relationships.",
                    suggested_source=MissingSource.BLOODHOUND,
                    importance=MissingImportance.HIGH,
                ),
            ]
        if edge.source_tool == "semantic":
            missing = []
            for item in edge.properties.get("missing_information") or []:
                if isinstance(item, MissingInformation):
                    missing.append(item)
                elif isinstance(item, dict):
                    missing.append(
                        MissingInformation(
                            question=str(item.get("question") or "What evidence is missing?"),
                            object=str(item.get("object") or target.name),
                            reason=str(item.get("reason") or "Semantic primitive is not fully confirmed."),
                            suggested_source=item.get("suggested_source") or MissingSource.BLOODHOUND,
                            importance=MissingImportance[str(item.get("importance", "medium")).upper()]
                            if str(item.get("importance", "medium")).upper() in MissingImportance.__members__
                            else MissingImportance.MEDIUM,
                        )
                    )
            return missing
        return []
