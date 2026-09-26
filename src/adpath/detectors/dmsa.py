"""dMSA and BadSuccessor primitive detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.detectors.common import finding, is_dmsa, missing, primitive
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingSource
from adpath.models.node import Node


class DMSADetector(BaseDetector):
    """Detect dMSA and BadSuccessor candidates."""

    name = "dmsa"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return dMSA findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for edge in graph.edges:
            if edge.relationship == "ReadDMSAPassword":
                findings.append(self._read_dmsa_password(graph, edge))
            if edge.relationship in {"CreateChild", "GenericAll", "GenericWrite", "WriteDACL"}:
                target = graph.get_node(edge.target)
                if target and str(target.type) == "OU":
                    findings.append(self._bad_successor_candidate(graph, edge, target))
        for node in graph.nodes:
            if is_dmsa(node):
                findings.append(self._dmsa_identity(graph, node))
        return findings

    def _read_dmsa_password(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "ReadDMSAPassword",
            "dMSA",
            ["ReadDMSAPassword"],
            target_type="dMSA",
            result="DelegatedManagedServiceCredentialCandidate",
            confidence=0.8,
        )
        return finding(
            name=f"ReadDMSAPassword: {edge.source} -> {edge.target}",
            description="A principal can read dMSA password material.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"dMSA credential candidate for {target.name if target else edge.target}",
            status="confirmed",
            confidence=0.8,
            missing_information=[],
            edge=edge,
            graph=graph,
        )

    def _bad_successor_candidate(self, graph: ADGraph, edge: Edge, ou: Node) -> Finding:
        primitive_obj = primitive(
            "BadSuccessor",
            "dMSA",
            [edge.relationship, "Contains"],
            target_type="OU",
            result="BadSuccessorCandidate",
            confidence=0.55,
            preconditions=[
                "dMSA creation or write path under OU",
                "Predecessor/successor relationship evidence",
            ],
        )
        return finding(
            name=f"BadSuccessorCandidate: {edge.source} -> {ou.name}",
            description="Control over an OU can be a prerequisite for BadSuccessor-style dMSA abuse.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"BadSuccessor candidate under {ou.name}",
            status="candidate" if edge.relationship == "CreateChild" else "incomplete",
            confidence=0.7 if edge.relationship == "CreateChild" else 0.55,
            missing_information=[
                missing(
                    "Can a dMSA be created or modified in this OU?",
                    ou.name,
                    f"{edge.relationship} is enabling evidence, not BadSuccessor by itself.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                ),
                missing(
                    "What predecessor/successor account relationship is present?",
                    ou.name,
                    "BadSuccessor requires successor linkage evidence.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                ),
            ],
            edge=edge,
            graph=graph,
        )

    def _dmsa_identity(self, graph: ADGraph, node: Node) -> Finding:
        primitive_obj = primitive(
            "DMSAIdentity",
            "dMSA",
            [],
            target_type=str(node.type),
            result="DMSAObjectIdentified",
            confidence=0.7,
        )
        return finding(
            name=f"dMSA: {node.name}",
            description="The object is identified as a delegated managed service account.",
            source=node.id,
            target=node.id,
            relationship="IsDMSA",
            primitive_obj=primitive_obj,
            result=f"dMSA object identified: {node.name}",
            status="confirmed",
            confidence=0.7,
            missing_information=[],
            graph=graph,
            evidence={"properties": node.properties},
        )
