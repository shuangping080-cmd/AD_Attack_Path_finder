"""gMSA primitive detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.detectors.common import finding, is_gmsa, missing, primitive
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingSource
from adpath.models.node import Node


class GMSADetector(BaseDetector):
    """Detect gMSA credential and downstream impact candidates."""

    name = "gmsa"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return gMSA findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for edge in graph.edges:
            if edge.relationship == "ReadGMSAPassword":
                findings.append(self._read_gmsa_password(graph, edge))
        for node in graph.nodes:
            if is_gmsa(node):
                findings.extend(self._impact_findings(graph, node))
        return findings

    def _read_gmsa_password(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "ReadGMSAPassword",
            "gMSA",
            ["ReadGMSAPassword"],
            target_type="gMSA",
            result="ServiceAccountCredentialCandidate",
            confidence=0.85,
            preconditions=["Read msDS-ManagedPassword"],
        )
        return finding(
            name=f"ReadGMSAPassword: {edge.source} -> {edge.target}",
            description="A principal can read gMSA managed password material.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"gMSA credential candidate for {target.name if target else edge.target}",
            status="confirmed",
            confidence=0.85,
            missing_information=[
                missing(
                    "Where is this gMSA privileged downstream?",
                    target.name if target else edge.target,
                    "Credential impact depends on MemberOf/AdminTo/Delegation relationships.",
                    MissingSource.BLOODHOUND,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
        )

    def _impact_findings(self, graph: ADGraph, node: Node) -> list[Finding]:
        findings: list[Finding] = []
        for edge in graph.out_edges(node.id):
            if edge.relationship not in {"MemberOf", "AdminTo", "AllowedToDelegate", "AllowedToAct"}:
                continue
            target = graph.get_node(edge.target)
            primitive_obj = primitive(
                "GMSAImpact",
                "gMSA",
                [edge.relationship],
                source_type="gMSA",
                target_type=str(target.type) if target else "*",
                result="DownstreamServiceAccountImpact",
                confidence=0.65,
            )
            findings.append(
                finding(
                    name=f"gMSAImpact: {node.name} --{edge.relationship}--> {edge.target}",
                    description="A gMSA has downstream privilege-relevant relationships.",
                    source=edge.source,
                    target=edge.target,
                    relationship=edge.relationship,
                    primitive_obj=primitive_obj,
                    result=f"gMSA downstream impact through {edge.relationship}",
                    status="candidate",
                    confidence=0.65,
                    missing_information=[],
                    edge=edge,
                    graph=graph,
                )
            )
        return findings
