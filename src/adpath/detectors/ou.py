"""OU primitive detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.detectors.common import finding, missing, primitive
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingSource
from adpath.models.node import Node


class OUDetector(BaseDetector):
    """Detect OU containment and delegated-control candidates."""

    name = "ou"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return OU findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for edge in graph.edges:
            target = graph.get_node(edge.target)
            if edge.relationship in {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner"}:
                if target and str(target.type) == "OU":
                    findings.append(self._ou_control(graph, edge, target))
            elif edge.relationship == "Contains":
                source = graph.get_node(edge.source)
                if source and str(source.type) in {"OU", "Container"}:
                    findings.append(self._contains(graph, edge, source))
        return findings

    def _ou_control(self, graph: ADGraph, edge: Edge, ou: Node) -> Finding:
        child_edges = graph.out_edges(ou.id, "Contains")
        primitive_obj = primitive(
            "OUControl",
            "OU",
            [edge.relationship, "Contains"],
            target_type="OU",
            result="OUControlCandidate",
            confidence=0.65,
            preconditions=["Effective OU ACL", "Inherited control path to child objects"],
        )
        return finding(
            name=f"OUControl: {edge.source} -> {ou.name}",
            description="A principal has a control relationship over an OU.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"OU control candidate over {ou.name}",
            status="candidate",
            confidence=0.65,
            missing_information=[
                missing(
                    "Which child objects inherit this OU control?",
                    ou.name,
                    "OU rights propagate only when inheritance and object-specific ACEs allow it.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
            evidence={
                "child_count": len(child_edges),
                "child_object_types": sorted({str(item.properties.get("object_type")) for item in child_edges}),
            },
        )

    def _contains(self, graph: ADGraph, edge: Edge, container: Node) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "OUContainsObject",
            "OU",
            ["Contains"],
            source_type=str(container.type),
            target_type=str(target.type) if target else "*",
            result="ContainmentEvidence",
            confidence=0.9,
        )
        return finding(
            name=f"Contains: {container.name} -> {edge.target}",
            description="OU/container containment is evidence for policy and inherited ACL analysis.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"{container.name} contains {target.name if target else edge.target}",
            status="confirmed",
            confidence=0.9,
            missing_information=[],
            edge=edge,
            graph=graph,
        )
