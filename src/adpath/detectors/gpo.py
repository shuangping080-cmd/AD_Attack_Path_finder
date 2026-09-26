"""GPO primitive detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.detectors.common import finding, missing, primitive
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingSource
from adpath.models.node import Node


class GPODetector(BaseDetector):
    """Detect GPO link and writable-GPO control candidates."""

    name = "gpo"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return GPO findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for edge in graph.edges:
            if edge.relationship == "LinkedTo":
                findings.append(self._linked_to(graph, edge))
            elif edge.relationship in {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner"}:
                target = graph.get_node(edge.target)
                if target and str(target.type) == "GPO":
                    findings.append(self._gpo_control(graph, edge, target))
        return findings

    def _linked_to(self, graph: ADGraph, edge: Edge) -> Finding:
        source = graph.get_node(edge.source)
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "GPOLink",
            "GPO",
            ["LinkedTo"],
            source_type=str(source.type) if source else "GPO",
            target_type=str(target.type) if target else "OU",
            result="PolicyScopeEvidence",
            confidence=0.9,
        )
        return finding(
            name=f"LinkedTo: {edge.source} -> {edge.target}",
            description="A GPO is linked to an OU/domain scope.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"GPO link from {source.name if source else edge.source} to {target.name if target else edge.target}",
            status="confirmed",
            confidence=0.9,
            missing_information=[],
            edge=edge,
            graph=graph,
        )

    def _gpo_control(self, graph: ADGraph, edge: Edge, gpo: Node) -> Finding:
        linked_edges = graph.out_edges(gpo.id, "LinkedTo")
        affected = []
        for link in linked_edges:
            affected.extend(graph.out_edges(link.target, "Contains"))
        primitive_obj = primitive(
            "GPOControl",
            "GPO",
            [edge.relationship, "LinkedTo", "Contains"],
            target_type="GPO",
            result="GPOControlCandidate",
            confidence=0.65,
            preconditions=["Writable GPO", "Linked scope", "Policy refresh/applies to target"],
        )
        return finding(
            name=f"GPOControl: {edge.source} -> {gpo.name}",
            description="A principal can modify a GPO; impact depends on linked scopes and policy application.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"GPO control candidate over {gpo.name}",
            status="candidate" if linked_edges else "incomplete",
            confidence=0.65 if linked_edges else 0.45,
            missing_information=[
                missing(
                    "Which computers or users receive this GPO?",
                    gpo.name,
                    "GPO write is not host admin until linked scope and policy application are known.",
                    MissingSource.BLOODHOUND,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
            evidence={
                "linked_scope_count": len(linked_edges),
                "affected_child_count": len(affected),
                "linked_scopes": [item.target for item in linked_edges],
            },
        )
