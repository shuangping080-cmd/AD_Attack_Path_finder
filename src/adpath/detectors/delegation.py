"""Delegation primitive detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.detectors.common import finding, missing, primitive, prop_bool, prop_list
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingSource
from adpath.models.node import Node


class DelegationDetector(BaseDetector):
    """Detect unconstrained, constrained, and resource-based delegation candidates."""

    name = "delegation"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return delegation findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for node in graph.nodes:
            if prop_bool(node.properties, "unconstraineddelegation", "UnconstrainedDelegation"):
                findings.append(self._unconstrained(graph, node))
            if prop_list(node.properties, "allowedtodelegate", "AllowedToDelegate"):
                findings.append(self._property_constrained(graph, node))
        for edge in graph.edges:
            if edge.relationship == "AllowedToAct":
                findings.append(self._rbcd(graph, edge))
            elif edge.relationship == "AllowedToDelegate":
                findings.append(self._constrained(graph, edge))
        return findings

    def _unconstrained(self, graph: ADGraph, node: Node) -> Finding:
        primitive_obj = primitive(
            "UnconstrainedDelegation",
            "Delegation",
            ["UnconstrainedDelegation"],
            target_type=str(node.type),
            result="CredentialExposureCandidate",
            confidence=0.75,
            preconditions=["Victim coerced or authenticates to delegated service"],
        )
        return finding(
            name=f"UnconstrainedDelegation: {node.name}",
            description="The object is configured for unconstrained delegation.",
            source=node.id,
            target=node.id,
            relationship="UnconstrainedDelegation",
            primitive_obj=primitive_obj,
            result=f"Unconstrained delegation credential exposure candidate on {node.name}",
            status="candidate",
            confidence=0.75,
            missing_information=[
                missing(
                    "Can privileged users authenticate to this service?",
                    node.name,
                    "Unconstrained delegation impact depends on coercion or existing sessions.",
                    MissingSource.BLOODHOUND,
                    MissingImportance.HIGH,
                )
            ],
            graph=graph,
            evidence={"properties": node.properties},
        )

    def _property_constrained(self, graph: ADGraph, node: Node) -> Finding:
        services = prop_list(node.properties, "allowedtodelegate", "AllowedToDelegate")
        primitive_obj = primitive(
            "ConstrainedDelegation",
            "Delegation",
            ["AllowedToDelegate"],
            target_type=str(node.type),
            result="S4UCandidate",
            confidence=0.65,
            preconditions=["Control delegated principal", "Target SPN reachable"],
        )
        return finding(
            name=f"ConstrainedDelegation: {node.name}",
            description="The object has constrained delegation targets configured.",
            source=node.id,
            target=node.id,
            relationship="AllowedToDelegate",
            primitive_obj=primitive_obj,
            result=f"Constrained delegation candidate from {node.name}",
            status="candidate",
            confidence=0.65,
            missing_information=[
                missing(
                    "Is the delegated principal controlled?",
                    node.name,
                    "S4U abuse requires control of the account configured for delegation.",
                    MissingSource.BLOODHOUND,
                    MissingImportance.HIGH,
                )
            ],
            graph=graph,
            evidence={"target_services": services},
        )

    def _rbcd(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "RBCD",
            "Delegation",
            ["AllowedToAct"],
            target_type=str(target.type) if target else "Computer",
            result="ResourceBasedConstrainedDelegationCandidate",
            confidence=0.8,
            preconditions=["Controlled machine/account with SPN", "Writable msDS-AllowedToAct"],
        )
        return finding(
            name=f"RBCD: {edge.source} -> {edge.target}",
            description="A principal is allowed to act on behalf of others to a target computer.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"RBCD candidate against {target.name if target else edge.target}",
            status="candidate",
            confidence=0.8,
            missing_information=[
                missing(
                    "Is the source account controlled and service-capable?",
                    edge.source,
                    "RBCD requires a controlled account, commonly with an SPN.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                ),
                missing(
                    "Which service/SPN is the intended target?",
                    target.name if target else edge.target,
                    "Operational impact depends on the target service.",
                    MissingSource.LDAP,
                ),
            ],
            edge=edge,
            graph=graph,
        )

    def _constrained(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "S4U",
            "Delegation",
            ["AllowedToDelegate"],
            target_type=str(target.type) if target else "*",
            result="S4UDelegationCandidate",
            confidence=0.65,
            preconditions=["Controlled delegated principal", "Configured target SPN"],
        )
        return finding(
            name=f"S4U: {edge.source} -> {edge.target}",
            description="AllowedToDelegate can enable constrained delegation abuse when controlled.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"S4U candidate to {target.name if target else edge.target}",
            status="candidate",
            confidence=0.65,
            missing_information=[
                missing(
                    "Is the delegating account controlled?",
                    edge.source,
                    "S4U requires usable credentials for the delegating principal.",
                    MissingSource.BLOODHOUND,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
            evidence={"service_principal_name": edge.properties.get("service_principal_name")},
        )
