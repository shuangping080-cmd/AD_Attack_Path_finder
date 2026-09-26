"""Kerberos primitive detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.detectors.common import (
    finding,
    is_service_account,
    missing,
    primitive,
    prop_bool,
    prop_list,
)
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingSource
from adpath.models.node import Node


class KerberosDetector(BaseDetector):
    """Detect Kerberos roast and ticket forgery candidates."""

    name = "kerberos"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return Kerberos findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for node in graph.nodes:
            findings.extend(self._node_findings(graph, node))
        for edge in graph.edges:
            if edge.relationship in {"GenericWrite", "WriteSPN"}:
                target = graph.get_node(edge.target)
                if target and (is_service_account(target) or str(target.type) == "User"):
                    findings.append(self._targeted_kerberoast(graph, edge, target))
            if edge.relationship == "DCSync":
                findings.append(self._golden_ticket(graph, edge))
        return findings

    def _node_findings(self, graph: ADGraph, node: Node) -> list[Finding]:
        findings: list[Finding] = []
        if str(node.type) in {"User", "ServiceAccount", "gMSA", "dMSA"} and prop_bool(
            node.properties,
            "dontreqpreauth",
            "DoesNotRequirePreAuth",
        ):
            primitive_obj = primitive(
                "ASREPRoast",
                "Kerberos",
                [],
                target_type=str(node.type),
                result="OfflineCredentialAttackCandidate",
                confidence=0.8,
                preconditions=["DONT_REQ_PREAUTH is set"],
            )
            findings.append(
                finding(
                    name=f"ASREPRoast: {node.name}",
                    description=f"{node.name} does not require Kerberos pre-authentication.",
                    source=node.id,
                    target=node.id,
                    relationship="DoesNotRequirePreAuth",
                    primitive_obj=primitive_obj,
                    result=f"ASREPRoast candidate for {node.name}",
                    status="candidate",
                    confidence=0.8,
                    missing_information=[
                        missing(
                            "Can the recovered hash be cracked?",
                            node.name,
                            "ASREP roasting still requires password cracking or reuse impact.",
                            MissingSource.HOST,
                        )
                    ],
                    graph=graph,
                    evidence={"properties": node.properties},
                )
            )
        if is_service_account(node):
            findings.extend(self._service_account_findings(graph, node))
        return findings

    def _service_account_findings(self, graph: ADGraph, node: Node) -> list[Finding]:
        spns = prop_list(node.properties, "serviceprincipalnames", "ServicePrincipalNames", "spns")
        primitive_obj = primitive(
            "Kerberoast",
            "Kerberos",
            ["HasSPN"],
            target_type=str(node.type),
            result="ServiceTicketRoastCandidate",
            confidence=0.75,
            preconditions=["Account has at least one SPN"],
        )
        return [
            finding(
                name=f"Kerberoast: {node.name}",
                description=f"{node.name} has SPN material and can be considered for Kerberoasting.",
                source=node.id,
                target=node.id,
                relationship="HasSPN",
                primitive_obj=primitive_obj,
                result=f"Kerberoast candidate for {node.name}",
                status="candidate",
                confidence=0.75,
                missing_information=[
                    missing(
                        "Can the service ticket hash be cracked?",
                        node.name,
                        "SPN presence is not equivalent to credential compromise.",
                        MissingSource.HOST,
                    )
                ],
                graph=graph,
                evidence={"spns": spns, "properties": node.properties},
            ),
            self._silver_ticket(graph, node, spns),
        ]

    def _targeted_kerberoast(self, graph: ADGraph, edge: Edge, target: Node) -> Finding:
        primitive_obj = primitive(
            "TargetedKerberoast",
            "Kerberos",
            [edge.relationship, "HasSPN"],
            target_type=str(target.type),
            result="TargetedKerberoastCandidate",
            confidence=0.8 if edge.relationship == "WriteSPN" else 0.65,
            preconditions=["Writable SPN attribute", "Controlled requesting principal"],
        )
        missing_information = [
            missing(
                "Can the resulting service ticket hash be cracked?",
                target.name,
                "The primitive yields an offline attack, not guaranteed access.",
                MissingSource.HOST,
            )
        ]
        if edge.relationship == "GenericWrite":
            missing_information.insert(
                0,
                missing(
                    "Is the servicePrincipalName attribute writable?",
                    target.name,
                    "GenericWrite must allow SPN modification for targeted Kerberoast.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                ),
            )
        return finding(
            name=f"TargetedKerberoast: {edge.source} -> {target.name}",
            description=self._targeted_description(edge),
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"Targeted Kerberoast candidate against {target.name}",
            status="candidate",
            confidence=0.8 if edge.relationship == "WriteSPN" else 0.65,
            missing_information=missing_information,
            edge=edge,
            graph=graph,
            evidence={"target_properties": target.properties},
        )

    def _targeted_description(self, edge: Edge) -> str:
        if edge.relationship == "WriteSPN":
            return "WriteSPN directly evidences servicePrincipalName modification capability."
        return "GenericWrite over an identity may allow SPN manipulation if the attribute is writable."

    def _silver_ticket(self, graph: ADGraph, node: Node, spns: list[object]) -> Finding:
        primitive_obj = primitive(
            "SilverTicketCandidate",
            "Kerberos",
            ["HasSPN"],
            target_type=str(node.type),
            result="ServiceTicketForgeryIncomplete",
            confidence=0.35,
            preconditions=["Service key or NT hash is compromised"],
        )
        return finding(
            name=f"SilverTicketCandidate: {node.name}",
            description="SPN presence identifies a possible service target but not ticket forgery by itself.",
            source=node.id,
            target=node.id,
            relationship="HasSPN",
            primitive_obj=primitive_obj,
            result=f"Silver Ticket precondition check for {node.name}",
            status="incomplete",
            confidence=0.35,
            missing_information=[
                missing(
                    "Is the service account key or NT hash compromised?",
                    node.name,
                    "Silver Ticket requires service key compromise; SPN alone is insufficient.",
                    MissingSource.HOST,
                    MissingImportance.HIGH,
                )
            ],
            graph=graph,
            evidence={"spns": spns},
        )

    def _golden_ticket(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "GoldenTicketCandidate",
            "Kerberos",
            ["DCSync"],
            target_type=str(target.type) if target else "*",
            result="KRBTGTKeyCompromiseCandidate",
            confidence=0.7,
            preconditions=["DCSync or KRBTGT key material available"],
        )
        return finding(
            name=f"GoldenTicketCandidate: {edge.source} -> {edge.target}",
            description="DCSync-style control can expose KRBTGT material for Golden Ticket analysis.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result="Golden Ticket candidate if KRBTGT material is obtained",
            status="candidate",
            confidence=0.7,
            missing_information=[
                missing(
                    "Was KRBTGT key material actually obtained?",
                    target.name if target else edge.target,
                    "DCSync capability must be exercised and scoped to KRBTGT secrets.",
                    MissingSource.HOST,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
        )
