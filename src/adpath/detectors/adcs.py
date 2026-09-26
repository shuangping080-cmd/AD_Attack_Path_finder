"""AD CS primitive detector."""

from typing import Any

from adpath.detectors.base import BaseDetector, Finding
from adpath.detectors.common import finding, missing, primitive, prop_bool, prop_list, prop_text
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingSource
from adpath.models.node import Node


class ADCSDetector(BaseDetector):
    """Detect AD CS enrollment, template, CA, and mapping-risk candidates."""

    name = "adcs"

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return AD CS findings."""
        graph = ADGraph(nodes, edges)
        findings: list[Finding] = []
        for edge in graph.edges:
            if edge.relationship in {"Enroll", "AutoEnroll"}:
                findings.append(self._enrollment(graph, edge))
            elif edge.relationship == "TemplateControl":
                findings.append(self._esc4(graph, edge))
            elif edge.relationship == "ManageCA":
                findings.append(self._esc7(graph, edge))
            elif edge.relationship == "ManageCertificates":
                findings.append(self._manage_certificates(graph, edge))
        for node in graph.nodes:
            if str(node.type) in {"CertificateTemplate", "CA", "CertificateAuthority"}:
                findings.extend(self._object_findings(graph, node))
        return findings

    def _enrollment(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        vulnerable = bool(target and self._template_vulnerabilities(target.properties))
        primitive_obj = primitive(
            "CertificateEnrollment",
            "ADCS",
            [edge.relationship],
            target_type=str(target.type) if target else "CertificateTemplate",
            result="CertificateEnrollmentCapability",
            confidence=0.8 if vulnerable else 0.55,
        )
        return finding(
            name=f"{edge.relationship}: {edge.source} -> {edge.target}",
            description="A principal can enroll in a certificate template.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"{edge.relationship} capability for {target.name if target else edge.target}",
            status="candidate",
            confidence=0.8 if vulnerable else 0.55,
            missing_information=[
                missing(
                    "Is this template vulnerable or only enrollable?",
                    target.name if target else edge.target,
                    "Enrollment by itself is not an AD CS escalation primitive.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
            evidence={"template_vulnerabilities": self._template_vulnerabilities(target.properties) if target else []},
        )

    def _esc4(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "ESC4",
            "ADCS",
            ["TemplateControl"],
            target_type="CertificateTemplate",
            result="TemplateModificationCandidate",
            confidence=0.8,
            preconditions=["Writable certificate template"],
        )
        return finding(
            name=f"ESC4: {edge.source} -> {edge.target}",
            description="A principal can modify a certificate template.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"ESC4 template control candidate on {target.name if target else edge.target}",
            status="candidate",
            confidence=0.8,
            missing_information=[
                missing(
                    "Which template settings can be changed effectively?",
                    target.name if target else edge.target,
                    "Template control must be translated into a vulnerable issuance path.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
        )

    def _esc7(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "ESC7",
            "ADCS",
            ["ManageCA"],
            target_type="CA",
            result="CertificateAuthorityControlCandidate",
            confidence=0.75,
            preconditions=["ManageCA or equivalent CA rights"],
        )
        return finding(
            name=f"ESC7: {edge.source} -> {edge.target}",
            description="A principal can manage certificate authority configuration.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"ESC7 CA control candidate on {target.name if target else edge.target}",
            status="candidate",
            confidence=0.75,
            missing_information=[
                missing(
                    "Can dangerous CA settings or officer rights be modified?",
                    target.name if target else edge.target,
                    "ManageCA impact depends on effective CA permissions and config.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                )
            ],
            edge=edge,
            graph=graph,
        )

    def _manage_certificates(self, graph: ADGraph, edge: Edge) -> Finding:
        target = graph.get_node(edge.target)
        primitive_obj = primitive(
            "ManageCertificates",
            "ADCS",
            ["ManageCertificates"],
            target_type="CA",
            result="CertificateApprovalCandidate",
            confidence=0.65,
        )
        return finding(
            name=f"ManageCertificates: {edge.source} -> {edge.target}",
            description="A principal can manage certificate requests on a CA.",
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            primitive_obj=primitive_obj,
            result=f"Certificate approval candidate on {target.name if target else edge.target}",
            status="candidate",
            confidence=0.65,
            missing_information=[
                missing(
                    "Are manager approval or pending request flows exploitable?",
                    target.name if target else edge.target,
                    "Certificate management rights need request/template context.",
                    MissingSource.LDAP,
                )
            ],
            edge=edge,
            graph=graph,
        )

    def _object_findings(self, graph: ADGraph, node: Node) -> list[Finding]:
        if str(node.type) in {"CA", "CertificateAuthority"}:
            return self._ca_findings(graph, node)
        return [self._esc_finding(graph, node, esc) for esc in self._template_vulnerabilities(node.properties)]

    def _ca_findings(self, graph: ADGraph, node: Node) -> list[Finding]:
        findings: list[Finding] = []
        for esc, flag, label in (
            ("ESC6", "user_specified_san_enabled", "CA allows user-specified SAN behavior"),
            ("ESC8", "web_enrollment_enabled", "CA exposes web enrollment surface"),
            ("ESC11", "rpc_enrollment_no_signing", "CA RPC enrollment signing is weak"),
        ):
            if prop_bool(node.properties, flag, flag.replace("_", "")):
                findings.append(self._esc_finding(graph, node, esc, description=label))
        return findings

    def _template_vulnerabilities(self, properties: dict[str, Any]) -> list[str]:
        vulnerabilities: list[str] = []
        ekus = " ".join(str(item).casefold() for item in prop_list(properties, "eku", "EKU", "ekus"))
        enrollee_supplies_subject = prop_bool(
            properties,
            "enrollee_supplies_subject",
            "EnrolleeSuppliesSubject",
            "subjectaltrequireupn",
        )
        client_auth = "client" in ekus or "smartcard" in ekus or "any purpose" in ekus
        if enrollee_supplies_subject and client_auth:
            vulnerabilities.append("ESC1")
        if prop_bool(properties, "no_security_extension", "NoSecurityExtension"):
            vulnerabilities.append("ESC9")
        if prop_bool(properties, "schema_v1", "SchemaV1", "ct_flag_no_security_extension"):
            vulnerabilities.append("ESC15")
        if prop_bool(properties, "esc4", "ESC4", "template_writable"):
            vulnerabilities.append("ESC4")
        return vulnerabilities

    def _esc_finding(
        self,
        graph: ADGraph,
        node: Node,
        esc: str,
        description: str | None = None,
    ) -> Finding:
        primitive_obj = primitive(
            esc,
            "ADCS",
            [],
            target_type=str(node.type),
            result=f"{esc}Candidate",
            confidence=0.75,
            preconditions=["Template/CA settings support this ESC condition"],
        )
        object_label = prop_text(node.properties, "displayname", "name") or node.name
        return finding(
            name=f"{esc}: {node.name}",
            description=description or f"{object_label} has settings associated with {esc}.",
            source=node.id,
            target=node.id,
            relationship=esc,
            primitive_obj=primitive_obj,
            result=f"{esc} candidate on {node.name}",
            status="candidate",
            confidence=0.75,
            missing_information=[
                missing(
                    "Who can enroll or exercise this AD CS condition?",
                    node.name,
                    "AD CS vulnerability requires rights and CA issuance context.",
                    MissingSource.LDAP,
                    MissingImportance.HIGH,
                )
            ],
            graph=graph,
            evidence={"properties": node.properties},
        )
