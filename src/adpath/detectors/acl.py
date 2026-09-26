"""ACL and relationship semantic detector."""

from adpath.detectors.base import BaseDetector, Finding
from adpath.graph import ADGraph
from adpath.knowledge.preconditions import PreconditionEvaluator
from adpath.knowledge.primitives import PrimitiveCatalog
from adpath.knowledge.relationships import RelationshipCatalog
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingInformation, MissingSource
from adpath.models.node import Node
from adpath.models.primitive import AttackPrimitive

SUPPORTED_RELATIONSHIPS = {
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "ForceChangePassword",
    "MemberOf",
    "AdminTo",
    "WriteSPN",
    "CreateChild",
}

FALLBACK_PRIMITIVES = {
    "GenericAll": "FullObjectControl",
    "GenericWrite": "GenericWriteCandidate",
    "WriteDACL": "PermissionEscalationCandidate",
    "WriteOwner": "OwnershipTakeover",
    "ForceChangePassword": "CredentialControl",
    "MemberOf": "GroupMembership",
    "AdminTo": "HostAdministrativeAccess",
    "WriteSPN": "SPNManipulation",
    "CreateChild": "OUChildCreationCandidate",
}

PREFERRED_PRIMITIVE_BY_RELATIONSHIP = {
    "GenericAll": "GenericAllControl",
    "GenericWrite": "GenericWriteToUser",
    "WriteDACL": "WriteDACLControl",
    "WriteOwner": "OwnershipTakeover",
    "ForceChangePassword": "PasswordReset",
    "MemberOf": "GroupMembership",
    "AdminTo": "LocalAdmin",
    "WriteSPN": "SPNManipulation",
    "CreateChild": "BadSuccessor",
}

GENERIC_WRITE_BY_TARGET_TYPE = {
    "User": ("GenericWriteToUser", "IdentityControlCandidate"),
    "Group": ("GenericWriteToGroup", "GroupModificationCandidate"),
    "Computer": ("GenericWriteToComputer", "ComputerControlCandidate"),
    "ServiceAccount": ("GenericWriteToServiceAccount", "ServiceAccountControlCandidate"),
}


class ACLDetector(BaseDetector):
    """Detect ACL-derived relationship candidates."""

    name = "acl"

    def __init__(
        self,
        primitive_catalog: PrimitiveCatalog | None = None,
        relationship_catalog: RelationshipCatalog | None = None,
        precondition_evaluator: PreconditionEvaluator | None = None,
    ) -> None:
        self.primitive_catalog = primitive_catalog or PrimitiveCatalog.load()
        self.relationship_catalog = relationship_catalog or RelationshipCatalog.load()
        self.precondition_evaluator = precondition_evaluator or PreconditionEvaluator()

    def detect(self, nodes: list[Node], edges: list[Edge]) -> list[Finding]:
        """Return ACL findings."""
        return self.detect_graph(ADGraph(nodes, edges))

    def detect_graph(self, graph: ADGraph) -> list[Finding]:
        """Return semantic findings for supported relationships."""
        findings: list[Finding] = []
        for edge in graph.edges:
            if edge.relationship not in SUPPORTED_RELATIONSHIPS:
                continue
            source = graph.get_node(edge.source)
            target = graph.get_node(edge.target)
            missing = self._missing_information(edge, target, graph)
            for primitive in self._match_primitives(edge, source, target):
                preconditions = self.precondition_evaluator.evaluate(primitive, edge, source, target, graph)
                primitive_missing = [*missing, *preconditions.missing_information]
                findings.append(
                    Finding(
                        name=f"{edge.relationship}: {source.name if source else edge.source} -> {target.name if target else edge.target}",
                        description=self._description(edge, source, target),
                        source=edge.source,
                        target=edge.target,
                        relationship=edge.relationship,
                        primitive=primitive,
                        result=self._result(edge, target, primitive),
                        status=self._status(edge, primitive, primitive_missing, preconditions.status),
                        confidence=self._confidence(edge, target, primitive, primitive_missing, preconditions.confidence_adjustment),
                        missing_information=primitive_missing,
                        evidence={
                            "edge": edge.to_dict(),
                            "source_name": source.name if source else None,
                            "target_name": target.name if target else None,
                            "source_type": str(source.type) if source else None,
                            "target_type": str(target.type) if target else None,
                            "relationship_definition": self._relationship_evidence(edge.relationship),
                            "historical_examples": primitive.observed_examples,
                        },
                    )
                )
        return findings

    def _match_primitives(self, edge: Edge, source: Node | None, target: Node | None) -> list[AttackPrimitive]:
        candidates = self.primitive_catalog.candidates_for(edge, source, target)
        mapped_names = self.relationship_catalog.primitives_for(edge.relationship)
        if mapped_names:
            candidates = [candidate for candidate in candidates if candidate.name in mapped_names] or candidates
        preferred = PREFERRED_PRIMITIVE_BY_RELATIONSHIP.get(edge.relationship)
        if edge.relationship == "GenericWrite":
            return [self._generic_write_primitive(edge, target), *self._non_duplicate(candidates, preferred)]
        preferred_candidates = [candidate for candidate in candidates if candidate.name == preferred]
        if preferred_candidates:
            return [*preferred_candidates, *self._non_duplicate(candidates, preferred)]
        if candidates:
            return candidates
        return [self._fallback_primitive(edge, source, target)]

    def _non_duplicate(self, candidates: list[AttackPrimitive], preferred: str | None) -> list[AttackPrimitive]:
        return [candidate for candidate in candidates if candidate.name != preferred]

    def _generic_write_primitive(self, edge: Edge, target: Node | None) -> AttackPrimitive:
        target_type = self._semantic_target_type(target)
        name, result = GENERIC_WRITE_BY_TARGET_TYPE.get(target_type, ("GenericWriteCandidate", "ObjectModificationCandidate"))
        return AttackPrimitive(
            name=name,
            category="ACL",
            source_type="*",
            target_type=target_type,
            required_relationships=[edge.relationship],
            result=result,
            confidence=0.75,
            description=f"GenericWrite over {target_type} object requires object-specific interpretation.",
        )

    def _fallback_primitive(self, edge: Edge, source: Node | None, target: Node | None) -> AttackPrimitive:
        return AttackPrimitive(
            name=FALLBACK_PRIMITIVES.get(edge.relationship, f"{edge.relationship}Candidate"),
            category="Relationship",
            source_type=str(source.type) if source else "*",
            target_type=str(target.type) if target else "*",
            required_relationships=[edge.relationship],
            result=self._result(edge, target),
            confidence=0.7,
            description=self._description(edge, source, target),
        )

    def _semantic_target_type(self, target: Node | None) -> str:
        if target is None:
            return "*"
        if str(target.type) == "User" and (target.properties.get("hasspn") or target.properties.get("serviceprincipalnames")):
            return "ServiceAccount"
        return str(target.type)

    def _description(self, edge: Edge, source: Node | None, target: Node | None) -> str:
        source_name = source.name if source else edge.source
        target_name = target.name if target else edge.target
        return f"{source_name} has {edge.relationship} relationship to {target_name}."

    def _result(self, edge: Edge, target: Node | None, primitive: AttackPrimitive | None = None) -> str:
        target_name = target.name if target else edge.target
        if primitive and primitive.result:
            return f"{primitive.result} on {target_name}"
        if edge.relationship in {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner"}:
            return f"Possible control path over {target_name}"
        if edge.relationship == "WriteSPN":
            return f"Possible SPN manipulation against {target_name}"
        if edge.relationship == "CreateChild":
            return f"Possible child-object creation under {target_name}"
        if edge.relationship == "ForceChangePassword":
            return f"Possible credential control of {target_name}"
        if edge.relationship == "MemberOf":
            return f"Principal may inherit privileges from {target_name}"
        if edge.relationship == "AdminTo":
            return f"Possible local administrative access to {target_name}"
        return f"Potential privilege-relevant relationship to {target_name}"

    def _status(
        self,
        edge: Edge,
        primitive: AttackPrimitive,
        missing: list[MissingInformation],
        precondition_status: str,
    ) -> str:
        if edge.relationship == "WriteSPN" and primitive.name == "SPNManipulation":
            return "confirmed"
        if edge.relationship == "WriteSPN" and primitive.name == "TargetedKerberoast":
            return "candidate"
        if edge.relationship == "CreateChild":
            return "incomplete"
        if edge.relationship == "GenericWrite" and primitive.name in {"SPNManipulation", "TargetedKerberoast"}:
            return "incomplete"
        if edge.relationship in {"WriteDACL", "WriteOwner"}:
            return "candidate"
        if missing:
            return precondition_status if precondition_status != "confirmed" else "candidate"
        return "confirmed"

    def _confidence(
        self,
        edge: Edge,
        target: Node | None,
        primitive: AttackPrimitive,
        missing: list[MissingInformation],
        adjustment: float = 0.0,
    ) -> float:
        confidence = primitive.confidence + adjustment
        if edge.relationship == "WriteSPN":
            confidence = max(confidence, 0.85 if primitive.name == "SPNManipulation" else 0.75)
        if edge.relationship == "CreateChild":
            confidence = max(confidence, 0.6)
        if edge.relationship in {"WriteDACL", "WriteOwner"}:
            confidence *= 0.7
        if edge.relationship == "MemberOf" and target and not target.properties.get("highvalue"):
            confidence *= 0.5
        if missing:
            confidence -= min(0.3, len(missing) * 0.05)
        return max(0.1, round(confidence, 2))

    def _relationship_evidence(self, relationship: str) -> dict[str, object] | None:
        definition = self.relationship_catalog.get(relationship)
        if definition is None:
            return None
        return {
            "name": definition.name,
            "maps_to_primitives": definition.maps_to_primitives,
            "extra_conditions": definition.extra_conditions,
        }

    def _missing_information(self, edge: Edge, target: Node | None, graph: ADGraph) -> list[MissingInformation]:
        missing: list[MissingInformation] = []
        target_type = str(target.type) if target else ""
        target_props = target.properties if target else {}
        target_name = target.name if target else edge.target
        if edge.relationship == "GenericWrite" and target_type in {"User", "ServiceAccount"}:
            if not target_props.get("hasspn") and not target_props.get("serviceprincipalnames"):
                missing.append(self._missing("Does the account have an SPN?", target_name, "Kerberoast/SPN manipulation depends on SPN state.", MissingSource.LDAP))
            missing.extend([
                self._missing("Does this identity have active sessions?", target_name, "Session location affects credential exposure follow-up.", MissingSource.BLOODHOUND),
                self._missing("Is this identity in privileged groups?", target_name, "Group membership determines downstream privilege.", MissingSource.LDAP, MissingImportance.HIGH),
                self._missing("Does this identity control other objects?", target_name, "Downstream control edges determine path continuation.", MissingSource.BLOODHOUND),
            ])
        elif edge.relationship == "WriteSPN":
            missing.append(
                self._missing(
                    "Can the resulting service ticket hash be cracked?",
                    target_name,
                    "WriteSPN gives SPN manipulation evidence, but credential recovery still depends on cracking.",
                    MissingSource.HOST,
                )
            )
        elif edge.relationship == "CreateChild":
            missing.extend(
                [
                    self._missing(
                        "Which child object classes can be created?",
                        target_name,
                        "BadSuccessor depends on the ability to create or modify dMSA-related objects.",
                        MissingSource.LDAP,
                        MissingImportance.HIGH,
                    ),
                    self._missing(
                        "What predecessor/successor relationship is present?",
                        target_name,
                        "CreateChild is only a prerequisite; successor linkage is still required.",
                        MissingSource.LDAP,
                        MissingImportance.HIGH,
                    ),
                ]
            )
        elif edge.relationship == "GenericWrite" and target_type == "Group":
            missing.extend([
                self._missing("Can membership or group attributes be modified effectively?", target_name, "GenericWrite on groups is object-specific.", MissingSource.LDAP, MissingImportance.HIGH),
                self._missing("What privileges does this group grant?", target_name, "Ordinary groups should not be treated as privilege gain.", MissingSource.BLOODHOUND),
            ])
        elif edge.relationship == "GenericWrite" and target_type == "Computer":
            missing.extend([
                self._missing("Which computer attributes are writable?", target_name, "Computer control depends on writable attribute set.", MissingSource.LDAP),
                self._missing("Are there sessions or credentials on the host?", target_name, "Host impact depends on credential exposure.", MissingSource.HOST, MissingImportance.HIGH),
            ])
        elif edge.relationship in {"GenericAll", "WriteDACL", "WriteOwner"}:
            missing.extend([
                self._missing("Is the effective ACL exploitable?", target_name, "Inherited/protected ACLs may change practical impact.", MissingSource.LDAP, MissingImportance.HIGH),
                self._missing("What follow-on permission would be granted?", target_name, "WriteDACL/WriteOwner are enabling relationships, not full control by themselves.", MissingSource.LDAP),
                self._missing("What downstream control edges become possible?", target_name, "Path continuation requires additional graph facts.", MissingSource.BLOODHOUND),
            ])
        elif edge.relationship == "ForceChangePassword":
            missing.extend([
                self._missing("What privileges does the target identity have?", target_name, "Password reset is useful only through downstream privileges.", MissingSource.BLOODHOUND, MissingImportance.HIGH),
                self._missing("Are password reset constraints present?", target_name, "Operational constraints can block credential control.", MissingSource.LDAP),
            ])
        elif edge.relationship == "MemberOf":
            if not target_props.get("highvalue"):
                missing.append(self._missing("What privilege tier is this group?", target_name, "Ordinary group membership is not automatically privilege gain.", MissingSource.BLOODHOUND))
            if not graph.out_edges(edge.target):
                missing.append(self._missing("Does this group have nested or admin relationships?", target_name, "Nested group paths may continue privilege inheritance.", MissingSource.BLOODHOUND))
        elif edge.relationship == "AdminTo":
            missing.extend([
                self._missing("Who has sessions on this host?", target_name, "AdminTo is local privilege; domain impact depends on sessions.", MissingSource.BLOODHOUND, MissingImportance.HIGH),
                self._missing("Are domain credentials stored on this host?", target_name, "Stored credentials can turn local admin into domain exposure.", MissingSource.HOST, MissingImportance.HIGH),
                self._missing("Which services are reachable?", target_name, "Service reachability affects practical use of local admin.", MissingSource.SMB),
            ])
        return missing

    def _missing(
        self,
        question: str,
        object_name: str,
        reason: str,
        source: MissingSource,
        importance: MissingImportance = MissingImportance.MEDIUM,
    ) -> MissingInformation:
        return MissingInformation(
            question=question,
            object=object_name,
            reason=reason,
            suggested_source=source,
            importance=importance,
        )
