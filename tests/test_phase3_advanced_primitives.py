"""Phase 3 advanced primitive detector tests."""

from pathlib import Path

from adpath.cli import _semantic_edges
from adpath.detectors.acl import ACLDetector
from adpath.detectors.adcs import ADCSDetector
from adpath.detectors.delegation import DelegationDetector
from adpath.detectors.dmsa import DMSADetector
from adpath.detectors.gmsa import GMSADetector
from adpath.detectors.gpo import GPODetector
from adpath.detectors.kerberos import KerberosDetector
from adpath.detectors.ou import OUDetector
from adpath.graph import ADGraph
from adpath.knowledge.correlation import KnowledgeCorrelator
from adpath.knowledge.relationships import RelationshipCatalog
from adpath.models.edge import Edge
from adpath.models.node import Node, NodeType
from adpath.parsers.bloodhound_parser import BloodHoundParser
from adpath.pathfinder.privilege_path import PrivilegePathFinder


def names(findings):
    """Return primitive names from findings."""
    return {item.primitive.name for item in findings if item.primitive}


def write_minimal_reviewed_kb(root: Path) -> Path:
    """Create public-safe reviewed fixtures without relying on real writeups."""
    reviewed = root / "htb" / "reviewed"
    reviewed.mkdir(parents=True)
    (reviewed / "Eighteen.yaml").write_text(
        """
machine:
  name: Eighteen
entities:
  - id: adam
    name: ADAM.SCOTT
    type: User
    aliases: [ADAM.SCOTT@EIGHTEEN.HTB]
  - id: staff
    name: STAFF
    type: OU
relationships:
  - source: ADAM.SCOTT
    relation: CreateChild
    target: STAFF
    evidence:
      description: Synthetic reviewed fixture for BadSuccessor correlation tests.
attack_primitives:
  - name: BadSuccessor
    source: ADAM.SCOTT
    target: STAFF
    result: DMSACandidate
    candidate: true
    evidence:
      description: Synthetic reviewed fixture.
attack_chain:
  - order: 1
    source: ADAM.SCOTT
    target: STAFF
    relationship: CreateChild
    primitive: BadSuccessor
    result: DMSACandidate
    evidence:
      description: Synthetic reviewed fixture.
confidence: high
review_status: reviewed
""".strip(),
        encoding="utf-8",
    )
    return root


def test_targeted_kerberoast_requires_service_account_context() -> None:
    graph = ADGraph(
        [
            Node(id="u1", name="alice", type=NodeType.USER),
            Node(
                id="svc1",
                name="svc_sql",
                type=NodeType.SERVICE_ACCOUNT,
                properties={"serviceprincipalnames": ["MSSQLSvc/sql01"]},
            ),
        ],
        [Edge(source="u1", target="svc1", relationship="GenericWrite")],
    )

    findings = KerberosDetector().detect_graph(graph)

    assert "TargetedKerberoast" in names(findings)
    assert next(item for item in findings if item.primitive.name == "SilverTicketCandidate").status == "incomplete"


def test_delegation_detector_finds_rbcd_and_constrained_delegation() -> None:
    graph = ADGraph(
        [
            Node(id="c1", name="FAKE01", type=NodeType.COMPUTER),
            Node(id="c2", name="WEB01", type=NodeType.COMPUTER),
            Node(id="svc1", name="svc_web", type=NodeType.SERVICE_ACCOUNT),
        ],
        [
            Edge(source="c1", target="c2", relationship="AllowedToAct"),
            Edge(source="svc1", target="c2", relationship="AllowedToDelegate"),
        ],
    )

    findings = DelegationDetector().detect_graph(graph)

    assert {"RBCD", "S4U"} <= names(findings)


def test_gmsa_password_read_and_downstream_impact() -> None:
    graph = ADGraph(
        [
            Node(id="u1", name="alice", type=NodeType.USER),
            Node(id="gmsa1", name="svc_web$", type=NodeType.GMSA),
            Node(id="c1", name="WEB01", type=NodeType.COMPUTER),
        ],
        [
            Edge(source="u1", target="gmsa1", relationship="ReadGMSAPassword"),
            Edge(source="gmsa1", target="c1", relationship="AdminTo"),
        ],
    )

    findings = GMSADetector().detect_graph(graph)

    assert {"ReadGMSAPassword", "GMSAImpact"} <= names(findings)


def test_bad_successor_is_incomplete_not_confirmed_from_ou_write() -> None:
    graph = ADGraph(
        [
            Node(id="u1", name="alice", type=NodeType.USER),
            Node(id="ou1", name="Tier1 Servers", type=NodeType.OU),
        ],
        [Edge(source="u1", target="ou1", relationship="GenericAll")],
    )

    finding = next(item for item in DMSADetector().detect_graph(graph) if item.primitive.name == "BadSuccessor")

    assert finding.status == "incomplete"
    assert finding.missing_information


def test_adcs_detects_esc4_and_esc9_separately_from_enrollment() -> None:
    graph = ADGraph(
        [
            Node(id="u1", name="alice", type=NodeType.USER),
            Node(
                id="tpl1",
                name="UserAuth",
                type=NodeType.CERTIFICATE_TEMPLATE,
                properties={"no_security_extension": True},
            ),
        ],
        [
            Edge(source="u1", target="tpl1", relationship="TemplateControl"),
            Edge(source="u1", target="tpl1", relationship="Enroll"),
        ],
    )

    findings = ADCSDetector().detect_graph(graph)

    assert {"ESC4", "ESC9", "CertificateEnrollment"} <= names(findings)
    assert next(item for item in findings if item.primitive.name == "CertificateEnrollment").status == "candidate"


def test_ou_control_and_gpo_control_are_candidates() -> None:
    graph = ADGraph(
        [
            Node(id="u1", name="alice", type=NodeType.USER),
            Node(id="ou1", name="Workstations", type=NodeType.OU),
            Node(id="gpo1", name="Workstation Policy", type=NodeType.GPO),
            Node(id="c1", name="WS01", type=NodeType.COMPUTER),
        ],
        [
            Edge(source="u1", target="ou1", relationship="WriteDACL"),
            Edge(source="ou1", target="c1", relationship="Contains"),
            Edge(source="gpo1", target="ou1", relationship="LinkedTo"),
            Edge(source="u1", target="gpo1", relationship="GenericWrite"),
        ],
    )

    ou_finding = next(item for item in OUDetector().detect_graph(graph) if item.primitive.name == "OUControl")
    gpo_finding = next(item for item in GPODetector().detect_graph(graph) if item.primitive.name == "GPOControl")

    assert ou_finding.status == "candidate"
    assert gpo_finding.status == "candidate"


def test_bloodhound_parser_supports_containers_and_phase3_relationships() -> None:
    payload = {
        "meta": {"type": "containers"},
        "data": [
            {
                "ObjectIdentifier": "cont1",
                "Properties": {"name": "CN=Users", "domain": "example.local"},
                "ChildObjects": [{"ObjectIdentifier": "u1", "ObjectType": "User"}],
            }
        ],
    }

    result = BloodHoundParser().parse_payload(payload, "containers.json")

    assert not result.warnings
    assert result.nodes[0].type == NodeType.CONTAINER
    assert result.edges[0].relationship == "Contains"


def test_parser_turns_contained_by_into_contains_edge() -> None:
    payload = {
        "meta": {"type": "users"},
        "data": [
            {
                "ObjectIdentifier": "adam",
                "Properties": {"name": "ADAM.SCOTT@EIGHTEEN.HTB"},
                "ContainedBy": {"ObjectIdentifier": "staff-ou", "ObjectType": "OU"},
            }
        ],
    }

    result = BloodHoundParser().parse_payload(payload, "users.json")

    assert ("STAFF-OU", "Contains", "ADAM") in {
        (edge.source, edge.relationship, edge.target) for edge in result.edges
    }
    assert result.edges[0].properties["source_field"] == "ContainedBy"


def test_createchild_parser_and_badsuccessor_path() -> None:
    payload = {
        "meta": {"type": "ous"},
        "data": [
            {
                "ObjectIdentifier": "staff-ou",
                "Properties": {"name": "STAFF@EIGHTEEN.HTB"},
                "Aces": [
                    {
                        "PrincipalSID": "it-group",
                        "PrincipalType": "Group",
                        "RightName": "CreateChild",
                        "IsInherited": False,
                    }
                ],
            }
        ],
    }

    result = BloodHoundParser().parse_payload(payload, "ous.json")
    graph = ADGraph(
        [
            Node(id="adam", name="ADAM.SCOTT@EIGHTEEN.HTB", type=NodeType.USER),
            Node(id="IT-GROUP", name="IT@EIGHTEEN.HTB", type=NodeType.GROUP),
            *result.nodes,
        ],
        [Edge(source="adam", target="IT-GROUP", relationship="MemberOf"), *result.edges],
    )

    dmsa_finding = next(item for item in DMSADetector().detect_graph(graph) if item.primitive.name == "BadSuccessor")
    paths = PrivilegePathFinder().find("adam", graph.nodes, graph.edges, max_depth=3, top_n=5)

    assert dmsa_finding.relationship == "CreateChild"
    assert dmsa_finding.status == "candidate"
    assert paths
    assert [edge.relationship for edge in paths[0].edges] == ["MemberOf", "CreateChild"]


def test_knowledge_correlator_returns_eighteen_badsuccessor_hint(tmp_path: Path) -> None:
    hints = KnowledgeCorrelator(write_minimal_reviewed_kb(tmp_path)).hints_for_identity("ADAM.SCOTT@EIGHTEEN.HTB")

    assert any(
        hint.machine == "Eighteen"
        and hint.primitive == "BadSuccessor"
        and hint.target == "STAFF"
        and not hint.graph_confirmed
        for hint in hints
    )


def test_writespn_parser_aliases_and_properties() -> None:
    payload = {
        "meta": {"type": "users"},
        "data": [
            {
                "ObjectIdentifier": "alfred",
                "Properties": {"name": "ALFRED@TOMBWATCHER.HTB"},
                "Aces": [
                    {
                        "PrincipalSID": "henry",
                        "RightName": "WriteSpn",
                        "IsInherited": False,
                        "PrincipalType": "User",
                    }
                ],
            }
        ],
    }

    result = BloodHoundParser().parse_payload(payload, "users.json")

    edge = result.edges[0]
    assert edge.relationship == "WriteSPN"
    assert edge.source == "HENRY"
    assert edge.target == "ALFRED"
    assert edge.properties["inherited"] is False
    assert edge.properties["principal_type"] == "User"


def test_writespn_relationship_catalog() -> None:
    relationship = RelationshipCatalog.load().get("WriteSPN")

    assert relationship is not None
    assert relationship.maps_to_primitives == ["SPNManipulation", "TargetedKerberoast"]
    assert "User" in relationship.source_types
    assert "ServiceAccount" in relationship.target_types


def tombwatcher_writespn_graph() -> ADGraph:
    """Build the TombWatcher WriteSPN golden graph."""
    return ADGraph(
        [
            Node(id="henry", name="HENRY@TOMBWATCHER.HTB", type=NodeType.USER),
            Node(id="alfred", name="ALFRED@TOMBWATCHER.HTB", type=NodeType.USER),
        ],
        [Edge(source="henry", target="alfred", relationship="WriteSPN")],
    )


def test_writespn_to_spn_manipulation_and_targeted_kerberoast() -> None:
    graph = tombwatcher_writespn_graph()

    acl_findings = ACLDetector().detect_graph(graph)
    kerberos_findings = KerberosDetector().detect_graph(graph)
    by_name = {item.primitive.name: item for item in [*acl_findings, *kerberos_findings]}

    assert by_name["SPNManipulation"].status == "confirmed"
    assert by_name["TargetedKerberoast"].status == "candidate"
    assert any(
        item.question == "Can the resulting service ticket hash be cracked?"
        for item in by_name["TargetedKerberoast"].missing_information
    )
    assert by_name["SPNManipulation"].evidence["historical_examples"][0]["machine"] == "TombWatcher"


def test_genericwrite_requires_spn_precondition_for_spn_primitives() -> None:
    graph = ADGraph(
        [
            Node(id="henry", name="HENRY@TOMBWATCHER.HTB", type=NodeType.USER),
            Node(id="alfred", name="ALFRED@TOMBWATCHER.HTB", type=NodeType.USER),
        ],
        [Edge(source="henry", target="alfred", relationship="GenericWrite")],
    )

    findings = ACLDetector().detect_graph(graph)
    spn_finding = next(item for item in findings if item.primitive.name == "SPNManipulation")

    assert spn_finding.status == "incomplete"
    assert any(item.question == "Is servicePrincipalName writable?" for item in spn_finding.missing_information)


def test_semantic_edges_do_not_double_score_or_create_self_path_loops() -> None:
    graph = tombwatcher_writespn_graph()
    findings = [*ACLDetector().detect_graph(graph), *KerberosDetector().detect_graph(graph)]
    semantic_edges = _semantic_edges(findings)
    analysis_graph = ADGraph(graph.nodes, [*graph.edges, *semantic_edges])

    paths = PrivilegePathFinder().find("henry", analysis_graph.nodes, analysis_graph.edges, max_depth=3, top_n=10)

    assert paths
    assert all(len(path.nodes) == len({node.id for node in path.nodes}) for path in paths)
    assert all([edge.target for edge in path.edges].count("alfred") == 1 for path in paths)
    assert max(path.score for path in paths) < 10
