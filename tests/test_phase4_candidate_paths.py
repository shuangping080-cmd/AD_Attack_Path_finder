"""Phase 4 candidate path tests."""

from pathlib import Path

from adpath.detectors.dmsa import DMSADetector
from adpath.detectors.gmsa import GMSADetector
from adpath.detectors.kerberos import KerberosDetector
from adpath.graph import ADGraph
from adpath.knowledge.loader import KnowledgeBaseLoader
from adpath.knowledge.matcher import AttackPatternMatcher
from adpath.knowledge.primitives import PrimitiveCatalog
from adpath.models.edge import Edge
from adpath.models.node import Node, NodeType
from adpath.models.path import PathType
from adpath.pathfinder.candidate_path import CandidatePathFinder
from adpath.reports import paths_report


def primitive_catalog():
    """Load the local primitive catalog."""
    return PrimitiveCatalog.load().primitives


def write_candidate_fixture_kb(root: Path) -> Path:
    """Create public-safe reviewed fixtures for candidate-path tests."""
    reviewed = root / "htb" / "reviewed"
    reviewed.mkdir(parents=True)
    records = {
        "Eighteen.yaml": """
machine:
  name: Eighteen
entities:
  - id: adam
    name: ADAM.SCOTT
    type: User
    aliases: [ADAM.SCOTT@EIGHTEEN.HTB]
  - id: it
    name: IT
    type: Group
    aliases: [IT@EIGHTEEN.HTB]
  - id: staff
    name: STAFF
    type: OU
    aliases: [STAFF@EIGHTEEN.HTB]
relationships:
  - source: IT
    relation: CreateChild
    target: STAFF
    evidence:
      description: Synthetic reviewed fixture for candidate continuation tests.
attack_primitives:
  - name: BadSuccessor
    source: IT
    target: STAFF
    result: DMSACandidate
    candidate: true
    evidence:
      description: Synthetic reviewed fixture.
attack_chain:
  - order: 1
    source: ADAM.SCOTT
    target: IT
    relationship: MemberOf
    primitive: GroupMembership
    result: GroupMembership
    evidence:
      description: Synthetic reviewed fixture.
  - order: 2
    source: IT
    target: STAFF
    relationship: CreateChild
    primitive: BadSuccessor
    result: DMSACandidate
    evidence:
      description: Synthetic reviewed fixture.
confidence: high
review_status: reviewed
""",
        "Vintage.yaml": """
machine:
  name: Vintage
entities: []
relationships: []
attack_primitives: []
attack_chain: []
confidence: medium
review_status: reviewed
""",
        "TombWatcher.yaml": """
machine:
  name: TombWatcher
entities: []
relationships: []
attack_primitives: []
attack_chain: []
confidence: medium
review_status: reviewed
""",
    }
    for filename, content in records.items():
        (reviewed / filename).write_text(content.strip(), encoding="utf-8")
    return root


def test_candidate_path_uses_kb_continuation_without_confirming_it(tmp_path: Path) -> None:
    graph = ADGraph(
        [
            Node(id="adam", name="ADAM.SCOTT@EIGHTEEN.HTB", type=NodeType.USER),
            Node(id="it", name="IT@EIGHTEEN.HTB", type=NodeType.GROUP),
            Node(id="staff", name="STAFF@EIGHTEEN.HTB", type=NodeType.OU),
        ],
        [Edge(source="adam", target="it", relationship="MemberOf")],
    )

    paths = CandidatePathFinder(knowledge_base=write_candidate_fixture_kb(tmp_path)).find(
        "adam",
        graph.nodes,
        graph.edges,
        primitive_catalog(),
        max_depth=3,
        top_n=10,
    )
    badsuccessor = next(
        path
        for path in paths
        if [edge.relationship for edge in path.edges] == ["MemberOf", "CreateChild"]
    )

    assert badsuccessor.path_type == PathType.CANDIDATE
    assert badsuccessor.edges[-1].source_tool == "knowledge"
    assert badsuccessor.confirmed_edges[0].relationship == "MemberOf"
    assert badsuccessor.candidate_edges[0].relationship == "CreateChild"
    assert badsuccessor.historical_support[0].machine == "Eighteen"
    assert badsuccessor.evidence["current_graph"][0]["relationship"] == "MemberOf"
    assert badsuccessor.evidence["historical_patterns"][0]["machine"] == "Eighteen"
    assert badsuccessor.evidence["score_breakdown"]["historical_pattern_match"] == 1.0
    assert any("BadSuccessor" in item.question for item in badsuccessor.missing_information)
    assert any(item.blocks_path for item in badsuccessor.missing_information)


def test_genericwrite_candidate_keeps_missing_preconditions() -> None:
    graph = ADGraph(
        [
            Node(id="alice", name="alice", type=NodeType.USER),
            Node(id="svc", name="svc_sql", type=NodeType.SERVICE_ACCOUNT),
        ],
        [Edge(source="alice", target="svc", relationship="GenericWrite")],
    )

    paths = CandidatePathFinder().find("alice", graph.nodes, graph.edges, primitive_catalog())

    incomplete = next(
        path
        for path in paths
        if path.target == "svc"
        and path.path_type == PathType.INCOMPLETE
        and any(primitive.name == "SPNManipulation" for primitive in path.primitives)
    )
    assert any(primitive.name == "SPNManipulation" for primitive in incomplete.primitives)
    assert incomplete.missing_information


def test_gmsa_chain_can_be_returned_as_confirmed_current_graph_path() -> None:
    graph = ADGraph(
        [
            Node(id="alice", name="alice", type=NodeType.USER),
            Node(id="gmsa", name="svc_web$", type=NodeType.GMSA),
            Node(id="web01", name="WEB01", type=NodeType.COMPUTER),
        ],
        [
            Edge(source="alice", target="gmsa", relationship="ReadGMSAPassword"),
            Edge(source="gmsa", target="web01", relationship="AdminTo"),
        ],
    )

    findings = GMSADetector().detect_graph(graph)
    semantic_edges = [
        Edge(
            source=item.source,
            target=item.target,
            relationship=item.primitive.name,
            source_tool="semantic",
            confidence=item.confidence,
            properties={"status": item.status},
        )
        for item in findings
        if item.source and item.target and item.primitive
    ]
    paths = CandidatePathFinder().find("alice", graph.nodes, [*graph.edges, *semantic_edges], primitive_catalog())

    gmsa_path = next(
        path
        for path in paths
        if path.target == "web01"
        and [edge.relationship for edge in path.confirmed_edges] == ["ReadGMSAPassword", "AdminTo"]
    )

    assert all(edge.source_tool != "knowledge" for edge in gmsa_path.edges)
    assert gmsa_path.evidence["current_graph"]
    assert gmsa_path.confirmed_edges


def test_semantic_edges_do_not_enter_confirmed_edges() -> None:
    graph = ADGraph(
        [
            Node(id="henry", name="HENRY@EXAMPLE.LOCAL", type=NodeType.USER),
            Node(id="alfred", name="ALFRED@EXAMPLE.LOCAL", type=NodeType.USER),
        ],
        [
            Edge(source="henry", target="alfred", relationship="TargetedKerberoast", source_tool="semantic"),
        ],
    )

    path = next(
        item
        for item in CandidatePathFinder().find("henry", graph.nodes, graph.edges, primitive_catalog(), top_n=10)
        if any(edge.relationship == "TargetedKerberoast" for edge in item.edges)
    )

    assert all(edge.source_tool != "semantic" for edge in path.confirmed_edges)
    assert path.path_type != PathType.CONFIRMED


def test_createchild_ou_is_badsuccessor_candidate_not_domain_admin() -> None:
    graph = ADGraph(
        [
            Node(id="alice", name="alice", type=NodeType.USER),
            Node(id="ou", name="OU=DMSAHolder", type=NodeType.OU),
        ],
        [Edge(source="alice", target="ou", relationship="CreateChild")],
    )

    finding = next(item for item in DMSADetector().detect_graph(graph) if item.primitive.name == "BadSuccessor")

    assert finding.status == "candidate"
    assert "BadSuccessor" in finding.result
    assert "Domain Admin" not in finding.result


def test_silver_ticket_stays_incomplete_without_service_key() -> None:
    graph = ADGraph(
        [
            Node(
                id="svc",
                name="svc_sql",
                type=NodeType.SERVICE_ACCOUNT,
                properties={"serviceprincipalnames": ["MSSQLSvc/sql01"]},
            ),
            Node(id="sql01", name="SQL01", type=NodeType.COMPUTER),
        ],
        [Edge(source="svc", target="sql01", relationship="HasSPN")],
    )

    finding = next(item for item in KerberosDetector().detect_graph(graph) if item.primitive.name == "SilverTicketCandidate")

    assert finding.status == "incomplete"
    assert any("service account key" in item.question for item in finding.missing_information)


def test_attack_pattern_matcher_uses_ordered_relationship_and_node_types() -> None:
    graph = ADGraph(
        [
            Node(id="alice", name="alice", type=NodeType.USER),
            Node(id="svc", name="svc_sql", type=NodeType.SERVICE_ACCOUNT),
        ],
        [Edge(source="alice", target="svc", relationship="GenericWrite")],
    )

    matches = AttackPatternMatcher().match_graph(graph.nodes, graph.edges, primitives=[], allow_partial=True)
    match = next(item for item in matches if item.pattern_key == "genericwrite-service-account")

    assert [node.type for node in match.matched_nodes] == [NodeType.USER, NodeType.SERVICE_ACCOUNT]
    assert [edge.relationship for edge in match.matched_edges] == ["GenericWrite"]
    assert match.partial
    assert "ServiceAccountHostImpact" in match.missing_primitives
    assert match.to_dict()["missing_steps"] or match.to_dict()["missing_primitives"]


def test_kb_loader_filters_review_status_for_candidate_paths(tmp_path: Path) -> None:
    loader = KnowledgeBaseLoader(write_candidate_fixture_kb(tmp_path))
    machines = loader.load_candidate_machines(include_normalized=True)
    reviewed_only = loader.load_candidate_machines(include_normalized=False)

    assert "Eighteen" in machines
    assert loader.review_status(machines["Eighteen"]) == "reviewed"
    assert "Eighteen" in reviewed_only
    assert "Vintage" in reviewed_only
    assert "TombWatcher" in reviewed_only


def test_kb_loader_loads_pattern_cards_for_llm_knowledge() -> None:
    cards = KnowledgeBaseLoader().pattern_cards()

    assert "vintage-pre2k-computer-password" in cards
    assert "eighteen-ou-createchild-badsuccessor" in cards
    assert "tombwatcher-writespn-targeted-kerberoast" in cards
    assert cards["eighteen-ou-createchild-badsuccessor"]["primitive"] == "BadSuccessor"


def test_candidate_paths_export_grouped_json_report(tmp_path: Path) -> None:
    graph = ADGraph(
        [
            Node(id="adam", name="ADAM.SCOTT@EIGHTEEN.HTB", type=NodeType.USER),
            Node(id="it", name="IT@EIGHTEEN.HTB", type=NodeType.GROUP),
            Node(id="staff", name="STAFF@EIGHTEEN.HTB", type=NodeType.OU),
        ],
        [Edge(source="adam", target="it", relationship="MemberOf")],
    )

    paths = CandidatePathFinder(knowledge_base=write_candidate_fixture_kb(tmp_path)).find(
        "adam",
        graph.nodes,
        graph.edges,
        primitive_catalog(),
        max_depth=3,
        top_n=10,
    )
    report = paths_report(paths)

    assert report["candidate_paths"]
    assert report["missing_information"]
    assert report["historical_support"]
    assert report["candidate_paths"][0]["evidence"]["score_breakdown"]
    assert report["next_best_investigations"]


def test_new_domain_genericwrite_answers_five_candidate_questions_without_identity_reuse() -> None:
    graph = ADGraph(
        [
            Node(id="nova-alice", name="ALICE@NOVA.LOCAL", type=NodeType.USER, domain="NOVA.LOCAL"),
            Node(id="nova-svc", name="SVC_SQL@NOVA.LOCAL", type=NodeType.SERVICE_ACCOUNT, domain="NOVA.LOCAL"),
        ],
        [Edge(source="nova-alice", target="nova-svc", relationship="GenericWrite", source_tool="bloodhound")],
    )

    paths = CandidatePathFinder().find("ALICE@NOVA.LOCAL", graph.nodes, graph.edges, primitive_catalog(), top_n=10)
    report = paths_report(paths)
    pattern_path = next(
        path
        for path in paths
        if path.historical_support and path.historical_support[0].pattern == "genericwrite-service-account"
    )

    assert pattern_path.confirmed_edges[0].relationship == "GenericWrite"
    assert pattern_path.historical_support[0].examples
    assert pattern_path.missing_information
    assert pattern_path.reason
    assert report["next_best_investigations"]
    assert not any("NOVA" in str(example) for example in pattern_path.historical_support[0].examples)
