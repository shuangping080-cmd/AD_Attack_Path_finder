"""Phase 2 relationship semantic analysis tests."""

from adpath.detectors.acl import ACLDetector
from adpath.detectors.privilege import PrivilegeDetector
from adpath.graph import ADGraph
from adpath.knowledge.primitives import PrimitiveCatalog
from adpath.models.edge import Edge
from adpath.models.node import Node, NodeType
from adpath.models.privilege import PrivilegeLevel
from adpath.pathfinder.path_explainer import PathExplainer
from adpath.pathfinder.privilege_path import PrivilegePathFinder


def phase2_graph() -> ADGraph:
    """Build the golden Phase 2 test chain."""
    nodes = [
        Node(id="u-1", name="alice", type=NodeType.USER),
        Node(id="svc-1", name="svc_backup", type=NodeType.USER, properties={"hasspn": True}),
        Node(
            id="g-1",
            name="Backup Operators@example.local",
            type=NodeType.GROUP,
            properties={"highvalue": True},
        ),
        Node(id="c-1", name="SRV01", type=NodeType.COMPUTER),
    ]
    edges = [
        Edge(source="u-1", target="svc-1", relationship="GenericWrite"),
        Edge(source="svc-1", target="g-1", relationship="MemberOf"),
        Edge(source="g-1", target="c-1", relationship="AdminTo"),
    ]
    return ADGraph(nodes, edges)


def test_acl_detector_maps_edges_to_findings_and_missing_information() -> None:
    graph = phase2_graph()

    findings = ACLDetector().detect_graph(graph)
    generic_write = next(item for item in findings if item.relationship == "GenericWrite")

    assert generic_write.primitive is not None
    assert generic_write.primitive.name == "GenericWriteToServiceAccount"
    assert generic_write.result == "ServiceAccountControlCandidate on svc_backup"
    assert any(item.question == "Does this identity have active sessions?" for item in generic_write.missing_information)
    assert all(item.suggested_source for item in generic_write.missing_information)


def test_privilege_detector_identifies_level_transitions() -> None:
    graph = phase2_graph()

    transitions = PrivilegeDetector().transitions(graph)
    by_relationship = {transition.relationship: transition for transition in transitions}

    assert by_relationship["GenericWrite"].to_level == PrivilegeLevel.SERVICE_ACCOUNT
    assert by_relationship["MemberOf"].to_level == PrivilegeLevel.PRIVILEGED_GROUP
    assert by_relationship["AdminTo"].to_level == PrivilegeLevel.LOCAL_PRIVILEGE
    assert by_relationship["MemberOf"].boundary.crosses


def test_privilege_path_finder_returns_complete_golden_path() -> None:
    graph = phase2_graph()

    paths = PrivilegePathFinder().find("alice", graph.nodes, graph.edges, max_depth=3)

    assert paths
    best = next(path for path in paths if path.target == "c-1")
    assert [edge.relationship for edge in best.edges] == [
        "GenericWrite",
        "MemberOf",
        "AdminTo",
    ]
    assert best.score > 0
    assert str(best.path_type) == "Incomplete Path"


def test_write_dacl_write_owner_and_force_change_password_findings() -> None:
    graph = ADGraph(
        [
            Node(id="u-1", name="alice", type=NodeType.USER),
            Node(id="u-2", name="bob", type=NodeType.USER),
            Node(id="g-1", name="Helpdesk", type=NodeType.GROUP),
        ],
        [
            Edge(source="u-1", target="u-2", relationship="WriteDACL"),
            Edge(source="u-1", target="g-1", relationship="WriteOwner"),
            Edge(source="g-1", target="u-2", relationship="ForceChangePassword"),
        ],
    )

    findings = ACLDetector().detect_graph(graph)
    by_relationship = {item.relationship: item for item in findings}

    assert by_relationship["WriteDACL"].primitive.name == "WriteDACLControl"
    assert by_relationship["WriteOwner"].primitive.name == "OwnershipTakeover"
    assert by_relationship["ForceChangePassword"].primitive.name == "PasswordReset"
    assert any(
        item.question == "What privileges does the target identity have?"
        for item in by_relationship["ForceChangePassword"].missing_information
    )


def test_primitive_catalog_loads_yaml_and_matches_relationships() -> None:
    catalog = PrimitiveCatalog.load()

    names = catalog.names()

    assert "GenericWriteToUser" in names
    assert "GroupMembership" in names
    assert "OwnershipTakeover" in names
    assert catalog.by_relationship("AdminTo")[0].name == "LocalAdmin"


def test_generic_write_uses_target_type_specific_primitives() -> None:
    graph = ADGraph(
        [
            Node(id="u-1", name="alice", type=NodeType.USER),
            Node(id="u-2", name="bob", type=NodeType.USER),
            Node(id="g-1", name="devs", type=NodeType.GROUP),
            Node(id="c-1", name="WS01", type=NodeType.COMPUTER),
        ],
        [
            Edge(source="u-1", target="u-2", relationship="GenericWrite"),
            Edge(source="u-1", target="g-1", relationship="GenericWrite"),
            Edge(source="u-1", target="c-1", relationship="GenericWrite"),
        ],
    )

    findings = ACLDetector().detect_graph(graph)
    by_target: dict[str, list[str]] = {}
    for finding in findings:
        if finding.relationship == "GenericWrite":
            by_target.setdefault(finding.target, []).append(finding.primitive.name)

    assert by_target["u-2"][0] == "GenericWriteToUser"
    assert by_target["g-1"][0] == "GenericWriteToGroup"
    assert by_target["c-1"][0] == "GenericWriteToComputer"


def test_ordinary_memberof_does_not_create_fake_privilege_gain() -> None:
    graph = ADGraph(
        [
            Node(id="u-1", name="alice", type=NodeType.USER),
            Node(id="g-1", name="Developers", type=NodeType.GROUP),
        ],
        [Edge(source="u-1", target="g-1", relationship="MemberOf")],
    )

    transition = PrivilegeDetector().transitions(graph)[0]

    assert transition.gain == 0
    assert not transition.key_edge
    assert transition.to_level == PrivilegeLevel.NORMAL_USER


def test_privilege_path_handles_cycles_duplicates_top_n_and_high_value_only() -> None:
    graph = ADGraph(
        [
            Node(id="u-1", name="alice", type=NodeType.USER),
            Node(id="g-1", name="Developers", type=NodeType.GROUP),
            Node(id="g-2", name="Account Operators", type=NodeType.GROUP, properties={"highvalue": True}),
            Node(id="c-1", name="SRV01", type=NodeType.COMPUTER),
        ],
        [
            Edge(source="u-1", target="g-1", relationship="MemberOf"),
            Edge(source="g-1", target="u-1", relationship="MemberOf"),
            Edge(source="u-1", target="g-2", relationship="MemberOf"),
            Edge(source="g-2", target="c-1", relationship="AdminTo"),
            Edge(source="u-1", target="g-2", relationship="MemberOf"),
        ],
    )

    paths = PrivilegePathFinder().find("alice", graph.nodes, graph.edges, max_depth=4, high_value_only=True, top_n=1)

    assert len(paths) == 1
    assert paths[0].target == "g-2"
    assert [edge.target for edge in paths[0].edges] == ["g-2"]


def test_path_explainer_describes_missing_information() -> None:
    graph = phase2_graph()
    path = next(path for path in PrivilegePathFinder().find("alice", graph.nodes, graph.edges, max_depth=3) if path.target == "c-1")

    explanation = PathExplainer().explain(path)

    assert "alice" in explanation
    assert "GenericWrite" in explanation
    assert "Missing information" in explanation
