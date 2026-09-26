"""Smoke tests for package imports."""

from adpath.models import AttackPath, AttackPrimitive, Edge, Node, NodeType


def test_core_model_imports() -> None:
    """Core models can be imported and instantiated."""
    node = Node(id="u-1", name="alice", type=NodeType.USER, domain="example.local")
    edge = Edge(source="u-1", target="g-1", relationship="MemberOf")
    primitive = AttackPrimitive(
        name="MembershipControlCandidate",
        source_type="User",
        target_type="Group",
    )
    path = AttackPath(
        start=node.id,
        target="g-1",
        nodes=[node],
        edges=[edge],
        primitives=[primitive],
    )

    assert path.start == "u-1"
    assert path.edges[0].relationship == "MemberOf"
