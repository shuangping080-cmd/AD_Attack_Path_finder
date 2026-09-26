"""Phase 1 graph MVP tests."""

import json
from pathlib import Path

from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.node import Node, NodeType
from adpath.parsers.bloodhound_parser import BloodHoundParser
from adpath.pathfinder.shortest_path import ShortestPathFinder


def test_graph_deduplicates_nodes_and_edges() -> None:
    node = Node(id="U-1", name="alice@example.local", type=NodeType.USER, domain="EXAMPLE.LOCAL")
    edge = Edge(source="U-1", target="G-1", relationship="MemberOf")

    graph = ADGraph([node, node], [edge, edge])

    assert len(graph.nodes) == 1
    assert len(graph.edges) == 1
    assert graph.get_node("U-1") == node
    assert graph.find_nodes_by_name("alice")[0] == node
    assert graph.out_edges("U-1")[0] == edge
    assert graph.in_edges("G-1")[0] == edge
    assert graph.edges_by_relationship("MemberOf")[0] == edge


def test_parser_builds_small_attack_chain() -> None:
    records = [
        {
            "meta_type": "users",
            "ObjectIdentifier": "u-1",
            "Properties": {"name": "alice@example.local", "domain": "example.local"},
            "Aces": [
                {
                    "RightName": "GenericWrite",
                    "PrincipalSID": "u-1",
                    "PrincipalType": "User",
                    "IsInherited": False,
                }
            ],
        },
        {
            "meta_type": "users",
            "ObjectIdentifier": "svc-1",
            "Properties": {"name": "svc_backup@example.local", "domain": "example.local"},
            "PrimaryGroupSID": "g-1",
        },
        {
            "meta_type": "groups",
            "ObjectIdentifier": "g-1",
            "Properties": {"name": "BackupOperators@example.local", "domain": "example.local"},
            "Members": [{"ObjectIdentifier": "svc-1", "ObjectType": "User"}],
        },
        {
            "meta_type": "computers",
            "ObjectIdentifier": "c-1",
            "Properties": {"name": "SRV01.example.local", "domain": "example.local"},
            "LocalAdmins": {"Results": [{"ObjectIdentifier": "g-1", "ObjectType": "Group"}]},
        },
    ]
    nodes, edges = BloodHoundParser().parse_records(records)
    graph = ADGraph(nodes, edges)

    relationships = {(edge.source, edge.relationship, edge.target) for edge in graph.edges}

    assert ("U-1", "GenericWrite", "U-1") in relationships
    assert ("SVC-1", "MemberOf", "G-1") in relationships
    assert ("G-1", "AdminTo", "C-1") in relationships


def test_shortest_path_and_reachable_nodes() -> None:
    nodes = [
        Node(id="u-1", name="alice", type=NodeType.USER),
        Node(id="svc-1", name="svc_backup", type=NodeType.USER),
        Node(id="g-1", name="BackupOperators", type=NodeType.GROUP),
        Node(id="c-1", name="SRV01", type=NodeType.COMPUTER),
    ]
    edges = [
        Edge(source="u-1", target="svc-1", relationship="GenericWrite"),
        Edge(source="svc-1", target="g-1", relationship="MemberOf"),
        Edge(source="g-1", target="c-1", relationship="AdminTo"),
    ]
    graph = ADGraph(nodes, edges)

    paths = ShortestPathFinder().find("alice", "SRV01", graph.nodes, graph.edges)
    reachable = ShortestPathFinder().reachable(graph, "alice", max_depth=2)

    assert [edge.relationship for edge in paths[0].edges] == [
        "GenericWrite",
        "MemberOf",
        "AdminTo",
    ]
    assert [node.name for node in reachable] == ["svc_backup", "BackupOperators"]


def test_parser_handles_bloodhound_json_payload(tmp_path: Path) -> None:
    payload = {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1-1104",
                "Properties": {"name": "MANAGEMENT@CERTIFIED.HTB", "domain": "certified.htb"},
                "Members": [{"ObjectIdentifier": "S-1-5-21-1-1105", "ObjectType": "User"}],
                "Aces": [
                    {
                        "RightName": "WriteDacl",
                        "PrincipalSID": "S-1-5-21-1-512",
                        "PrincipalType": "Group",
                        "IsInherited": True,
                    }
                ],
            }
        ],
        "meta": {"type": "groups", "count": 1, "version": 5},
    }
    source = tmp_path / "groups.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    result = BloodHoundParser().parse_file_result(source)
    graph = ADGraph(result.nodes, result.edges)

    assert graph.nodes[0].domain == "CERTIFIED.HTB"
    assert graph.edges_by_relationship("MemberOf")[0].source == "S-1-5-21-1-1105"
    assert graph.edges_by_relationship("WriteDACL")[0].source == "S-1-5-21-1-512"


def test_parse_path_handles_single_json_file(tmp_path: Path) -> None:
    source = tmp_path / "users.json"
    source.write_text(
        json.dumps(
            {
                "data": [
                    {
                        "ObjectIdentifier": "u-1",
                        "Properties": {"name": "alice@example.local", "domain": "example.local"},
                    }
                ],
                "meta": {"type": "users"},
            }
        ),
        encoding="utf-8",
    )

    result = BloodHoundParser().parse_path(source)

    assert result.nodes[0].id == "U-1"
    assert result.nodes[0].domain == "EXAMPLE.LOCAL"


def test_parser_reports_bad_json(tmp_path: Path) -> None:
    bad_json = tmp_path / "users.json"
    bad_json.write_text("{not-json", encoding="utf-8")

    result = BloodHoundParser().parse_file_result(bad_json)

    assert result.nodes == []
    assert result.edges == []
    assert result.warnings


def test_normalized_graph_round_trip(tmp_path: Path) -> None:
    graph = ADGraph(
        [Node(id="u-1", name="alice", type=NodeType.USER)],
        [Edge(source="u-1", target="g-1", relationship="MemberOf", source_tool="bloodhound")],
    )

    graph.write_normalized(tmp_path)
    loaded = ADGraph.read_normalized(tmp_path)

    assert (tmp_path / "nodes.json").exists()
    assert (tmp_path / "edges.json").exists()
    assert (tmp_path / "graph.json").exists()
    assert loaded.nodes[0].name == "alice"
    assert loaded.edges[0].relationship == "MemberOf"
