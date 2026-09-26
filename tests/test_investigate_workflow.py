"""One-shot investigation workflow tests."""

import json
from pathlib import Path

from adpath.graph import ADGraph
from adpath.investigate import investigation_json, markdown_investigation_report, run_investigation
from adpath.models.edge import Edge
from adpath.models.node import Node, NodeType


def test_investigate_builds_rule_and_llm_review_context(tmp_path: Path) -> None:
    graph_dir = tmp_path / "graph"
    graph = ADGraph(
        [
            Node(id="alice", name="ALICE@NOVA.LOCAL", type=NodeType.USER, domain="NOVA.LOCAL"),
            Node(id="svc", name="SVC_SQL@NOVA.LOCAL", type=NodeType.SERVICE_ACCOUNT, domain="NOVA.LOCAL"),
        ],
        [Edge(source="alice", target="svc", relationship="GenericWrite", source_tool="bloodhound")],
    )
    graph.write_normalized(graph_dir)

    result = run_investigation(
        graph_dir,
        "ALICE@NOVA.LOCAL",
        output=tmp_path / "unused",
        max_depth=4,
        top_n=5,
    )
    data = result.to_dict()

    assert result.graph_dir == graph_dir
    assert data["graph_summary"] == {"nodes": 2, "edges": 1}
    assert data["rule_based_paths"]["candidate_paths"] or data["rule_based_paths"]["incomplete_paths"]
    assert data["structural_pattern_matches"]
    assert data["llm_review"]["recommended"] is True
    assert "knowledge-base/htb/structured" in data["llm_review"]["prompt"].replace("\\", "/")
    assert "historical interpretation only" in data["llm_review"]["prompt"]


def test_investigate_markdown_and_json_are_structured(tmp_path: Path) -> None:
    graph_dir = tmp_path / "graph"
    graph = ADGraph(
        [
            Node(id="henry", name="HENRY@EXAMPLE.LOCAL", type=NodeType.USER),
            Node(id="alfred", name="ALFRED@EXAMPLE.LOCAL", type=NodeType.USER),
        ],
        [Edge(source="henry", target="alfred", relationship="WriteSPN", source_tool="bloodhound")],
    )
    graph.write_normalized(graph_dir)

    result = run_investigation(graph_dir, "HENRY@EXAMPLE.LOCAL", output=tmp_path / "unused")
    markdown = markdown_investigation_report(result)
    parsed = json.loads(investigation_json(result))

    assert "# AD Attack Path Investigation" in markdown
    assert "Ranked Recommended Paths" in markdown
    assert "LLM Review" in markdown
    assert parsed["start"] == "HENRY@EXAMPLE.LOCAL"
    assert "rule_based_paths" in parsed
    assert "llm_review" in parsed
