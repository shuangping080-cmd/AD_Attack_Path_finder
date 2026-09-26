"""Phase 5 interesting signal and foothold hypothesis tests."""

from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.node import Node, NodeType
from adpath.signal import EvidenceRecord, EvidenceStore, SignalStatus, rank_signals
from adpath.signal.detectors import ComputerAccountSignalDetector


def vintage_fs01_graph() -> ADGraph:
    """Build a minimal Vintage-like graph containing FS01 and Pre2K membership."""
    return ADGraph(
        [
            Node(
                id="fs01",
                name="FS01.VINTAGE.HTB",
                type=NodeType.COMPUTER,
                domain="VINTAGE.HTB",
                properties={
                    "samaccountname": "FS01$",
                    "enabled": True,
                    "serviceprincipalnames": ["HOST/fs01", "RestrictedKrbHost/fs01"],
                },
            ),
            Node(
                id="pre2k",
                name="PRE-WINDOWS 2000 COMPATIBLE ACCESS@VINTAGE.HTB",
                type=NodeType.GROUP,
                domain="VINTAGE.HTB",
            ),
        ],
        [
            Edge(source="fs01", target="pre2k", relationship="MemberOf", source_tool="bloodhound"),
        ],
    )


def test_computer_signal_detector_generates_pre2k_foothold_hypothesis() -> None:
    graph = vintage_fs01_graph()

    findings = ComputerAccountSignalDetector(dc="10.10.11.45").detect_graph(graph)
    fs01 = next(item for item in findings if item.object_name == "FS01.VINTAGE.HTB")

    assert fs01.status == SignalStatus.PATTERN_MATCHED
    assert fs01.metadata["username_candidate"] == "FS01$"
    assert fs01.metadata["password_candidate"] == "fs01"
    assert "netexec ldap 10.10.11.45" in fs01.suggested_validation[0]
    assert "'FS01$'" in fs01.suggested_validation[0]
    assert "'fs01'" in fs01.suggested_validation[0]
    assert fs01.pattern_matches[0]["id"] == "htb-vintage-pre2k-computer-password"


def test_signal_ranking_prefers_pattern_matched_computer_candidates() -> None:
    graph = vintage_fs01_graph()
    findings = ComputerAccountSignalDetector().detect_graph(graph)

    ranked = rank_signals(findings, top_n=1)

    assert ranked[0].object_name == "FS01.VINTAGE.HTB"
    assert ranked[0].score > 0


def test_evidence_store_marks_valid_credentials_as_controlled(tmp_path) -> None:
    graph_dir = tmp_path / "graph"
    store = EvidenceStore(graph_dir)

    store.add(
        EvidenceRecord(
            principal="FS01$@VINTAGE.HTB",
            type="credential_valid",
            method="kerberos_ldap",
            note="netexec ldap success with FS01$:fs01",
        )
    )

    assert store.controlled_principals() == ["FS01$@VINTAGE.HTB"]
    assert store.records()[0].type == "credential_valid"
    assert store.path == graph_dir / "evidence.json"


def test_graph_resolves_machine_sam_account_alias() -> None:
    graph = vintage_fs01_graph()

    assert graph.resolve_node("FS01$@VINTAGE.HTB").id == "fs01"
    assert graph.resolve_node("FS01$").id == "fs01"
