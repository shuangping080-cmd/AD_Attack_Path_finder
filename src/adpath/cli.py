"""Command-line entry point for AD-Attack-Path-Finder."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adpath.detectors.acl import ACLDetector
from adpath.detectors.adcs import ADCSDetector
from adpath.detectors.delegation import DelegationDetector
from adpath.detectors.dmsa import DMSADetector
from adpath.detectors.gmsa import GMSADetector
from adpath.detectors.gpo import GPODetector
from adpath.detectors.kerberos import KerberosDetector
from adpath.detectors.ou import OUDetector
from adpath.detectors.privilege import PrivilegeDetector
from adpath.graph import ADGraph
from adpath.investigate import investigation_json, markdown_investigation_report, run_investigation
from adpath.knowledge.correlation import KnowledgeCorrelator
from adpath.knowledge.primitives import PrimitiveCatalog
from adpath.models.edge import Edge
from adpath.parsers.bloodhound_parser import BloodHoundParser
from adpath.pathfinder.candidate_path import CandidatePathFinder
from adpath.pathfinder.privilege_path import PrivilegePathFinder
from adpath.pathfinder.shortest_path import ShortestPathFinder
from adpath.reports import markdown_report, markdown_signals_report, paths_report, signals_report
from adpath.signal import EvidenceRecord, EvidenceStore, rank_signals
from adpath.signal.detectors import ComputerAccountSignalDetector

DEFAULT_GRAPH_DIR = Path("data/normalized")
ADVANCED_DETECTORS = {
    "kerberos": KerberosDetector,
    "delegation": DelegationDetector,
    "gmsa": GMSADetector,
    "dmsa": DMSADetector,
    "adcs": ADCSDetector,
    "ou": OUDetector,
    "gpo": GPODetector,
}


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(prog="adpath")
    subcommands = parser.add_subparsers(dest="command", required=True)

    import_cmd = subcommands.add_parser("import", help="import BloodHound JSON or zip data")
    import_cmd.add_argument("input", type=Path)
    import_cmd.add_argument("-o", "--output", type=Path, default=DEFAULT_GRAPH_DIR)

    investigate_cmd = subcommands.add_parser(
        "investigate",
        help="run one-shot import, rule analysis, KB correlation, and LLM review prompt generation",
    )
    investigate_cmd.add_argument("input", type=Path, help="BloodHound zip/JSON directory or normalized graph directory")
    investigate_cmd.add_argument("--start", required=True, help="initial controlled low-privilege principal")
    investigate_cmd.add_argument("-o", "--output", type=Path, default=Path("data/current"))
    investigate_cmd.add_argument("--kb", type=Path, default=Path("knowledge-base"))
    investigate_cmd.add_argument("--max-depth", type=int, default=6)
    investigate_cmd.add_argument("--top-n", type=int, default=10)
    investigate_cmd.add_argument("--dc", help="domain controller host/IP for foothold validation hints")
    investigate_cmd.add_argument("--include-normalized", action=argparse.BooleanOptionalAction, default=True)
    investigate_cmd.add_argument("--json", action="store_true")
    investigate_cmd.add_argument("--markdown", action="store_true")

    nodes_cmd = subcommands.add_parser("nodes", help="list normalized nodes")
    nodes_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    nodes_cmd.add_argument("--type")

    edges_cmd = subcommands.add_parser("edges", help="list normalized edges")
    edges_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    edges_cmd.add_argument("--relationship")

    path_cmd = subcommands.add_parser("path", help="find a shortest path")
    path_cmd.add_argument("start")
    path_cmd.add_argument("target")
    path_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    path_cmd.add_argument("--max-depth", type=int)

    reachable_cmd = subcommands.add_parser("reachable", help="list reachable nodes")
    reachable_cmd.add_argument("start")
    reachable_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    reachable_cmd.add_argument("--max-depth", type=int)

    findings_cmd = subcommands.add_parser("findings", help="list semantic findings")
    findings_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    findings_cmd.add_argument("--relationship")

    for detector_name in ADVANCED_DETECTORS:
        detector_cmd = subcommands.add_parser(detector_name, help=f"list {detector_name} findings")
        detector_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)

    primitives_cmd = subcommands.add_parser("primitives", help="list loaded attack primitives")
    primitives_cmd.add_argument("-k", "--knowledge-base", type=Path, default=Path("knowledge-base"))

    privilege_path_cmd = subcommands.add_parser("privilege-path", help="find privilege-oriented paths")
    privilege_path_cmd.add_argument("start")
    privilege_path_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    privilege_path_cmd.add_argument("--max-depth", type=int, default=4)
    privilege_path_cmd.add_argument("--target-type")
    privilege_path_cmd.add_argument("--high-value-only", action="store_true")
    privilege_path_cmd.add_argument("--top-n", type=int, default=20)

    candidate_path_cmd = subcommands.add_parser("candidate-path", help="find evidence-backed candidate paths")
    candidate_path_cmd.add_argument("start", nargs="?")
    candidate_path_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    candidate_path_cmd.add_argument("--kb", type=Path, default=Path("knowledge-base"))
    candidate_path_cmd.add_argument("--target")
    candidate_path_cmd.add_argument("--max-depth", type=int, default=5)
    candidate_path_cmd.add_argument("--top-n", type=int, default=10)
    candidate_path_cmd.add_argument("--controlled", action="store_true", help="expand all controlled principals from evidence.json")
    candidate_path_cmd.add_argument("--evidence", type=Path, help="path to evidence.json or a graph directory containing it")
    candidate_path_cmd.add_argument("--include-normalized", action=argparse.BooleanOptionalAction, default=True)
    candidate_path_cmd.add_argument("--show-evidence", action="store_true")
    candidate_path_cmd.add_argument("--json", action="store_true")
    candidate_path_cmd.add_argument("--markdown", action="store_true")

    foothold_cmd = subcommands.add_parser("foothold-candidates", help="recommend initial foothold candidates")
    foothold_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    foothold_cmd.add_argument("--kb", type=Path, default=Path("knowledge-base"))
    foothold_cmd.add_argument("--dc", help="domain controller host/IP to place in validation commands")
    foothold_cmd.add_argument("--top-n", type=int, default=20)
    foothold_cmd.add_argument("--json", action="store_true")
    foothold_cmd.add_argument("--markdown", action="store_true")

    evidence_cmd = subcommands.add_parser("evidence", help="manage analyst-supplied validation evidence")
    evidence_subcommands = evidence_cmd.add_subparsers(dest="evidence_command", required=True)
    evidence_add = evidence_subcommands.add_parser("add", help="add validation evidence")
    evidence_add.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    evidence_add.add_argument("--principal", required=True)
    evidence_add.add_argument(
        "--type",
        required=True,
        choices=[
            "credential_valid",
            "credential_invalid",
            "ldap_readable",
            "shell_obtained",
            "hash_obtained",
            "cert_obtained",
        ],
    )
    evidence_add.add_argument("--method", required=True)
    evidence_add.add_argument("--note", default="")
    evidence_list = evidence_subcommands.add_parser("list", help="list validation evidence")
    evidence_list.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)

    analyze_cmd = subcommands.add_parser("analyze", help="summarize reachable nodes and semantic paths")
    analyze_cmd.add_argument("start")
    analyze_cmd.add_argument("-g", "--graph", type=Path, default=DEFAULT_GRAPH_DIR)
    analyze_cmd.add_argument("--max-depth", type=int, default=3)
    return parser


def main() -> None:
    """Run the CLI."""
    args = build_parser().parse_args()
    if args.command == "import":
        result = BloodHoundParser().parse_path(args.input)
        graph = ADGraph(result.nodes, result.edges)
        graph.write_normalized(args.output)
        print(f"Imported {len(graph.nodes)} nodes and {len(graph.edges)} edges into {args.output}")
        if result.warnings:
            print(f"Warnings: {len(result.warnings)}")
            for warning in result.warnings[:10]:
                print(f"- {warning}")
        return

    if args.command == "investigate":
        result = run_investigation(
            args.input,
            args.start,
            output=args.output,
            knowledge_base=args.kb,
            max_depth=args.max_depth,
            top_n=args.top_n,
            include_normalized=args.include_normalized,
            dc=args.dc,
        )
        if args.json:
            print(investigation_json(result))
            return
        print(markdown_investigation_report(result))
        return

    if args.command == "primitives":
        catalog = PrimitiveCatalog.load(args.knowledge_base)
        for warning in catalog.warnings:
            print(f"WARNING: {warning}")
        for primitive in catalog.primitives:
            relationships = ", ".join(primitive.required_relationships)
            print(f"{primitive.name}\t{primitive.category}\t{relationships}\t{primitive.result or ''}")
        return

    if args.command == "evidence":
        store = EvidenceStore(args.graph)
        if args.evidence_command == "add":
            record = EvidenceRecord(
                principal=args.principal,
                type=args.type,
                method=args.method,
                note=args.note,
            )
            data = store.add(record)
            print(f"Added evidence for {record.principal}: {record.type}")
            if record.principal in data.get("controlled_principals", []):
                print(f"Controlled principal: {record.principal}")
            print(f"Wrote {store.path}")
            return
        if args.evidence_command == "list":
            data = store.load()
            print("Controlled principals:")
            for principal in data.get("controlled_principals", []):
                print(f"- {principal}")
            print("\nEvidence:")
            for item in data.get("evidence", []):
                print(f"- {item.get('principal')} [{item.get('type')}] via {item.get('method')}: {item.get('note') or ''}")
            return

    graph = ADGraph.read_normalized(args.graph)
    if args.command == "nodes":
        nodes = graph.nodes
        if args.type:
            nodes = [node for node in nodes if str(node.type).casefold() == args.type.casefold()]
        for node in nodes:
            print(f"{node.id}\t{node.type}\t{node.name}")
        return

    if args.command == "edges":
        edges = graph.edges
        if args.relationship:
            edges = [edge for edge in edges if edge.relationship == args.relationship]
        for edge in edges:
            print(f"{edge.source}\t{edge.relationship}\t{edge.target}")
        return

    finder = ShortestPathFinder()
    if args.command == "path":
        paths = finder.find(
            args.start,
            args.target,
            graph.nodes,
            graph.edges,
            max_depth=args.max_depth,
        )
        if not paths:
            print("No path found")
            return
        path = paths[0]
        print(_format_path(path.nodes, path.edges))
        return

    if args.command == "reachable":
        for node in finder.reachable(graph, args.start, max_depth=args.max_depth):
            print(f"{node.id}\t{node.type}\t{node.name}")
        return

    if args.command == "findings":
        findings = _all_findings(graph)
        if args.relationship:
            findings = [item for item in findings if item.relationship == args.relationship]
        for finding in findings:
            print(_format_finding(finding, graph))
        return

    if args.command in ADVANCED_DETECTORS:
        findings = ADVANCED_DETECTORS[args.command]().detect_graph(graph)
        for finding in findings:
            print(_format_finding(finding, graph))
        if not findings:
            print(f"No {args.command} findings")
        return

    if args.command == "privilege-path":
        paths = PrivilegePathFinder().find(
            args.start,
            graph.nodes,
            graph.edges,
            max_depth=args.max_depth,
            target_type=args.target_type,
            high_value_only=args.high_value_only,
            top_n=args.top_n,
        )
        for path in paths:
            print(_format_path(path.nodes, path.edges))
            print(f"Score: {path.score:.2f}")
            print(f"Status: {path.path_type}")
            if path.missing_information:
                print("Missing:")
                for item in path.missing_information:
                    print(f"- {item.question} on {item.object} [{item.suggested_source}, {item.importance.name.lower()}]")
            print()
        if not paths:
            print("No privilege path found")
        return

    if args.command == "candidate-path":
        findings = _all_findings(graph)
        analysis_edges = [*graph.edges, *_semantic_edges(findings)]
        starts = _candidate_starts(args)
        if not starts:
            print("No candidate path start provided and no controlled principals found.")
            return
        paths = []
        for start in starts:
            paths.extend(
                CandidatePathFinder(knowledge_base=args.kb, include_normalized=args.include_normalized).find(
                    start,
                    graph.nodes,
                    analysis_edges,
                    PrimitiveCatalog.load(args.kb).primitives,
                    findings=findings,
                    target=args.target,
                    max_depth=args.max_depth,
                    top_n=args.top_n,
                )
            )
        paths = sorted(paths, key=lambda item: (-item.score, item.target))[: args.top_n]
        if args.json:
            print(json.dumps(paths_report(paths), indent=2))
            return
        if args.markdown:
            print(markdown_report(paths))
            return
        for path in paths:
            print(f"[{path.path_type}] score={path.score:.2f} confidence={path.confidence:.2f}")
            print(_format_candidate_path(path))
            if path.reason:
                print(f"Why not confirmed: {path.reason}")
            if path.confirmed_edges:
                print("Confirmed:")
                for edge in path.confirmed_edges:
                    print(f"- {edge.source} {edge.relationship} {edge.target}")
            if path.candidate_edges:
                print("Candidate:")
                for edge in path.candidate_edges:
                    print(f"- {edge.source} {edge.relationship} {edge.target}")
            historical = path.evidence.get("historical_patterns") if path.evidence else None
            if historical:
                print("Historical support:")
                for item in historical[:3]:
                    print(
                        f"- {item.get('pattern') or item.get('machine')}: {item.get('source')} "
                        f"--{item.get('relationship')}--> {item.get('target')} "
                        f"[{item.get('primitive') or 'relationship'}, {item.get('support_strength', 'weak')}]"
                    )
            if path.missing_information:
                print("Missing:")
                for item in path.missing_information:
                    print(f"- {item.question} on {item.object} [{item.suggested_source}, {item.importance.name.lower()}]")
            if args.show_evidence:
                print("Evidence:")
                print(json.dumps(path.evidence.to_dict(), indent=2))
            print()
        report = paths_report(paths)
        investigations = report.get("next_best_investigations") or []
        if investigations:
            print("Next best investigations:")
            for item in investigations[:5]:
                print(
                    f"- priority={item['priority']}: {item['question']} "
                    f"on {item['object']} [{item['possible_collector']}]"
                )
        if not paths:
            print("No candidate path found")
            print("Reason: start node did not resolve, no confirmed prefix was found, or KB review filters excluded matching hints.")
        return

    if args.command == "foothold-candidates":
        signals = rank_signals(
            ComputerAccountSignalDetector(knowledge_base=args.kb, dc=args.dc).detect_graph(graph),
            top_n=args.top_n,
        )
        if args.json:
            print(json.dumps(signals_report(signals), indent=2))
            return
        if args.markdown:
            print(markdown_signals_report(signals))
            return
        if not signals:
            print("No foothold candidates found")
            return
        for index, signal in enumerate(signals, start=1):
            print(f"[{index}] {signal.object_name}")
            print(f"    Type: {signal.object_type}")
            print(f"    Status: {signal.status}")
            print(f"    Confidence: {signal.confidence}")
            print(f"    Score: {signal.score:.2f}")
            print("    Signals:")
            for item in signal.observed_evidence:
                print(f"      - {item}")
            if signal.pattern_matches:
                print("    Knowledge Match:")
                for item in signal.pattern_matches[:3]:
                    print(f"      - {item.get('id')} ({item.get('machine')}, {item.get('primitive')})")
            print("    Hypothesis:")
            print(f"      - {signal.hypothesis}")
            print("    Validate:")
            for command in signal.suggested_validation:
                print(f"      {command}")
            print("    If valid:")
            for step in signal.next_steps:
                print(f"      - {step}")
            print()
        return

    if args.command == "analyze":
        reachable = ShortestPathFinder().reachable(graph, args.start, max_depth=args.max_depth)
        all_findings = _all_findings(graph)
        start_node = graph.resolve_node(args.start)
        start_id = start_node.id if start_node else args.start
        findings = [item for item in all_findings if item.source == start_id]
        advanced_edges = _semantic_edges(all_findings)
        analysis_edges = [*graph.edges, *advanced_edges]
        transitions = PrivilegeDetector().detect(graph.nodes, analysis_edges)
        paths = PrivilegePathFinder().find(args.start, graph.nodes, analysis_edges, max_depth=args.max_depth)
        print("Reachable nodes:")
        for node in reachable[:20]:
            print(f"- {node.name} ({node.type})")
        print("\nDetected primitives:")
        for finding in findings[:20]:
            primitive_name = finding.primitive.name if finding.primitive else "Unknown"
            print(f"- [{finding.status}] {finding.relationship}: {primitive_name} -> {finding.result}")
        print("\nPrivilege transitions:")
        scoped_transitions = [
            finding
            for finding in transitions
            if not start_node or finding.source == start_node.id
        ]
        for finding in scoped_transitions[:20]:
            print(f"- {finding.result}")
        print("\nPotential privilege paths:")
        for path in paths[:5]:
            print(f"- {_format_path(path.nodes, path.edges)} (score {path.score:.2f})")
        missing = []
        seen = set()
        for path in paths[:5]:
            for item in path.missing_information:
                if item.key not in seen:
                    seen.add(item.key)
                    missing.append(item)
        if missing:
            print("\nMissing information:")
            for item in missing:
                print(f"- {item.question} on {item.object} [{item.suggested_source}, {item.importance.name.lower()}]")
        hints = KnowledgeCorrelator().hints_for_identity(start_node.name if start_node else args.start)
        if hints:
            print("\nKnowledge base hints:")
            for hint in hints[:10]:
                relation = f" --{hint.relationship}--> {hint.target}" if hint.relationship and hint.target else ""
                primitive = f" [{hint.primitive}]" if hint.primitive else ""
                print(
                    f"- {hint.machine}: {hint.source}{relation}{primitive} -> {hint.result} "
                    f"(confidence {hint.confidence}, graph-confirmed: {hint.graph_confirmed})"
                )


def _all_findings(graph: ADGraph):
    detectors = [
        ACLDetector(),
        KerberosDetector(),
        DelegationDetector(),
        GMSADetector(),
        DMSADetector(),
        ADCSDetector(),
        OUDetector(),
        GPODetector(),
    ]
    findings = []
    for detector in detectors:
        findings.extend(detector.detect_graph(graph))
    return _dedupe_findings(findings)


def _candidate_starts(args) -> list[str]:
    """Resolve candidate path starting principals from CLI args and evidence store."""
    starts = []
    if getattr(args, "start", None):
        starts.append(args.start)
    if getattr(args, "controlled", False) or not starts:
        store = EvidenceStore(args.evidence or args.graph)
        starts.extend(store.controlled_principals())
    deduped = []
    seen = set()
    for start in starts:
        if start not in seen:
            seen.add(start)
            deduped.append(start)
    return deduped


def _dedupe_findings(findings):
    by_key = {}
    status_rank = {"confirmed": 3, "candidate": 2, "incomplete": 1}
    for item in findings:
        key = (
            item.source,
            item.target,
            item.relationship,
            item.primitive.name if item.primitive else item.name,
        )
        existing = by_key.get(key)
        item_score = (status_rank.get(item.status, 0), item.confidence, -len(item.missing_information))
        existing_score = (
            status_rank.get(existing.status, 0),
            existing.confidence,
            -len(existing.missing_information),
        ) if existing else None
        if existing is None or item_score > existing_score:
            by_key[key] = item
    return list(by_key.values())


def _semantic_edges(findings) -> list[Edge]:
    edges: list[Edge] = []
    for item in findings:
        semantic = item.evidence.get("semantic_edge") if item.evidence else None
        if not semantic or not item.source or not item.target:
            continue
        edges.append(
            Edge(
                source=item.source,
                target=item.target,
                relationship=str(semantic.get("primitive") or item.name),
                confidence=float(semantic.get("confidence") or item.confidence),
                source_tool="semantic",
                properties={
                    "status": item.status,
                    "raw_edges": semantic.get("raw_edges") or [],
                    "derived_from": semantic.get("derived_from") or [],
                    "evidence": semantic.get("evidence") or {},
                    "missing_information": [missing.to_dict() for missing in item.missing_information],
                },
            )
        )
    return edges


def _format_path(nodes, edges) -> str:
    if not nodes:
        return ""
    parts = [nodes[0].name]
    for index, edge in enumerate(edges):
        target_name = nodes[index + 1].name if index + 1 < len(nodes) else edge.target
        parts.append(f"--{edge.relationship}--> {target_name}")
    return " ".join(parts)


def _format_candidate_path(path) -> str:
    if not path.nodes:
        return ""
    parts = [path.nodes[0].name]
    for index, edge in enumerate(path.edges):
        target_name = path.nodes[index + 1].name if index + 1 < len(path.nodes) else edge.target
        marker = f"[KB:{edge.relationship}]" if edge.source_tool == "knowledge" else edge.relationship
        parts.append(f"--{marker}--> {target_name}")
    return " ".join(parts)


def _format_finding(finding, graph: ADGraph) -> str:
    source = graph.get_node(finding.source).name if finding.source and graph.get_node(finding.source) else finding.source
    target = graph.get_node(finding.target).name if finding.target and graph.get_node(finding.target) else finding.target
    primitive_name = finding.primitive.name if finding.primitive else "Unknown"
    lines = [
        f"{source} --{finding.relationship}--> {target}",
        "",
        f"Primitive: {primitive_name}",
        f"Result: {finding.result}",
        f"Confidence: {finding.confidence:.2f}",
    ]
    if finding.missing_information:
        lines.append("Missing:")
        lines.extend(
            f"- {item.question} on {item.object} [{item.suggested_source}, {item.importance.name.lower()}]"
            for item in finding.missing_information
        )
    examples = finding.evidence.get("historical_examples") if finding.evidence else None
    if examples:
        lines.append("Known examples:")
        lines.extend(
            f"- {item.get('machine')}: {item.get('source')} --{item.get('relationship')}--> {item.get('target')}"
            for item in examples[:3]
            if isinstance(item, dict)
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
