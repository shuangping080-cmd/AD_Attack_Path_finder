"""Validate candidate-path safety invariants for a normalized graph."""

from __future__ import annotations

import argparse
from pathlib import Path

from adpath.graph import ADGraph
from adpath.knowledge.primitives import PrimitiveCatalog
from adpath.pathfinder.candidate_path import CandidatePathFinder


def build_parser() -> argparse.ArgumentParser:
    """Build script arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("start")
    parser.add_argument("-g", "--graph", type=Path, default=Path("data/normalized"))
    parser.add_argument("--kb", type=Path, default=Path("knowledge-base"))
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--top-n", type=int, default=10)
    parser.add_argument("--include-normalized", action=argparse.BooleanOptionalAction, default=True)
    return parser


def main() -> None:
    """Run candidate path validation."""
    args = build_parser().parse_args()
    graph = ADGraph.read_normalized(args.graph)
    primitives = PrimitiveCatalog.load(args.kb).primitives
    paths = CandidatePathFinder(knowledge_base=args.kb, include_normalized=args.include_normalized).find(
        args.start,
        graph.nodes,
        graph.edges,
        primitives,
        max_depth=args.max_depth,
        top_n=args.top_n,
    )
    failures: list[str] = []
    graph_edges = {(edge.source, edge.relationship, edge.target) for edge in graph.edges}
    for index, path in enumerate(paths, start=1):
        has_knowledge = any(edge.source_tool == "knowledge" for edge in path.candidate_edges)
        if has_knowledge and not path.missing_information:
            failures.append(f"path {index}: knowledge continuation has no missing information")
        if has_knowledge and "Candidate" not in str(path.path_type):
            failures.append(f"path {index}: knowledge continuation is not marked candidate")
        for edge in path.candidate_edges:
            if edge in path.confirmed_edges:
                failures.append(f"path {index}: candidate edge appears in confirmed_edges: {edge.relationship}")
            if edge.source_tool != "knowledge":
                failures.append(f"path {index}: candidate edge is not marked knowledge: {edge.relationship}")
        for edge in path.confirmed_edges:
            key = (edge.source, edge.relationship, edge.target)
            if key not in graph_edges and edge.source_tool != "semantic":
                failures.append(f"path {index}: confirmed edge is not in graph: {key}")
        historical = path.evidence.get("historical_patterns") if path.evidence else []
        if has_knowledge and not historical:
            failures.append(f"path {index}: candidate path has no historical support")
        for item in historical:
            if not item.get("pattern") and not item.get("machine"):
                failures.append(f"path {index}: historical support has no pattern or machine name")
            if item.get("review_status") in {"raw", "extracted", "rejected"} and item.get("support_strength") == "strong":
                failures.append(f"path {index}: unreviewed historical support is marked strong")
        if "Confirmed" in str(path.path_type):
            relationships = {edge.relationship for edge in path.edges}
            if "HasSPN" in relationships and any(edge.relationship == "SilverTicketCandidate" for edge in path.edges):
                failures.append(f"path {index}: HasSPN produced confirmed SilverTicket")
            if "CreateChild" in relationships and any(edge.relationship == "BadSuccessor" for edge in path.edges):
                failures.append(f"path {index}: CreateChild produced confirmed BadSuccessor")
            if "Enroll" in relationships and path.target.casefold().find("domain admin") >= 0:
                failures.append(f"path {index}: Enroll produced confirmed DomainPrivilege")
            if "AdminTo" in relationships and path.target.casefold().find("domain admin") >= 0:
                failures.append(f"path {index}: AdminTo produced confirmed DomainPrivilege")
    if failures:
        print("Candidate path validation failed:")
        for failure in failures:
            print(f"- {failure}")
        raise SystemExit(1)
    print(f"Validated {len(paths)} candidate paths")


if __name__ == "__main__":
    main()
