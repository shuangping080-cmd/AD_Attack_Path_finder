"""One-shot investigation workflow for BloodHound graph analysis."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adpath.detectors.acl import ACLDetector
from adpath.detectors.adcs import ADCSDetector
from adpath.detectors.base import Finding
from adpath.detectors.delegation import DelegationDetector
from adpath.detectors.dmsa import DMSADetector
from adpath.detectors.gmsa import GMSADetector
from adpath.detectors.gpo import GPODetector
from adpath.detectors.kerberos import KerberosDetector
from adpath.detectors.ou import OUDetector
from adpath.graph import ADGraph
from adpath.knowledge.loader import KnowledgeBaseLoader
from adpath.knowledge.matcher import AttackPatternMatcher
from adpath.knowledge.primitives import PrimitiveCatalog
from adpath.models.edge import Edge
from adpath.models.path import AttackPath, PathType
from adpath.parsers.bloodhound_parser import BloodHoundParser
from adpath.pathfinder.candidate_path import CandidatePathFinder
from adpath.pathfinder.privilege_path import PrivilegePathFinder
from adpath.reports import markdown_report, markdown_signals_report, paths_report
from adpath.signal import rank_signals
from adpath.signal.detectors import ComputerAccountSignalDetector


@dataclass(slots=True)
class InvestigationResult:
    """Combined output from the one-shot investigation workflow."""

    graph_dir: Path
    start: str
    graph_summary: dict[str, int]
    findings: list[Finding]
    candidate_paths: list[AttackPath]
    privilege_paths: list[AttackPath]
    foothold_candidates: list[Any]
    pattern_matches: list[Any]
    llm_review_recommended: bool
    llm_prompt: str
    import_warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-ready investigation output."""
        path_report = paths_report(self.candidate_paths)
        return {
            "graph_dir": str(self.graph_dir),
            "start": self.start,
            "graph_summary": self.graph_summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "rule_based_paths": path_report,
            "privilege_paths": [path.to_dict() for path in self.privilege_paths],
            "foothold_candidates": [finding.to_dict() for finding in self.foothold_candidates],
            "structural_pattern_matches": [match.to_dict() for match in self.pattern_matches],
            "llm_review": {
                "recommended": self.llm_review_recommended,
                "prompt": self.llm_prompt,
            },
            "import_warnings": self.import_warnings,
        }


def run_investigation(
    input_path: Path | str,
    start: str,
    *,
    output: Path | str = Path("data/current"),
    knowledge_base: Path | str = Path("knowledge-base"),
    max_depth: int = 6,
    top_n: int = 10,
    include_normalized: bool = True,
    dc: str | None = None,
) -> InvestigationResult:
    """Import or read a graph, run rules, and prepare a knowledge-assisted report."""
    output_path = Path(output)
    graph, graph_dir, import_warnings = _load_or_import_graph(Path(input_path), output_path)
    findings = _all_findings(graph)
    semantic_edges = _semantic_edges(findings)
    analysis_edges = [*graph.edges, *semantic_edges]
    primitives = PrimitiveCatalog.load(knowledge_base).primitives

    candidate_paths = CandidatePathFinder(
        knowledge_base=knowledge_base,
        include_normalized=include_normalized,
    ).find(
        start,
        graph.nodes,
        analysis_edges,
        primitives,
        findings=findings,
        max_depth=max_depth,
        top_n=top_n,
    )
    candidate_paths = sorted(candidate_paths, key=lambda item: (-item.score, item.target))[:top_n]

    privilege_paths = PrivilegePathFinder().find(
        start,
        graph.nodes,
        analysis_edges,
        max_depth=max_depth,
        top_n=top_n,
    )
    foothold_candidates = rank_signals(
        ComputerAccountSignalDetector(knowledge_base=knowledge_base, dc=dc).detect_graph(graph),
        top_n=top_n,
    )
    pattern_matches = AttackPatternMatcher(knowledge_base).match_graph(
        graph.nodes,
        analysis_edges,
        primitives=primitives,
        allow_partial=True,
    )[:top_n]

    llm_review_recommended = _needs_llm_review(candidate_paths)
    llm_prompt = _build_llm_prompt(
        start=start,
        graph=graph,
        candidate_paths=candidate_paths,
        privilege_paths=privilege_paths,
        findings=findings,
        pattern_matches=pattern_matches,
        knowledge_base=Path(knowledge_base),
        llm_review_recommended=llm_review_recommended,
    )
    return InvestigationResult(
        graph_dir=graph_dir,
        start=start,
        graph_summary={"nodes": len(graph.nodes), "edges": len(graph.edges)},
        findings=findings,
        candidate_paths=candidate_paths,
        privilege_paths=privilege_paths,
        foothold_candidates=foothold_candidates,
        pattern_matches=pattern_matches,
        llm_review_recommended=llm_review_recommended,
        llm_prompt=llm_prompt,
        import_warnings=import_warnings,
    )


def markdown_investigation_report(result: InvestigationResult) -> str:
    """Return a concise Markdown investigation report."""
    lines = [
        "# AD Attack Path Investigation",
        "",
        f"- Start principal: `{result.start}`",
        f"- Graph: `{result.graph_dir}`",
        f"- Nodes / edges: {result.graph_summary['nodes']} / {result.graph_summary['edges']}",
        "",
        "## Ranked Recommended Paths",
        "",
    ]
    if result.candidate_paths:
        for index, path in enumerate(result.candidate_paths, start=1):
            lines.append(
                f"{index}. {path.path_type} score={path.score:.2f} "
                f"confidence={path.confidence:.2f} target=`{path.target}`"
            )
            lines.append(f"   - Reason: {path.reason or 'current graph and knowledge-assisted analysis'}")
            if path.missing_information:
                lines.append("   - Conditions to verify:")
                for item in path.missing_information[:5]:
                    lines.append(f"     - {item.question} on `{item.object}` via {item.possible_collector}")
            if path.historical_support:
                examples = []
                for support in path.historical_support[:3]:
                    names = [str(example.get("machine")) for example in support.examples[:3] if example.get("machine")]
                    label = support.pattern or support.machine or "historical-pattern"
                    examples.append(f"{label} ({', '.join(names) if names else support.confidence})")
                lines.append(f"   - Historical support: {', '.join(examples)}")
    else:
        lines.append("No rule-based candidate path found.")
    lines.extend(["", "## Rule-Based Path Report", "", markdown_report(result.candidate_paths), ""])

    if result.privilege_paths:
        lines.extend(["## Raw Privilege-Oriented Paths", ""])
        for index, path in enumerate(result.privilege_paths[:5], start=1):
            edge_text = " -> ".join(edge.relationship for edge in path.edges) or "no edges"
            lines.append(f"{index}. score={path.score:.2f} target=`{path.target}` relationships={edge_text}")
        lines.append("")

    if result.pattern_matches:
        lines.extend(["## Structural Knowledge Matches", ""])
        for match in result.pattern_matches[:5]:
            status = "partial" if match.partial else "complete"
            examples = ", ".join(str(item.get("machine")) for item in match.examples[:3] if item.get("machine"))
            lines.append(
                f"- {match.pattern_key} ({status}, score={match.score:.2f}, confidence={match.confidence:.2f})"
                + (f" examples: {examples}" if examples else "")
            )
        lines.append("")

    if result.foothold_candidates:
        lines.extend(["## Initial Foothold Signals", "", markdown_signals_report(result.foothold_candidates), ""])

    lines.extend(
        [
            "## LLM Review",
            "",
            "Recommended: " + ("yes" if result.llm_review_recommended else "optional"),
            "",
            "```text",
            result.llm_prompt,
            "```",
        ]
    )
    return "\n".join(lines)


def investigation_json(result: InvestigationResult) -> str:
    """Return pretty JSON for an investigation result."""
    return json.dumps(result.to_dict(), indent=2)


def _load_or_import_graph(input_path: Path, output_path: Path) -> tuple[ADGraph, Path, list[str]]:
    if _looks_normalized_graph(input_path):
        return ADGraph.read_normalized(input_path), input_path, []
    parsed = BloodHoundParser().parse_path(input_path)
    graph = ADGraph(parsed.nodes, parsed.edges)
    graph.write_normalized(output_path)
    return graph, output_path, parsed.warnings


def _looks_normalized_graph(path: Path) -> bool:
    if path.is_dir():
        return (path / "graph.json").exists() or ((path / "nodes.json").exists() and (path / "edges.json").exists())
    return path.name == "graph.json" and path.exists()


def _all_findings(graph: ADGraph) -> list[Finding]:
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
    findings: list[Finding] = []
    for detector in detectors:
        findings.extend(detector.detect_graph(graph))
    return _dedupe_findings(findings)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple[Any, ...], Finding] = {}
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


def _semantic_edges(findings: list[Finding]) -> list[Edge]:
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


def _needs_llm_review(paths: list[AttackPath]) -> bool:
    strong_paths = [
        path
        for path in paths
        if path.path_type == PathType.CONFIRMED
        or (path.path_type == PathType.CANDIDATE and path.score >= 2.0 and not path.missing_information)
    ]
    return not strong_paths


def _build_llm_prompt(
    *,
    start: str,
    graph: ADGraph,
    candidate_paths: list[AttackPath],
    privilege_paths: list[AttackPath],
    findings: list[Finding],
    pattern_matches: list[Any],
    knowledge_base: Path,
    llm_review_recommended: bool,
) -> str:
    loader = KnowledgeBaseLoader(knowledge_base)
    pattern_cards = loader.pattern_cards()
    path_report = paths_report(candidate_paths)
    top_findings = [
        {
            "relationship": finding.relationship,
            "primitive": finding.primitive.name if finding.primitive else finding.name,
            "status": finding.status,
            "source": finding.source,
            "target": finding.target,
        }
        for finding in findings[:20]
    ]
    prompt_data = {
        "task": "Review the current BloodHound graph for likely AD attack paths. Treat graph edges as facts and HTB knowledge as historical interpretation only.",
        "start_principal": start,
        "llm_review_reason": "rule-based analysis did not find a strong complete path"
        if llm_review_recommended
        else "rule-based analysis found paths; use LLM only for analyst review and prioritization",
        "graph_summary": {"nodes": len(graph.nodes), "edges": len(graph.edges)},
        "rule_based_paths": {
            "confirmed": len(path_report["confirmed_paths"]),
            "candidate": len(path_report["candidate_paths"]),
            "incomplete": len(path_report["incomplete_paths"]),
            "next_best_investigations": path_report["next_best_investigations"][:5],
        },
        "top_findings": top_findings,
        "raw_privilege_paths": [
            {
                "target": path.target,
                "score": path.score,
                "relationships": [edge.relationship for edge in path.edges],
            }
            for path in privilege_paths[:5]
        ],
        "structural_pattern_matches": [match.to_dict() for match in pattern_matches[:5]],
        "knowledge_sources_to_consult": [
            (knowledge_base / "htb" / "public-index.json").as_posix(),
            (knowledge_base / "htb" / "structured").as_posix(),
            (knowledge_base / "attack-patterns").as_posix(),
            (knowledge_base / "pattern-cards").as_posix(),
        ],
        "available_pattern_cards": list(pattern_cards)[:20],
        "required_output": [
            "ranked recommended paths with confirmed/candidate/incomplete status",
            "facts from current graph separated from historical HTB analogies",
            "conditions that must be verified before treating a path as workable",
            "next best collection or validation steps",
            "short final analyst recommendation",
        ],
    }
    return json.dumps(prompt_data, indent=2)
