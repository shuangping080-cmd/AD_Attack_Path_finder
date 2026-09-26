"""Candidate path finder backed by current graph facts and historical knowledge."""

from __future__ import annotations

from collections import deque
from pathlib import Path

from adpath.detectors.base import Finding
from adpath.graph import ADGraph
from adpath.knowledge.correlation import KnowledgeCorrelator, KnowledgeHint
from adpath.knowledge.matcher import AttackPatternMatcher, PatternMatch
from adpath.models.edge import Edge
from adpath.models.evidence import HistoricalSupport, PathEvidence
from adpath.models.missing import (
    MissingImportance,
    MissingInformation,
    MissingSource,
    dedupe_missing,
)
from adpath.models.node import Node
from adpath.models.path import AttackPath, PathType
from adpath.models.primitive import AttackPrimitive
from adpath.pathfinder.path_score import PathScorer
from adpath.pathfinder.privilege_path import PrivilegePathFinder


class CandidatePathFinder:
    """Infer potential paths from primitive mappings and historical chain knowledge."""

    def __init__(
        self,
        correlator: KnowledgeCorrelator | None = None,
        knowledge_base: Path | str = "knowledge-base",
        include_normalized: bool = True,
    ) -> None:
        self.correlator = correlator or KnowledgeCorrelator(knowledge_base, include_normalized=include_normalized)
        self.pattern_matcher = AttackPatternMatcher(knowledge_base)
        self.privilege_finder = PrivilegePathFinder()
        self.scorer = PathScorer()

    def find(
        self,
        start: str,
        nodes: list[Node],
        edges: list[Edge],
        primitives: list[AttackPrimitive] | None = None,
        findings: list[Finding] | None = None,
        target: str | None = None,
        max_depth: int = 5,
        top_n: int = 10,
    ) -> list[AttackPath]:
        """Return confirmed, candidate, and incomplete paths with explicit evidence."""
        graph = ADGraph(nodes, edges)
        start_node = graph.resolve_node(start)
        if start_node is None:
            return []

        results: list[AttackPath] = []
        results.extend(self._confirmed_paths(graph, start_node, max_depth, top_n, findings or []))
        results.extend(self._pattern_candidates(graph, start_node, primitives or [], findings or [], target))
        results.extend(self._knowledge_continuations(graph, start_node, primitives or [], target, max_depth, findings or []))
        results.extend(self._primitive_candidates(graph, start_node, primitives or [], target))
        ranked = sorted(self._dedupe_paths(results).values(), key=lambda path: path.score, reverse=True)
        return ranked[:top_n]

    def _confirmed_paths(
        self,
        graph: ADGraph,
        start_node: Node,
        max_depth: int,
        top_n: int,
        findings: list[Finding],
    ) -> list[AttackPath]:
        paths = self.privilege_finder.find(start_node.id, graph.nodes, graph.edges, max_depth=max_depth, top_n=top_n)
        for path in paths:
            target_node = graph.get_node(path.target)
            path.confirmed_edges = [edge for edge in path.edges if self._is_observed_edge(edge)]
            path.candidate_edges = [edge for edge in path.edges if edge.source_tool == "knowledge"]
            if (
                not path.missing_information
                and all(self._is_observed_edge(edge) for edge in path.edges)
            ):
                path.path_type = PathType.CONFIRMED
            elif any(not self._is_observed_edge(edge) for edge in path.edges):
                path.path_type = PathType.CANDIDATE if path.candidate_edges else PathType.INCOMPLETE
            semantic_findings = self._findings_for_edges(findings, path.edges)
            score = self.scorer.score(
                confirmed_edges=path.confirmed_edges,
                candidate_edges=path.candidate_edges,
                missing=path.missing_information,
                target=target_node,
                confirmed_primitives=sum(1 for item in semantic_findings if item.get("status") == "confirmed"),
                incomplete_preconditions=1 if path.path_type == PathType.INCOMPLETE else 0,
            )
            path.score = score.value
            path.evidence = PathEvidence(
                current_graph_edges=[self._edge_evidence(graph, edge, confirmed=True) for edge in path.confirmed_edges],
                semantic_findings=semantic_findings,
                missing_information=[item.to_dict() for item in path.missing_information],
                notes=["Confirmed edges are present in the current graph."],
                score_breakdown=score.breakdown,
            )
            path.reason = self._reason(path)
        return paths

    def _pattern_candidates(
        self,
        graph: ADGraph,
        start_node: Node,
        primitives: list[AttackPrimitive],
        findings: list[Finding],
        requested_target: str | None,
    ) -> list[AttackPath]:
        observed_edges = [edge for edge in graph.edges if self._is_observed_edge(edge)]
        matches = self.pattern_matcher.match_graph(graph.nodes, observed_edges, primitives=primitives, allow_partial=True)
        paths: list[AttackPath] = []
        for match in matches:
            if not match.matched_nodes or match.matched_nodes[0].id != start_node.id:
                continue
            target_node = match.matched_nodes[-1]
            if requested_target and not self._same_identity(target_node.name, requested_target):
                continue
            if not match.partial:
                continue
            missing = self._missing_for_pattern_match(match, target_node)
            support = self._historical_support_for_match(match)
            score = self.scorer.score(
                confirmed_edges=match.matched_edges,
                candidate_edges=[],
                missing=missing,
                target=target_node,
                historical_pattern_matches=1,
                reviewed_examples=sum(
                    1
                    for item in support.examples
                    if item.get("review_status") == "reviewed" or item.get("confidence") == "reviewed"
                ),
                example_count=max(support.source_count, len(support.examples)),
                incomplete_preconditions=1 if missing else 0,
            )
            paths.append(
                AttackPath(
                    start=start_node.id,
                    target=target_node.id,
                    nodes=match.matched_nodes,
                    edges=match.matched_edges,
                    confirmed_edges=match.matched_edges,
                    primitives=[primitive for primitive in primitives if primitive.name in match.matched_primitives],
                    historical_support=[support],
                    path_type=PathType.INCOMPLETE,
                    score=score.value,
                    confidence=match.confidence or 0.5,
                    missing_information=missing,
                    evidence=PathEvidence(
                        current_graph_edges=[self._edge_evidence(graph, edge, confirmed=True) for edge in match.matched_edges],
                        semantic_findings=self._findings_for_edges(findings, match.matched_edges),
                        historical_patterns=[
                            {
                                "pattern": support.pattern,
                                "machine": item.get("machine"),
                                "relationship": item.get("relationship"),
                                "target": item.get("target"),
                                "confidence": item.get("confidence"),
                                "review_status": item.get("review_status"),
                                "support_strength": item.get("support_strength"),
                                "examples": item.get("steps") or item.get("chain"),
                            }
                            for item in support.examples
                        ],
                        missing_information=[item.to_dict() for item in missing],
                        notes=["Structural pattern match uses object types and relationship sequence; no identity-name reuse is required."],
                        score_breakdown=score.breakdown,
                    ),
                    reason="Current graph matches a known attack pattern prefix; missing steps block confirmation.",
                )
            )
        return paths

    def _knowledge_continuations(
        self,
        graph: ADGraph,
        start_node: Node,
        primitives: list[AttackPrimitive],
        requested_target: str | None,
        max_depth: int,
        findings: list[Finding],
    ) -> list[AttackPath]:
        paths: list[AttackPath] = []
        primitive_by_relationship = self._primitive_by_relationship(primitives)
        for hint in self.correlator.all_hints():
            if not hint.relationship or not hint.target:
                continue
            if requested_target and not self._same_identity(hint.target, requested_target):
                continue
            source_node = self._resolve_knowledge_node(graph, hint.source, hint.machine)
            if source_node is None:
                continue
            prefix = self._shortest_prefix(graph, start_node.id, source_node.id, max_depth=max_depth - 1)
            if prefix is None:
                continue
            target_node = self._resolve_knowledge_node(graph, hint.target, hint.machine)
            if target_node is None:
                continue
            if graph.out_edges(source_node.id, hint.relationship) and any(
                edge.target == target_node.id for edge in graph.out_edges(source_node.id, hint.relationship)
            ):
                continue
            continuation = Edge(
                source=source_node.id,
                target=target_node.id,
                relationship=hint.relationship,
                confidence=self._confidence_value(hint.confidence),
                source_tool="knowledge",
                properties={
                    "machine": hint.machine,
                    "primitive": hint.primitive,
                    "result": hint.result,
                    "graph_confirmed": False,
                    "evidence": hint.evidence,
                },
            )
            all_edges = [*prefix, continuation]
            path_nodes = self._nodes_for_path(graph, start_node, all_edges, target_node)
            missing = self._missing_for_hint(hint, target_node)
            path_primitives = self._primitives_for_hint(hint, primitive_by_relationship)
            historical_support = HistoricalSupport(
                pattern=hint.primitive or hint.relationship,
                machine=hint.machine,
                examples=[
                    {
                        "machine": hint.machine,
                        "source": hint.source,
                        "relationship": hint.relationship,
                        "target": hint.target,
                    }
                ],
                source_count=1,
                confidence=hint.confidence,
                evidence=hint.evidence,
            )
            score = self.scorer.score(
                confirmed_edges=prefix,
                candidate_edges=[continuation],
                missing=missing,
                target=target_node,
                historical_pattern_matches=1,
                reviewed_examples=1 if hint.review_status == "reviewed" else 0,
                example_count=1,
            )
            paths.append(
                AttackPath(
                    start=start_node.id,
                    target=target_node.id,
                    nodes=path_nodes,
                    edges=all_edges,
                    confirmed_edges=prefix,
                    candidate_edges=[continuation],
                    primitives=path_primitives,
                    historical_support=[historical_support],
                    path_type=PathType.CANDIDATE,
                    score=score.value,
                    confidence=min([edge.confidence for edge in all_edges], default=0.5),
                    missing_information=missing,
                    evidence=PathEvidence(
                        current_graph_edges=[self._edge_evidence(graph, edge, confirmed=True) for edge in prefix],
                        semantic_findings=self._findings_for_edges(findings, prefix),
                        historical_patterns=[
                            {
                                "pattern": hint.primitive or hint.relationship,
                                "machine": hint.machine,
                                "source": hint.source,
                                "relationship": hint.relationship,
                                "target": hint.target,
                                "primitive": hint.primitive,
                                "result": hint.result,
                                "confidence": hint.confidence,
                                "review_status": hint.review_status,
                                "support_strength": hint.support_strength,
                                "evidence": hint.evidence,
                            }
                        ],
                        missing_information=[item.to_dict() for item in missing],
                        notes=["KB support is historical and does not confirm the candidate edge in the current graph."],
                        score_breakdown=score.breakdown,
                    ),
                    reason="Confirmed prefix is present in the current graph; continuation is historical KB support only.",
                )
            )
        return paths

    def _primitive_candidates(
        self,
        graph: ADGraph,
        start_node: Node,
        primitives: list[AttackPrimitive],
        requested_target: str | None,
    ) -> list[AttackPath]:
        paths: list[AttackPath] = []
        primitives_by_relationship = self._primitive_by_relationship(primitives)
        for edge in graph.out_edges(start_node.id):
            if requested_target:
                target_node = graph.get_node(edge.target)
                if not target_node or not self._same_identity(target_node.name, requested_target):
                    continue
            candidates = primitives_by_relationship.get(edge.relationship, [])
            if not candidates:
                continue
            target_node = graph.get_node(edge.target)
            if target_node is None:
                continue
            missing = self._missing_for_primitive_candidates(candidates, target_node)
            if not missing:
                continue
            score = self.scorer.score(
                confirmed_edges=[edge],
                candidate_edges=[],
                missing=missing,
                target=target_node,
                incomplete_preconditions=1,
            )
            paths.append(
                AttackPath(
                    start=start_node.id,
                    target=edge.target,
                    nodes=[start_node, target_node],
                    edges=[edge],
                    confirmed_edges=[edge],
                    primitives=candidates,
                    path_type=PathType.INCOMPLETE,
                    score=score.value,
                    confidence=edge.confidence,
                    missing_information=missing,
                    evidence=PathEvidence(
                        current_graph_edges=[self._edge_evidence(graph, edge, confirmed=True)],
                        semantic_findings=[primitive.name for primitive in candidates],
                        missing_information=[item.to_dict() for item in missing],
                        notes=["Primitive candidate has missing preconditions and is not a confirmed path."],
                        score_breakdown=score.breakdown,
                    ),
                    reason="The graph edge exists, but primitive preconditions are incomplete.",
                )
            )
        return paths

    def _shortest_prefix(self, graph: ADGraph, start_id: str, target_id: str, max_depth: int) -> list[Edge] | None:
        if start_id == target_id:
            return []
        queue = deque([(start_id, [], {start_id})])
        while queue:
            node_id, path_edges, visited = queue.popleft()
            if len(path_edges) >= max_depth:
                continue
            for edge in graph.out_edges(node_id):
                if edge.target in visited or not self._is_observed_edge(edge):
                    continue
                next_edges = [*path_edges, edge]
                if edge.target == target_id:
                    return next_edges
                queue.append((edge.target, next_edges, {*visited, edge.target}))
        return None

    def _resolve_knowledge_node(self, graph: ADGraph, identity: str, machine: str | None = None) -> Node | None:
        if not identity or identity.casefold() == "unknown":
            return None
        direct = graph.resolve_node(identity)
        if direct:
            return direct
        identity_short = identity.casefold().split("@", 1)[0].split("\\", 1)[-1]
        if "@" in identity or "\\" in identity:
            return None
        for node in graph.nodes:
            node_short = node.name.casefold().split("@", 1)[0].split("\\", 1)[-1]
            node_scope = f"{node.domain or ''} {node.name}".casefold()
            if node_short == identity_short and machine and machine.casefold() in node_scope:
                return node
        return None

    def _nodes_for_path(self, graph: ADGraph, start_node: Node, edges: list[Edge], final_node: Node) -> list[Node]:
        nodes = [start_node]
        for edge in edges:
            node = graph.get_node(edge.target) or final_node
            if node.id != nodes[-1].id:
                nodes.append(node)
        return nodes

    def _primitive_by_relationship(self, primitives: list[AttackPrimitive]) -> dict[str, list[AttackPrimitive]]:
        result: dict[str, list[AttackPrimitive]] = {}
        for primitive in primitives:
            for relationship in primitive.required_relationships:
                result.setdefault(relationship, []).append(primitive)
        return result

    def _primitives_for_hint(
        self,
        hint: KnowledgeHint,
        primitive_by_relationship: dict[str, list[AttackPrimitive]],
    ) -> list[AttackPrimitive]:
        primitives = list(primitive_by_relationship.get(hint.relationship or "", []))
        if hint.primitive:
            primitives = sorted(primitives, key=lambda item: item.name != hint.primitive)
        return primitives

    def _missing_for_hint(self, hint: KnowledgeHint, target_node: Node) -> list[MissingInformation]:
        missing = [
            MissingInformation(
                question=f"Can the historical {hint.relationship} relationship be confirmed in this graph?",
                object=target_node.name,
                reason="The continuation is supported by HTB knowledge-base evidence but is not present as a current BloodHound graph fact.",
                suggested_source=MissingSource.LDAP,
                importance=MissingImportance.HIGH,
                missing_relationship=hint.relationship,
                expected_target_type=str(target_node.type),
                possible_collector=str(MissingSource.LDAP),
            )
        ]
        primitive = (hint.primitive or "").casefold()
        relationship = (hint.relationship or "").casefold()
        if primitive == "badsuccessor" or relationship == "createchild":
            missing.append(
                MissingInformation(
                    question="Can dMSA BadSuccessor predecessor/successor abuse be confirmed?",
                    object=target_node.name,
                    reason="CreateChild over an OU is only the setup condition; dMSA creation, successor linkage, and target impact still need validation.",
                    suggested_source=MissingSource.LDAP,
                    importance=MissingImportance.HIGH,
                    missing_relationship="dMSA successor/predecessor",
                    expected_target_type="dMSA",
                    possible_collector=str(MissingSource.LDAP),
                )
            )
        return dedupe_missing(missing)

    def _missing_for_pattern_match(self, match: PatternMatch, target_node: Node) -> list[MissingInformation]:
        missing: list[MissingInformation] = []
        for step in match.missing_steps:
            details = step.missing_if_absent
            relationship = details.get("relationship") or step.relationship
            missing.append(
                MissingInformation(
                    question=str(details.get("question") or f"Is {relationship or step.primitive} present downstream?"),
                    object=target_node.name,
                    reason=f"Pattern {match.name} matched a confirmed prefix but stopped before step {step.order}.",
                    suggested_source=details.get("collector") or MissingSource.BLOODHOUND,
                    importance=MissingImportance.HIGH if step.required else MissingImportance.MEDIUM,
                    blocks_path=step.required,
                    missing_relationship=relationship,
                    expected_source_type=step.source_type,
                    expected_target_type=step.target_type,
                    possible_collector=str(details.get("collector") or MissingSource.BLOODHOUND),
                )
            )
        for primitive in match.missing_primitives:
            missing.append(
                MissingInformation(
                    question=f"Can primitive {primitive} be confirmed?",
                    object=target_node.name,
                    reason=f"Pattern {match.name} expects this primitive before the path can be confirmed.",
                    suggested_source=MissingSource.LDAP,
                    importance=MissingImportance.MEDIUM,
                    blocks_path=True,
                    expected_target_type=str(target_node.type),
                    possible_collector=str(MissingSource.LDAP),
                )
            )
        return dedupe_missing(missing)

    def _historical_support_for_match(self, match: PatternMatch) -> HistoricalSupport:
        relationships = [step.relationship for step in [*match.matched_steps, *match.missing_steps] if step.relationship]
        primitives = [step.primitive for step in [*match.matched_steps, *match.missing_steps] if step.primitive]
        kb_examples = self.correlator.historical_examples_for_pattern(match.pattern_key, relationships, primitives)
        examples = [*match.examples, *kb_examples]
        return HistoricalSupport(
            pattern=match.pattern_key,
            machine=examples[0].get("machine") if examples else None,
            examples=examples,
            source_count=len(examples),
            confidence="medium" if any(item.get("review_status") == "reviewed" for item in examples) else "low",
            evidence={"match": match.to_dict()},
        )

    def _missing_for_primitive_candidates(
        self,
        primitives: list[AttackPrimitive],
        target_node: Node,
    ) -> list[MissingInformation]:
        missing: list[MissingInformation] = []
        for primitive in primitives:
            if primitive.preconditions:
                for condition in primitive.preconditions:
                    missing.append(
                        MissingInformation(
                            question=f"Is precondition satisfied for {primitive.name}?",
                            object=target_node.name,
                            reason=condition,
                            suggested_source=MissingSource.LDAP,
                            importance=MissingImportance.MEDIUM,
                            expected_target_type=str(target_node.type),
                            possible_collector=str(MissingSource.LDAP),
                        )
                    )
            for item in primitive.follow_up_information:
                missing.append(
                    MissingInformation(
                        question=item,
                        object=target_node.name,
                        reason=f"{primitive.name} requires analyst follow-up before it can be treated as confirmed.",
                        suggested_source=MissingSource.BLOODHOUND,
                        importance=MissingImportance.MEDIUM,
                        expected_target_type=str(target_node.type),
                        possible_collector=str(MissingSource.BLOODHOUND),
                    )
                )
        return dedupe_missing(missing)

    def _edge_evidence(self, graph: ADGraph, edge: Edge, confirmed: bool) -> dict[str, object]:
        source = graph.get_node(edge.source)
        target = graph.get_node(edge.target)
        return {
            "source": source.name if source else edge.source,
            "relationship": edge.relationship,
            "target": target.name if target else edge.target,
            "source_tool": edge.source_tool or "graph",
            "confirmed": confirmed,
        }

    def _is_observed_edge(self, edge: Edge) -> bool:
        return edge.source_tool not in {"knowledge", "semantic", "pattern"}

    def _findings_for_edges(self, findings: list[Finding], edges: list[Edge]) -> list[dict[str, object]]:
        edge_keys = {(edge.source, edge.relationship, edge.target) for edge in edges}
        matched = []
        for finding in findings:
            key = (finding.source, finding.relationship, finding.target)
            if key not in edge_keys:
                continue
            matched.append(
                {
                    "name": finding.name,
                    "relationship": finding.relationship,
                    "primitive": finding.primitive.name if finding.primitive else None,
                    "status": finding.status,
                    "confidence": finding.confidence,
                    "source_type": "semantic",
                }
            )
        return matched

    def _reason(self, path: AttackPath) -> str:
        if path.candidate_edges:
            return "Contains candidate edges inferred from KB or patterns, so it is not confirmed."
        if path.missing_information:
            return "Current graph edges exist, but missing information blocks a confirmed conclusion."
        return "All path edges are present in the current graph."

    def _dedupe_paths(
        self,
        paths: list[AttackPath],
    ) -> dict[tuple[str, tuple[tuple[str, str, str], ...], tuple[str, ...]], AttackPath]:
        best: dict[tuple[str, tuple[tuple[str, str, str], ...], tuple[str, ...]], AttackPath] = {}
        for path in paths:
            key = (
                path.target,
                tuple((edge.source, edge.relationship, edge.target) for edge in path.edges),
                tuple(sorted(primitive.name for primitive in path.primitives)),
            )
            current = best.get(key)
            if current is None or path.score > current.score:
                best[key] = path
        return best

    def _same_identity(self, left: str, right: str) -> bool:
        return bool(self._identity_keys(left) & self._identity_keys(right))

    def _identity_keys(self, value: str) -> set[str]:
        normalized = value.strip().casefold()
        if not normalized:
            return set()
        keys = {normalized}
        if "@" in normalized or "\\" in normalized:
            keys.add(normalized.split("\\", 1)[-1])
        return {item for item in keys if item and item != "unknown"}

    def _confidence_value(self, confidence: str) -> float:
        return {
            "high": 0.85,
            "medium": 0.65,
            "low": 0.4,
            "unknown": 0.5,
        }.get(confidence.casefold(), 0.5)
