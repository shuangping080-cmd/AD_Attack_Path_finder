"""Shared helpers for advanced AD primitive detectors."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from adpath.detectors.base import Finding
from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.missing import MissingImportance, MissingInformation, MissingSource
from adpath.models.node import Node
from adpath.models.primitive import AttackPrimitive
from adpath.models.semantic import SemanticEdge

TRUE_VALUES = {"true", "1", "yes", "y", "enabled"}


def prop_bool(properties: dict[str, Any], *keys: str) -> bool:
    """Return true if any named property is truthy."""
    for key in keys:
        if key not in properties:
            continue
        value = properties[key]
        if isinstance(value, bool):
            return value
        if isinstance(value, int | float):
            return value != 0
        if isinstance(value, str):
            return value.strip().casefold() in TRUE_VALUES
        if value:
            return True
    return False


def prop_list(properties: dict[str, Any], *keys: str) -> list[Any]:
    """Return the first non-empty list-like property."""
    for key in keys:
        value = properties.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, list):
            return value
        if isinstance(value, tuple | set):
            return list(value)
        return [value]
    return []


def prop_text(properties: dict[str, Any], *keys: str) -> str:
    """Return the first non-empty property as text."""
    for key in keys:
        value = properties.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def is_type(node: Node | None, *types: str) -> bool:
    """Return true when a node type matches one of the provided semantic types."""
    if node is None:
        return False
    return str(node.type).casefold() in {item.casefold() for item in types}


def is_service_account(node: Node | None) -> bool:
    """Identify service accounts from type and SPN-style properties."""
    if node is None:
        return False
    return is_type(node, "ServiceAccount", "gMSA", "dMSA") or bool(
        prop_list(node.properties, "serviceprincipalnames", "ServicePrincipalNames", "spns")
        or prop_bool(node.properties, "hasspn", "HasSPN")
    )


def is_gmsa(node: Node | None) -> bool:
    """Identify gMSA objects from type and common properties."""
    if node is None:
        return False
    name = node.name.casefold()
    return is_type(node, "gMSA") or prop_bool(node.properties, "isgmsa", "IsGMSA") or name.endswith("$")


def is_dmsa(node: Node | None) -> bool:
    """Identify dMSA objects from type and common properties."""
    if node is None:
        return False
    return is_type(node, "dMSA") or prop_bool(node.properties, "isdmsa", "IsDMSA")


def primitive(
    name: str,
    category: str,
    relationships: Iterable[str],
    *,
    source_type: str = "*",
    target_type: str = "*",
    result: str | None = None,
    confidence: float = 0.75,
    preconditions: Iterable[str] = (),
    description: str = "",
) -> AttackPrimitive:
    """Build a lightweight primitive for detector output."""
    return AttackPrimitive(
        name=name,
        category=category,
        source_type=source_type,
        target_type=target_type,
        required_relationships=list(relationships),
        preconditions=list(preconditions),
        result=result,
        confidence=confidence,
        description=description,
    )


def missing(
    question: str,
    object_name: str,
    reason: str,
    source: MissingSource,
    importance: MissingImportance = MissingImportance.MEDIUM,
) -> MissingInformation:
    """Build a structured missing-information record."""
    return MissingInformation(
        question=question,
        object=object_name,
        reason=reason,
        suggested_source=source,
        importance=importance,
    )


def finding(
    *,
    name: str,
    description: str,
    source: str | None,
    target: str | None,
    relationship: str | None,
    primitive_obj: AttackPrimitive,
    result: str,
    status: str,
    confidence: float,
    missing_information: list[MissingInformation],
    edge: Edge | None = None,
    graph: ADGraph | None = None,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Create a finding with semantic-edge evidence."""
    raw_edges = [edge.to_dict()] if edge else []
    semantic_edge = None
    if source and target:
        derived_from = [f"{edge.relationship}:{edge.source}:{edge.target}"] if edge else []
        semantic_edge = SemanticEdge(
            source=source,
            target=target,
            primitive=primitive_obj.name,
            status=status,
            confidence=confidence,
            raw_edges=raw_edges,
            derived_from=derived_from,
            evidence=evidence or {},
        )
    source_node = graph.get_node(source) if graph and source else None
    target_node = graph.get_node(target) if graph and target else None
    merged_evidence = {
        "source_name": source_node.name if source_node else None,
        "target_name": target_node.name if target_node else None,
        "source_type": str(source_node.type) if source_node else None,
        "target_type": str(target_node.type) if target_node else None,
        "raw_edge": edge.to_dict() if edge else None,
        "semantic_edge": semantic_edge.to_dict() if semantic_edge else None,
    }
    merged_evidence.update(evidence or {})
    return Finding(
        name=name,
        description=description,
        source=source,
        target=target,
        relationship=relationship,
        primitive=primitive_obj,
        result=result,
        status=status,
        confidence=confidence,
        missing_information=missing_information,
        evidence=merged_evidence,
    )
