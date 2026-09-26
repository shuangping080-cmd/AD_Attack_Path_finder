"""Report formatters for attack path analysis."""

from __future__ import annotations

from adpath.models.path import AttackPath, PathType
from adpath.signal.hypothesis import SignalFinding


def paths_report(paths: list[AttackPath]) -> dict[str, object]:
    """Return a JSON-ready report grouped by path status."""
    confirmed = [path for path in paths if path.path_type == PathType.CONFIRMED]
    candidate = [path for path in paths if path.path_type == PathType.CANDIDATE]
    incomplete = [path for path in paths if path.path_type == PathType.INCOMPLETE]
    missing = []
    historical = []
    seen_missing = set()
    impacted_by_missing: dict[tuple[object, ...], int] = {}
    for path in paths:
        for item in path.missing_information:
            impacted_by_missing[item.key] = impacted_by_missing.get(item.key, 0) + 1
            if item.key not in seen_missing:
                seen_missing.add(item.key)
                missing.append(item.to_dict())
        historical.extend(support.to_dict() for support in path.historical_support)
    investigations = next_best_investigations(paths, impacted_by_missing)
    return {
        "confirmed_paths": [path.to_dict() for path in confirmed],
        "candidate_paths": [path.to_dict() for path in candidate],
        "incomplete_paths": [path.to_dict() for path in incomplete],
        "missing_information": missing,
        "historical_support": historical,
        "next_best_investigations": investigations,
    }


def next_best_investigations(
    paths: list[AttackPath],
    impacted_by_missing: dict[tuple[object, ...], int] | None = None,
) -> list[dict[str, object]]:
    """Rank missing information by analyst value and collection cost."""
    impacted_by_missing = impacted_by_missing or {}
    collector_cost = {
        "BloodHound": 1,
        "LDAP": 2,
        "SMB": 3,
        "Host": 4,
    }
    ranked: dict[tuple[object, ...], dict[str, object]] = {}
    for path in paths:
        historical_bonus = 1 if path.historical_support else 0
        privilege_bonus = max(path.evidence.get("score_breakdown", {}).get("confirmed_edge", 0), 0) / 2
        for item in path.missing_information:
            cost = collector_cost.get(str(item.possible_collector or item.suggested_source), 3)
            impacted_paths = impacted_by_missing.get(item.key, 1)
            priority = (
                (3 if item.blocks_path else 0)
                + int(item.importance)
                + privilege_bonus
                + historical_bonus
                + impacted_paths
                - (cost * 0.5)
            )
            current = ranked.get(item.key)
            entry = {
                **item.to_dict(),
                "priority": round(priority, 2),
                "collection_cost": cost,
                "impacted_paths": impacted_paths,
            }
            if current is None or entry["priority"] > current["priority"]:
                ranked[item.key] = entry
    return sorted(ranked.values(), key=lambda item: (-float(item["priority"]), item["collection_cost"], item["question"]))


def markdown_report(paths: list[AttackPath]) -> str:
    """Return a concise Markdown report."""
    report = paths_report(paths)
    lines = ["# Attack Path Analysis", ""]
    sections = [
        ("Confirmed Paths", report["confirmed_paths"]),
        ("Candidate Paths", report["candidate_paths"]),
        ("Incomplete Paths", report["incomplete_paths"]),
    ]
    for title, section_paths in sections:
        lines.extend([f"## {title}", ""])
        if not section_paths:
            lines.extend(["None.", ""])
            continue
        for item in section_paths:
            lines.append(f"- score={item['score']:.2f} confidence={item['confidence']:.2f}: {item['reason']}")
            for missing in item["missing_information"]:
                lines.append(f"  - Missing: {missing['question']} ({missing['possible_collector']})")
            lines.append("")
    lines.extend(["## Missing Information", ""])
    for item in report["missing_information"]:
        lines.append(f"- {item['question']} on {item['object']} [{item['importance']}]")
    lines.extend(["", "## Historical Support", ""])
    for item in report["historical_support"]:
        lines.append(f"- {item.get('machine') or item.get('pattern')}: {item.get('confidence')}")
    lines.extend(["", "## Next Best Investigations", ""])
    for item in report["next_best_investigations"]:
        lines.append(f"- priority={item['priority']}: {item['question']} on {item['object']}")
    lines.extend(["", "## Notes", ""])
    lines.append("Candidate and incomplete paths are analysis hypotheses; they do not execute or confirm exploitation.")
    return "\n".join(lines)


def signals_report(findings: list[SignalFinding]) -> dict[str, object]:
    """Return a JSON-ready interesting-signal report."""
    return {
        "foothold_candidates": [finding.to_dict() for finding in findings],
        "summary": {
            "total": len(findings),
            "hypothesis": sum(1 for item in findings if str(item.status) == "hypothesis"),
            "pattern_matched": sum(1 for item in findings if str(item.status) == "pattern_matched"),
            "confirmed": sum(1 for item in findings if str(item.status) == "confirmed"),
        },
    }


def markdown_signals_report(findings: list[SignalFinding]) -> str:
    """Return a concise Markdown report for initial foothold candidates."""
    lines = ["# Foothold Candidate Analysis", ""]
    if not findings:
        lines.extend(["No foothold candidates found.", ""])
        return "\n".join(lines)
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"## {index}. {finding.object_name}",
                "",
                f"- Type: {finding.object_type}",
                f"- Signal: {finding.signal}",
                f"- Status: {finding.status}",
                f"- Confidence: {finding.confidence}",
                f"- Risk if valid: {finding.risk_if_valid}",
                f"- Score: {finding.score:.2f}",
                "",
                "Observed Evidence:",
            ]
        )
        lines.extend(f"- {item}" for item in finding.observed_evidence)
        if finding.pattern_matches:
            lines.extend(["", "Knowledge Match:"])
            lines.extend(
                f"- {item.get('id')} ({item.get('machine')}, {item.get('primitive')})"
                for item in finding.pattern_matches
            )
        lines.extend(["", "Hypothesis:", f"- {finding.hypothesis}", "", "Suggested Validation:"])
        lines.extend(f"- `{item}`" for item in finding.suggested_validation)
        lines.extend(["", "If Valid:"])
        lines.extend(f"- {item}" for item in finding.next_steps)
        lines.append("")
    lines.append("These are validation hypotheses, not confirmed credentials or confirmed attack paths.")
    return "\n".join(lines)
