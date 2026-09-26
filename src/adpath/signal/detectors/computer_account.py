"""Computer-account signal detector."""

from __future__ import annotations

import re
from pathlib import Path

from adpath.graph import ADGraph
from adpath.models.edge import Edge
from adpath.models.node import Node
from adpath.signal.hypothesis import SignalFinding, SignalStatus
from adpath.signal.knowledge_trigger import KnowledgeTriggerEngine

HOSTNAME_PATTERN = re.compile(r"^(?:FS|WEB|SQL|BACKUP|CA|DC|SRV|APP|DB)\d{1,3}$", re.IGNORECASE)


class ComputerAccountSignalDetector:
    """Find computer objects that are worth validating as possible footholds."""

    def __init__(self, knowledge_base: Path | str = "knowledge-base", dc: str | None = None) -> None:
        self.knowledge = KnowledgeTriggerEngine(knowledge_base)
        self.dc = dc or "<dc>"

    def detect_graph(self, graph: ADGraph) -> list[SignalFinding]:
        """Return interesting computer-account signals."""
        findings: list[SignalFinding] = []
        for node in graph.nodes:
            if str(node.type).casefold() != "computer":
                continue
            signal = self._computer_signal(graph, node)
            if signal is not None:
                findings.append(signal)
        return findings

    def _computer_signal(self, graph: ADGraph, node: Node) -> SignalFinding | None:
        sam = str(node.properties.get("samaccountname") or node.name.split("@", 1)[0])
        if not sam.endswith("$"):
            return None
        hostname = sam.rstrip("$")
        hostname_lower = hostname.lower()
        relationships = [*graph.out_edges(node.id), *graph.in_edges(node.id)]
        observed = [
            f"Computer object exists: {node.name}",
            "Account name follows machine account format",
            f"Hostname candidate: {hostname}",
        ]
        score = 2.0
        if HOSTNAME_PATTERN.match(hostname):
            observed.append("Name matches common hostname/service pattern")
            score += 1.5
        if node.properties.get("enabled") is True:
            observed.append("Account is enabled")
            score += 0.5
        if node.properties.get("serviceprincipalnames"):
            observed.append("Computer has HOST/RestrictedKrbHost SPNs")
            score += 0.5
        pre2k_member = self._has_pre2k_membership(graph, node, relationships)
        if pre2k_member:
            observed.append("Computer is related to Pre-Windows 2000 Compatible Access")
            score += 1.5
        pattern_matches = [
            card.to_match(node, pattern_score)
            for card, pattern_score in self.knowledge.matches_for_object(node, relationships=relationships)
        ]
        if pattern_matches:
            score += max(float(item["score"]) for item in pattern_matches)
            status = SignalStatus.PATTERN_MATCHED
        else:
            status = SignalStatus.HYPOTHESIS
        command = self._validation_command(node, hostname, hostname_lower)
        return SignalFinding.for_node(
            node,
            "Computer account foothold candidate",
            "Computer account may use lowercase hostname as an initial password; validation is required.",
            status=status,
            confidence="medium" if score >= 5 else "low",
            risk_if_valid="initial foothold",
            score=score,
            observed_evidence=observed,
            pattern_matches=pattern_matches,
            suggested_validation=[command],
            next_steps=[
                f"If valid, mark {node.name} as a controlled principal.",
                "Re-run LDAP/BloodHound collection with the validated identity.",
                "Expand candidate paths from the controlled principal.",
                "Check ACL, delegation, RBCD, ADCS, gMSA, dMSA, SPN, and session visibility.",
            ],
            metadata={
                "username_candidate": sam,
                "password_candidate": hostname_lower,
                "hostname": hostname,
                "pre2k_related": pre2k_member,
            },
        )

    def _validation_command(self, node: Node, hostname: str, hostname_lower: str) -> str:
        domain = (node.domain or node.name.split("@", 1)[-1]).lower()
        return f"netexec ldap {self.dc} -d {domain} -u '{hostname}$' -p '{hostname_lower}' -k"

    def _has_pre2k_membership(self, graph: ADGraph, node: Node, relationships: list[Edge]) -> bool:
        for edge in relationships:
            target = graph.get_node(edge.target)
            source = graph.get_node(edge.source)
            names = [target.name if target else "", source.name if source else ""]
            if any("PRE-WINDOWS 2000 COMPATIBLE ACCESS" in name.upper() for name in names):
                return True
        return False
