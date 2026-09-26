"""Normalize extracted HTB machine knowledge records."""

from typing import Any

from adpath.knowledge.extractor import ExtractionResult


class MachineRecordNormalizer:
    """Create schema-shaped machine records from extraction output."""

    def normalize(self, extraction: ExtractionResult, status: str = "draft") -> dict[str, Any]:
        """Return a machine YAML-compatible dictionary."""
        return {
            "machine": {
                "name": extraction.machine,
                "platform": "Windows",
                "environment": "ActiveDirectory",
                "difficulty": "unknown",
            },
            "domain": {"name": None, "forest": None, "trusts": []},
            "initial_access": {"type": None, "identity": None, "source": None, "notes": None},
            "entities": extraction.entities,
            "relationships": extraction.relationships,
            "attack_primitives": extraction.attack_primitives,
            "attack_chain": extraction.attack_chain,
            "privilege_transitions": [],
            "credential_transitions": [],
            "missing_information": extraction.missing_information,
            "bloodhound_visible": [],
            "bloodhound_semantic_gaps": extraction.bloodhound_semantic_gaps,
            "tags": [],
            "sources": [],
            "confidence": "unknown",
            "review_status": status,
        }
