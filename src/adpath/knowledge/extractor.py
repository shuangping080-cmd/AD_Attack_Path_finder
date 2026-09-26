"""First-pass writeup extraction interfaces."""

from dataclasses import dataclass, field

from adpath.knowledge.wp_parser import ParsedWriteup


@dataclass(slots=True)
class ExtractionResult:
    """Unreviewed extraction output derived from writeup text."""

    machine: str
    entities: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    attack_primitives: list[dict] = field(default_factory=list)
    attack_chain: list[dict] = field(default_factory=list)
    missing_information: list[dict] = field(default_factory=list)
    bloodhound_semantic_gaps: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class WriteupExtractor:
    """Interface for evidence-backed extraction from writeup text.

    This class intentionally does not infer facts. Future LLM-assisted extraction
    must keep every conclusion tied to source writeup evidence.
    """

    def extract(self, machine: str, writeups: list[ParsedWriteup]) -> ExtractionResult:
        """Return empty extraction if no reviewed extractor is configured."""
        warnings = []
        if not writeups:
            warnings.append("No local writeup files found.")
        for writeup in writeups:
            warnings.extend(writeup.warnings)
        return ExtractionResult(machine=machine, warnings=warnings)
