"""Load AD attack path knowledge-base YAML files."""

from pathlib import Path
from typing import Any, ClassVar

import yaml


class KnowledgeBaseLoader:
    """Load machine records, dictionaries, and pattern definitions from disk."""

    STRONG_REVIEW_STATUSES: ClassVar[set[str]] = {"reviewed"}
    CANDIDATE_REVIEW_STATUSES: ClassVar[set[str]] = {"reviewed", "normalized"}
    EXCLUDED_REVIEW_STATUSES: ClassVar[set[str]] = {"raw", "extracted", "rejected"}

    def __init__(self, root: Path | str = "knowledge-base") -> None:
        self.root = Path(root)

    def load_yaml(self, path: Path | str) -> Any:
        """Load one YAML file."""
        with Path(path).open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    def load_yaml_dir(self, relative_dir: str) -> dict[str, Any]:
        """Load all YAML files in a knowledge-base subdirectory keyed by filename stem."""
        directory = self.root / relative_dir
        if not directory.exists():
            return {}
        return {
            path.stem: self.load_yaml(path)
            for path in sorted(directory.glob("*.yaml"))
        }

    def machines(self) -> dict[str, Any]:
        """Load normalized and reviewed machine records, with reviewed records overriding."""
        machines = self.load_yaml_dir("htb/normalized")
        machines.update(self.load_yaml_dir("htb/reviewed"))
        return machines

    def normalized_machines(self) -> dict[str, Any]:
        """Load normalized machine records."""
        return self.load_yaml_dir("htb/normalized")

    def reviewed_machine_records(self) -> dict[str, Any]:
        """Load records from the explicit reviewed directory."""
        return self.load_yaml_dir("htb/reviewed")

    def load_reviewed_machines(self) -> dict[str, Any]:
        """Load only manually reviewed machine records."""
        return self._filter_machines(self.STRONG_REVIEW_STATUSES)

    def load_candidate_machines(self, include_normalized: bool = True) -> dict[str, Any]:
        """Load machine records allowed to support candidate paths."""
        statuses = self.CANDIDATE_REVIEW_STATUSES if include_normalized else self.STRONG_REVIEW_STATUSES
        return self._filter_machines(statuses)

    def review_status(self, record: dict[str, Any]) -> str:
        """Return the normalized review status for a machine record."""
        status = str(record.get("review_status") or "normalized").casefold()
        if status.startswith("reviewed"):
            return "reviewed"
        if status.startswith("normalized"):
            return "normalized"
        if status.startswith("raw"):
            return "raw"
        if status.startswith("extracted") or "auto_extracted" in status:
            return "extracted"
        if status.startswith("rejected"):
            return "rejected"
        return "normalized"

    def _filter_machines(self, allowed_statuses: set[str]) -> dict[str, Any]:
        machines = self.machines()
        return {
            key: record
            for key, record in machines.items()
            if self.review_status(record) in allowed_statuses
        }

    def primitives(self) -> dict[str, Any]:
        """Load primitive dictionary entries."""
        return self.load_yaml_dir("primitives")

    def relationships(self) -> dict[str, Any]:
        """Load relationship dictionary entries."""
        return self.load_yaml_dir("relationships")

    def attack_patterns(self) -> dict[str, Any]:
        """Load attack pattern entries."""
        return self.load_yaml_dir("attack-patterns")

    def pattern_cards(self) -> dict[str, Any]:
        """Load interesting-object pattern cards."""
        return self.load_yaml_dir("pattern-cards")
