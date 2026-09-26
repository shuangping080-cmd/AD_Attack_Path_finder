"""BloodHound data collector placeholder."""

from pathlib import Path

from adpath.collectors.base import BaseCollector, CollectionResult


class BloodHoundCollector(BaseCollector):
    """Accept existing BloodHound.py or SharpHound exports for parser handoff.

    This collector does not perform LDAP collection and does not execute attack behavior.
    """

    name = "bloodhound"

    def __init__(self, input_dir: Path | str) -> None:
        self.input_dir = Path(input_dir)

    def collect(self) -> CollectionResult:
        """Return candidate BloodHound JSON files from the configured input directory."""
        # TODO: Add stricter file classification for BloodHound and SharpHound export types.
        files = sorted(self.input_dir.glob("*.json")) if self.input_dir.exists() else []
        return CollectionResult(source=self.name, files=files, metadata={"input_dir": self.input_dir})
