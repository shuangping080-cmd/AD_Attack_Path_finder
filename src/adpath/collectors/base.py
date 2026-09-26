"""Base collector interfaces."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class CollectionResult:
    """Metadata returned by a collector before parser normalization."""

    source: str
    files: list[Path] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseCollector(ABC):
    """Abstract analysis-only collector interface."""

    name: str

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Return collected file references or metadata without executing attack actions."""
