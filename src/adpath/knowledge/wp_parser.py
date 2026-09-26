"""Local writeup text extraction adapters."""

from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import ClassVar


@dataclass(slots=True)
class ParsedWriteup:
    """Extracted text from a local writeup file."""

    source_file: Path
    text: str
    parser: str
    warnings: list[str]


class _HTMLTextParser(HTMLParser):
    """Tiny HTML-to-text parser for writeup ingestion."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if stripped:
            self.parts.append(stripped)

    def text(self) -> str:
        """Return extracted text."""
        return "\n".join(self.parts)


class WriteupParser:
    """Read local writeup files without modifying originals."""

    supported_suffixes: ClassVar[set[str]] = {".md", ".txt", ".html", ".htm", ".pdf"}

    def parse_file(self, path: Path | str) -> ParsedWriteup:
        """Parse one local writeup file."""
        source = Path(path)
        suffix = source.suffix.lower()
        if suffix not in self.supported_suffixes:
            return ParsedWriteup(source, "", "unsupported", [f"Unsupported writeup type: {suffix}"])
        if suffix == ".pdf":
            return self._parse_pdf(source)
        if suffix in {".html", ".htm"}:
            return self._parse_html(source)
        return self._parse_text(source)

    def parse_machine_dir(self, machine_dir: Path | str) -> list[ParsedWriteup]:
        """Parse all supported local files for one machine."""
        directory = Path(machine_dir)
        if not directory.exists():
            return []
        return [
            self.parse_file(path)
            for path in sorted(directory.iterdir())
            if path.is_file() and path.suffix.lower() in self.supported_suffixes
        ]

    def _parse_text(self, path: Path) -> ParsedWriteup:
        return ParsedWriteup(path, path.read_text(encoding="utf-8", errors="replace"), "text", [])

    def _parse_html(self, path: Path) -> ParsedWriteup:
        parser = _HTMLTextParser()
        parser.feed(path.read_text(encoding="utf-8", errors="replace"))
        return ParsedWriteup(path, parser.text(), "html", [])

    def _parse_pdf(self, path: Path) -> ParsedWriteup:
        return ParsedWriteup(
            path,
            "",
            "pdf",
            ["PDF parsing adapter is reserved for a future reliable extractor."],
        )
