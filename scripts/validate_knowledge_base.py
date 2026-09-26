"""Validate the AD Attack Path knowledge base."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from adpath.knowledge.validator import KnowledgeBaseValidator


def main() -> int:
    """Run validation and print a concise report."""
    validator = KnowledgeBaseValidator(PROJECT_ROOT / "knowledge-base")
    issues = validator.validate()
    if not issues:
        print("Knowledge base validation passed.")
        return 0

    for issue in issues:
        machine = issue.machine or "-"
        print(f"{issue.severity.upper()} [{machine}] {issue.message}")
    return 1 if any(issue.severity == "error" for issue in issues) else 0


if __name__ == "__main__":
    raise SystemExit(main())
