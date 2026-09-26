"""Smoke tests for knowledge-base pipeline imports."""

from adpath.knowledge import (
    KnowledgeBaseLoader,
    KnowledgeBaseValidator,
    MachineRecordNormalizer,
    WriteupExtractor,
    WriteupParser,
)


def test_knowledge_pipeline_imports() -> None:
    """Knowledge pipeline classes can be imported."""
    assert KnowledgeBaseLoader
    assert KnowledgeBaseValidator
    assert MachineRecordNormalizer
    assert WriteupExtractor
    assert WriteupParser
