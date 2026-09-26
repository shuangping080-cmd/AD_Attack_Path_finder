"""Collector interfaces and implementations."""

from adpath.collectors.base import BaseCollector, CollectionResult
from adpath.collectors.bloodhound import BloodHoundCollector

__all__ = ["BaseCollector", "BloodHoundCollector", "CollectionResult"]
