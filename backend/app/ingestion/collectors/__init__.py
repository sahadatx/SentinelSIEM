"""Collector contracts and registry."""

from app.ingestion.collectors.base import Collector
from app.ingestion.collectors.registry import CollectorRegistry

__all__ = ["Collector", "CollectorRegistry"]
