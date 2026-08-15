"""Log collection and ingestion foundations."""

from app.ingestion.manager import IngestionManager
from app.ingestion.pipeline import IngestionPipeline

__all__ = ["IngestionManager", "IngestionPipeline"]
