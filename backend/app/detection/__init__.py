"""Phase 07 detection engine and Phase 08 detector plugin system."""

from app.detection.engine import DetectionEngine
from app.detection.manager import DetectorPluginManager
from app.detection.plugin import DetectorMetadata, DetectorPlugin
from app.detection.plugin_registry import DetectorPluginRegistry

__all__ = [
    "DetectionEngine",
    "DetectorMetadata",
    "DetectorPlugin",
    "DetectorPluginManager",
    "DetectorPluginRegistry",
]
