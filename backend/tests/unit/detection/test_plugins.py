from __future__ import annotations

from pathlib import Path

import pytest

from app.detection.discovery import DetectorPluginDiscovery
from app.detection.manager import DetectorPluginManager
from app.detection.plugin import DetectorMetadata, DetectorPlugin
from app.detection.plugin_registry import DetectorPluginRegistry


class DummyPlugin(DetectorPlugin):
    metadata = DetectorMetadata(
        id="dummy-plugin",
        name="Dummy Plugin",
        version="1.0.0",
        description="Test plugin.",
    )

    def initialize(self, config=None) -> None:
        self.config = dict(config or {})

    def detect(self, event):
        return ()


def test_registry_rejects_duplicate_plugin() -> None:
    registry = DetectorPluginRegistry()
    registry.register(DummyPlugin())

    with pytest.raises(ValueError, match="duplicate detector plugin"):
        registry.register(DummyPlugin())


def test_registry_enable_disable() -> None:
    registry = DetectorPluginRegistry()
    registry.register(DummyPlugin())

    assert len(registry.enabled()) == 1

    registry.set_enabled("dummy-plugin", False)

    assert registry.enabled() == ()


def test_registry_initializes_configuration() -> None:
    registry = DetectorPluginRegistry()
    plugin = DummyPlugin()
    registry.register(plugin)

    registry.initialize({"dummy-plugin": {"threshold": 3}})

    assert plugin.config == {"threshold": 3}


def test_discovery_finds_detector_plugins() -> None:
    plugins = DetectorPluginDiscovery(Path("plugins/detectors")).discover()
    ids = {plugin.metadata.id for plugin in plugins}

    assert {
        "brute-force-plugin",
        "port-scan-plugin",
        "suspicious-login-plugin",
        "web-attack-plugin",
        "privilege-escalation-plugin",
        "malware-indicator-plugin",
    } <= ids


def test_manager_discovers_and_registers_plugins() -> None:
    manager = DetectorPluginManager()

    count = manager.discover_and_register(Path("plugins/detectors"))

    assert count == 6
    assert len(manager.registry.all()) == 6


def test_discovery_rejects_invalid_factory(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "broken"
    plugin_dir.mkdir()

    (plugin_dir / "plugin.py").write_text(
        "def create_plugin():\n"
        "    return object()\n",
        encoding="utf-8",
    )

    with pytest.raises(TypeError, match="DetectorPlugin"):
        DetectorPluginDiscovery(tmp_path).discover()


def test_metadata_rejects_empty_required_fields() -> None:
    with pytest.raises(ValueError):
        DetectorMetadata(
            id="",
            name="Test",
            version="1.0.0",
            description="Test",
        )
