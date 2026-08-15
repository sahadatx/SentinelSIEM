from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from app.detection.plugin import DetectorPlugin


class DetectorPluginDiscovery:
    """Discover plugins from plugins/detectors/<name>/plugin.py."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def discover(self) -> tuple[DetectorPlugin, ...]:
        if not self.root.exists():
            return ()

        plugins: list[DetectorPlugin] = []

        for directory in sorted(self.root.iterdir(), key=lambda item: item.name):
            if not directory.is_dir() or directory.name.startswith("_"):
                continue

            module_path = directory / "plugin.py"
            if not module_path.is_file():
                continue

            module = self._load_module(directory.name, module_path)
            plugins.append(self._extract_plugin(module))

        return tuple(plugins)

    @staticmethod
    def _load_module(name: str, path: Path) -> ModuleType:
        module_name = f"_siem_detector_{name}"
        spec = importlib.util.spec_from_file_location(module_name, path)

        if spec is None or spec.loader is None:
            raise ValueError(f"unable to load detector plugin: {path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _extract_plugin(module: ModuleType) -> DetectorPlugin:
        factory = getattr(module, "create_plugin", None)

        if factory is None or not callable(factory):
            raise ValueError("detector plugin must expose create_plugin()")

        plugin = factory()

        if not isinstance(plugin, DetectorPlugin):
            raise TypeError("create_plugin() must return DetectorPlugin")

        return plugin
