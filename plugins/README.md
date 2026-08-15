# Detection Plugins

Detector plugins live under `plugins/detectors/`.

Each detector directory contains:

```text
<plugin-id>/
├── __init__.py
└── plugin.py
```

`plugin.py` must expose:

```python
def create_plugin() -> DetectorPlugin:
    ...
```

The core system discovers detector plugins automatically. The detection
engine does not contain hard-coded imports for individual detectors.
