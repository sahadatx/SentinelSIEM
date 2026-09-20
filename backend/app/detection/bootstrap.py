from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.detection.engine import DetectionEngine
from app.detection.manager import DetectorPluginManager
from app.detection.plugin_registry import DetectorPluginRegistry
from app.detection.registry import DetectionRuleRegistry
from app.detection.service import DetectionService


@dataclass(slots=True)
class DetectionRuntime:
    """
    Application-scoped detection runtime.

    DetectionRuntime owns the runtime components required by the
    detection subsystem.

    Runtime topology
    ---------------

        DetectionRuleRegistry
                |
                +-----------------------+
                |                       |
                v                       v
        DetectionService        DetectionEngine


        DetectorPluginRegistry
                |
                +-----------------------+
                |                       |
                v                       v
        DetectionService        DetectionEngine


    DetectionService and DetectionEngine receive the exact same
    registry instances within the current process.

    Important
    ---------
    Detection registries are process-local runtime registries.

    FastAPI and an ingestion worker may run as separate processes.
    Those processes do not share Python memory.

    Therefore, this bootstrap provides deterministic runtime
    construction for each process, but it does not provide:

    - cross-process rule synchronization
    - persistent rule storage
    - distributed registry state

    Responsibilities
    ----------------
    - Own detection runtime components.
    - Create shared rule and plugin registries.
    - Keep service and engine registries synchronized in-process.
    - Load configured detection rules during startup.
    - Discover detector plugins during startup.
    - Initialize detector plugins during startup.

    Non-responsibilities
    --------------------
    - Does not evaluate events.
    - Does not persist detection results.
    - Does not create alerts.
    - Does not manage incidents.
    - Does not calculate risk.
    - Does not perform RBAC.
    - Does not provide distributed synchronization.
    """

    rule_registry: DetectionRuleRegistry
    plugin_registry: DetectorPluginRegistry
    detection_service: DetectionService
    detection_engine: DetectionEngine
    plugin_manager: DetectorPluginManager


def _validate_directory(
    directory: Path,
    *,
    name: str,
) -> Path:
    """
    Validate a required runtime directory.

    Parameters
    ----------
    directory:
        Directory that must exist.

    name:
        Human-readable name used in error messages.

    Returns
    -------
    Path
        The validated directory.

    Raises
    ------
    TypeError
        If directory is not a pathlib.Path.

    FileNotFoundError
        If directory does not exist.

    NotADirectoryError
        If the path exists but is not a directory.
    """

    if not isinstance(directory, Path):
        raise TypeError(
            f"{name} must be pathlib.Path",
        )

    if not directory.exists():
        raise FileNotFoundError(
            f"{name} directory does not exist: {directory}",
        )

    if not directory.is_dir():
        raise NotADirectoryError(
            f"{name} path is not a directory: {directory}",
        )

    return directory


def _validate_plugin_config(
    plugin_config: dict[str, dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """
    Validate and defensively copy detector plugin configuration.

    Plugin configuration is optional.

    The returned dictionary is independent from the caller's
    dictionary so subsequent caller-side mutation cannot alter
    runtime initialization configuration.
    """

    if plugin_config is None:
        return {}

    if not isinstance(plugin_config, dict):
        raise TypeError(
            "plugin_config must be a dictionary or None",
        )

    normalized: dict[str, dict[str, Any]] = {}

    for plugin_id, config in plugin_config.items():
        if not isinstance(plugin_id, str):
            raise TypeError(
                "plugin_config keys must be strings",
            )

        normalized_plugin_id = plugin_id.strip()

        if not normalized_plugin_id:
            raise ValueError(
                "plugin_config contains an empty plugin id",
            )

        if not isinstance(config, dict):
            raise TypeError(
                f"plugin configuration for '{normalized_plugin_id}' "
                "must be a dictionary",
            )

        normalized[normalized_plugin_id] = dict(config)

    return normalized


def build_detection_runtime(
    *,
    rules_directory: Path,
    plugins_directory: Path,
    plugin_config: dict[str, dict[str, Any]] | None = None,
) -> DetectionRuntime:
    """
    Build the complete application-scoped detection runtime.

    Construction order
    ------------------

    1. Validate runtime directories and plugin configuration.
    2. Create the shared DetectionRuleRegistry.
    3. Create the shared DetectorPluginRegistry.
    4. Create DetectionService using both registries.
    5. Load detection rules through DetectionService.
    6. Create DetectorPluginManager using the plugin registry.
    7. Discover and register detector plugins.
    8. Initialize discovered detector plugins.
    9. Create DetectionEngine using the same registries.
    10. Validate the shared-registry invariants.
    11. Return the completed DetectionRuntime.

    Shared-registry invariant
    --------------------------

    Within a single process:

        detection_service.rule_registry is rule_registry

        detection_service.plugin_registry is plugin_registry

        detection_engine.registry is rule_registry

        detection_engine.plugins is plugin_registry

    The DetectionEngine currently exposes its rule registry as
    ``registry`` and its plugin registry as ``plugins``. This
    bootstrap intentionally follows that actual engine contract.

    Event evaluation
    ----------------

    This function only constructs the runtime.

    It does not evaluate events.

    Event evaluation remains the responsibility of the caller,
    normally the ingestion/detection pipeline.

    Detection results
    -----------------

    DetectionEngine returns DetectionResult objects.

    Persistence of those results belongs to the detection storage
    repository layer.

    Alert integration
    -----------------

    Alert creation is outside this bootstrap boundary and belongs
    to the downstream alert pipeline.

    RBAC
    ----

    RBAC is intentionally not implemented here.

    Detection permissions must be enforced at the API/application
    authorization boundary.

    RBAC must not be embedded inside:

    - DetectionRuleRegistry
    - DetectorPluginRegistry
    - DetectionService
    - DetectionEvaluator
    - DetectionContext
    - DetectionResult
    - DetectionEngine
    - DetectionSuppression
    - this bootstrap
    """

    # ============================================================
    # Validate Runtime Configuration
    # ============================================================

    validated_rules_directory = _validate_directory(
        rules_directory,
        name="detection rules",
    )

    validated_plugins_directory = _validate_directory(
        plugins_directory,
        name="detector plugins",
    )

    normalized_plugin_config = _validate_plugin_config(
        plugin_config,
    )

    # ============================================================
    # Shared Detection Rule Registry
    # ============================================================

    rule_registry = DetectionRuleRegistry()

    # ============================================================
    # Shared Detector Plugin Registry
    # ============================================================

    plugin_registry = DetectorPluginRegistry()

    # ============================================================
    # Detection Service
    # ============================================================

    # DetectionService and DetectionEngine must receive the exact
    # same registry instances within this process.

    detection_service = DetectionService(
        rule_registry=rule_registry,
        plugin_registry=plugin_registry,
    )

    # ============================================================
    # Load Detection Rules
    # ============================================================

    # Rule loading goes through DetectionService so rule validation
    # and registry insertion remain inside the service boundary.

    detection_service.load_rule_directory(
        validated_rules_directory,
    )

    # ============================================================
    # Detector Plugin Manager
    # ============================================================

    plugin_manager = DetectorPluginManager(
        registry=plugin_registry,
    )

    # ============================================================
    # Discover Detector Plugins
    # ============================================================

    plugin_manager.discover_and_register(
        validated_plugins_directory,
    )

    # ============================================================
    # Initialize Detector Plugins
    # ============================================================

    plugin_manager.initialize(
        normalized_plugin_config,
    )

    # ============================================================
    # Detection Engine
    # ============================================================

    # IMPORTANT:
    #
    # Current DetectionEngine constructor is:
    #
    # DetectionEngine(
    #     registry,
    #     *,
    #     evaluator=None,
    #     suppression=None,
    #     plugin_registry=None,
    # )
    #
    # Therefore the rule registry MUST be passed as `registry=`.
    #
    # The exact same rule and plugin registry objects used by the
    # DetectionService are passed to the engine.

    detection_engine = DetectionEngine(
        registry=rule_registry,
        plugin_registry=plugin_registry,
    )

    # ============================================================
    # Runtime Invariant Checks
    # ============================================================

    # DetectionService contract
    if detection_service.rule_registry is not rule_registry:
        raise RuntimeError(
            "DetectionService is not using the runtime rule registry",
        )

    if detection_service.plugin_registry is not plugin_registry:
        raise RuntimeError(
            "DetectionService is not using the runtime plugin registry",
        )

    # DetectionEngine contract
    #
    # The current engine exposes:
    #
    #     self.registry
    #     self.plugins
    #
    # rather than:
    #
    #     self.rule_registry
    #     self.plugin_registry

    if detection_engine.registry is not rule_registry:
        raise RuntimeError(
            "DetectionEngine is not using the runtime rule registry",
        )

    if detection_engine.plugins is not plugin_registry:
        raise RuntimeError(
            "DetectionEngine is not using the runtime plugin registry",
        )

    # ============================================================
    # Final Runtime
    # ============================================================

    return DetectionRuntime(
        rule_registry=rule_registry,
        plugin_registry=plugin_registry,
        detection_service=detection_service,
        detection_engine=detection_engine,
        plugin_manager=plugin_manager,
    )


__all__ = [
    "DetectionRuntime",
    "build_detection_runtime",
]