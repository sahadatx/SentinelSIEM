from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pathlib import Path

from app.core.metrics import REGISTRY

from app.detection.plugin import DetectorPlugin
from app.detection.plugin_registry import DetectorPluginRegistry
from app.detection.registry import DetectionRuleRegistry
from app.detection.result import DetectionResult
from app.detection.rules.loader import DetectionRuleLoader
from app.detection.rules.validator import DetectionRuleValidator
from app.detection.schema import DetectionRule


# ============================================================================
# Metric names
# ============================================================================

DETECTION_EVALUATIONS_METRIC = (
    "siem_detection_evaluations_total"
)

DETECTION_MATCHES_METRIC = (
    "siem_detection_matches_total"
)

DETECTION_SUPPRESSED_METRIC = (
    "siem_detection_suppressed_total"
)

DETECTION_FAILURES_METRIC = (
    "siem_detection_failures_total"
)

PLUGIN_EVALUATIONS_METRIC = (
    "siem_detector_plugin_evaluations_total"
)

PLUGIN_FAILURES_METRIC = (
    "siem_detector_plugin_failures_total"
)


# ============================================================================
# Detection Statistics
# ============================================================================


@dataclass(frozen=True, slots=True)
class DetectionStatistics:
    """
    Immutable read-only statistics for the Detection subsystem.

    Rule and plugin counts represent the current runtime registries.

    Detection/plugin activity counters are read from the shared application
    metrics registry.

    Alert counts are intentionally excluded because alert lifecycle belongs
    to the Alert subsystem.
    """

    total_rules: int
    enabled_rules: int
    disabled_rules: int

    total_plugins: int
    enabled_plugins: int

    total_evaluations: int
    detection_matches: int
    suppressed_matches: int
    evaluation_failures: int

    plugin_evaluations: int
    plugin_failures: int

    @property
    def active_rules(self) -> int:
        """
        Return the number of currently enabled rules.
        """
        return self.enabled_rules

    @property
    def failures(self) -> int:
        """
        Return DetectionEngine-level failures.

        Plugin failures remain separately available through
        ``plugin_failures``.
        """
        return self.evaluation_failures


# ============================================================================
# Detection Service
# ============================================================================


class DetectionService:
    """
    Application/service layer for Detection operations.

    Responsibilities
    ----------------
    - Validate detection rules.
    - Create, update, enable, disable, and delete runtime rules.
    - Load rules from YAML files/directories.
    - Manage detector plugin registrations.
    - Validate DetectionResult objects at the service boundary.
    - Provide read-only runtime rule/plugin access.
    - Expose Detection subsystem statistics.

    Non-responsibilities
    --------------------
    - Does not evaluate security events.
    - Does not create alerts.
    - Does not calculate risk.
    - Does not persist DetectionResult objects.
    - Does not manage alert lifecycle.
    - Does not publish realtime events.
    - Does not perform RBAC.

    RBAC is enforced by the API/service authorization boundary.

    Runtime persistence synchronization is intentionally kept outside the
    in-memory registry. A dedicated rule repository can be integrated above
    or alongside this service without changing DetectionEngine.
    """

    def __init__(
        self,
        *,
        rule_registry: DetectionRuleRegistry | None = None,
        plugin_registry: DetectorPluginRegistry | None = None,
        validator: DetectionRuleValidator | None = None,
        loader: DetectionRuleLoader | None = None,
    ) -> None:
        """
        Initialize the Detection service.

        The supplied registries are preserved so DetectionService and
        DetectionEngine can share the same application-scoped runtime state.
        """

        self.rule_registry = (
            rule_registry
            if rule_registry is not None
            else DetectionRuleRegistry()
        )

        self.plugin_registry = (
            plugin_registry
            if plugin_registry is not None
            else DetectorPluginRegistry()
        )

        self.validator = (
            validator
            if validator is not None
            else DetectionRuleValidator()
        )

        self.loader = (
            loader
            if loader is not None
            else DetectionRuleLoader(
                self.validator,
            )
        )

    # ========================================================================
    # Detection Rules
    # ========================================================================

    def list_rules(
        self,
    ) -> tuple[DetectionRule, ...]:
        """
        Return all registered detection rules.
        """
        return self.rule_registry.all()

    def list_enabled_rules(
        self,
    ) -> tuple[DetectionRule, ...]:
        """
        Return only enabled detection rules.
        """
        return self.rule_registry.enabled()

    def list_disabled_rules(
        self,
    ) -> tuple[DetectionRule, ...]:
        """
        Return only disabled detection rules.
        """
        return self.rule_registry.disabled()

    def get_rule(
        self,
        rule_id: str,
    ) -> DetectionRule | None:
        """
        Return a detection rule by ID.

        Returns None when the rule does not exist.
        """
        normalized_id = self._normalize_rule_id(
            rule_id,
        )

        return self.rule_registry.get(
            normalized_id,
        )

    def create_rule(
        self,
        rule: DetectionRule,
    ) -> DetectionRule:
        """
        Validate and register a new detection rule.

        Raises
        ------
        TypeError
            If the supplied object is not a DetectionRule.

        ValueError
            If the rule is invalid or already exists.
        """
        self._validate_rule(
            rule,
        )

        self.validator.validate(
            rule,
        )

        self.rule_registry.register(
            rule,
        )

        return rule

    def update_rule(
        self,
        rule: DetectionRule,
    ) -> DetectionRule:
        """
        Validate and replace an existing detection rule.

        The rule ID cannot be changed through this operation because the
        DetectionRule object itself contains the canonical identifier.

        Raises
        ------
        KeyError
            If the rule does not exist.

        ValueError
            If the rule is invalid.
        """
        self._validate_rule(
            rule,
        )

        self.validator.validate(
            rule,
        )

        normalized_id = self._normalize_rule_id(
            rule.id,
        )

        if not self.rule_registry.contains(
            normalized_id,
        ):
            raise KeyError(
                f"unknown detection rule: {normalized_id}",
            )

        self.rule_registry.replace(
            rule,
        )

        return rule

    def delete_rule(
        self,
        rule_id: str,
    ) -> DetectionRule:
        """
        Remove and return a detection rule.

        Raises KeyError when the rule does not exist.
        """
        normalized_id = self._normalize_rule_id(
            rule_id,
        )

        return self.rule_registry.remove(
            normalized_id,
        )

    def enable_rule(
        self,
        rule_id: str,
    ) -> DetectionRule:
        """
        Enable one detection rule.
        """
        return self.set_rule_enabled(
            rule_id,
            True,
        )

    def disable_rule(
        self,
        rule_id: str,
    ) -> DetectionRule:
        """
        Disable one detection rule.
        """
        return self.set_rule_enabled(
            rule_id,
            False,
        )

    def set_rule_enabled(
        self,
        rule_id: str,
        enabled: bool,
    ) -> DetectionRule:
        """
        Enable or disable a detection rule.

        DetectionRule is treated as immutable at the service boundary.
        A new validated model instance is therefore created and placed into
        the runtime registry.
        """
        normalized_id = self._normalize_rule_id(
            rule_id,
        )

        existing = self.rule_registry.get(
            normalized_id,
        )

        if existing is None:
            raise KeyError(
                f"unknown detection rule: {normalized_id}",
            )

        updated = existing.model_copy(
            update={
                "enabled": bool(enabled),
            },
        )

        self.validator.validate(
            updated,
        )

        self.rule_registry.replace(
            updated,
        )

        return updated

    # ========================================================================
    # Rule Loading
    # ========================================================================

    def load_rule_file(
        self,
        path: Path,
    ) -> DetectionRule:
        """
        Load, validate, and register one YAML detection rule.

        Duplicate rule IDs are rejected by the runtime registry.
        """
        rule = self.loader.load_file(
            path,
        )

        self._validate_rule(
            rule,
        )

        self.validator.validate(
            rule,
        )

        self.rule_registry.register(
            rule,
        )

        return rule

    def load_rule_directory(
        self,
        directory: Path,
    ) -> tuple[DetectionRule, ...]:
        """
        Load, validate, and register all YAML detection rules from a
        directory.

        Duplicate IDs are rejected by the runtime registry.
        """
        rules = self.loader.load_directory(
            directory,
        )

        validated_rules: list[DetectionRule] = []

        for rule in rules:
            self._validate_rule(
                rule,
            )

            self.validator.validate(
                rule,
            )

            validated_rules.append(
                rule,
            )

        self.rule_registry.register_many(
            validated_rules,
        )

        return tuple(
            validated_rules,
        )

    # ========================================================================
    # Rule Statistics
    # ========================================================================

    def total_rules(self) -> int:
        """
        Return the total number of registered rules.
        """
        return self.rule_registry.count()

    def enabled_rule_count(self) -> int:
        """
        Return the number of enabled detection rules.
        """
        return self.rule_registry.enabled_count()

    def disabled_rule_count(self) -> int:
        """
        Return the number of disabled detection rules.
        """
        return self.rule_registry.disabled_count()

    # ========================================================================
    # Detection Results
    # ========================================================================

    @staticmethod
    def handle_result(
        result: DetectionResult,
    ) -> DetectionResult:
        """
        Validate and return one DetectionResult.

        The DetectionService does not persist, transform, or publish the
        result. Downstream persistence/Alert integration remains separate.
        """
        if not isinstance(
            result,
            DetectionResult,
        ):
            raise TypeError(
                "detection result handler requires DetectionResult",
            )

        return result

    @staticmethod
    def handle_results(
        results: Iterable[DetectionResult],
    ) -> tuple[DetectionResult, ...]:
        """
        Validate and return multiple DetectionResult objects.

        Input ordering is preserved.
        """
        handled: list[DetectionResult] = []

        for result in results:
            handled.append(
                DetectionService.handle_result(
                    result,
                ),
            )

        return tuple(
            handled,
        )

    # ========================================================================
    # Detector Plugins
    # ========================================================================

    def list_plugins(
        self,
    ) -> tuple[DetectorPlugin, ...]:
        """
        Return all registered detector plugins.
        """
        return self.plugin_registry.all()

    def list_enabled_plugins(
        self,
    ) -> tuple[DetectorPlugin, ...]:
        """
        Return only enabled detector plugins.
        """
        return self.plugin_registry.enabled()

    def get_plugin(
        self,
        plugin_id: str,
    ) -> DetectorPlugin | None:
        """
        Return a detector plugin by ID.
        """
        normalized_id = self._normalize_plugin_id(
            plugin_id,
        )

        return self.plugin_registry.get(
            normalized_id,
        )

    def set_plugin_enabled(
        self,
        plugin_id: str,
        enabled: bool,
    ) -> None:
        """
        Enable or disable a detector plugin.
        """
        normalized_id = self._normalize_plugin_id(
            plugin_id,
        )

        self.plugin_registry.set_enabled(
            normalized_id,
            bool(enabled),
        )

    def enable_plugin(
        self,
        plugin_id: str,
    ) -> None:
        """
        Enable a detector plugin.
        """
        self.set_plugin_enabled(
            plugin_id,
            True,
        )

    def disable_plugin(
        self,
        plugin_id: str,
    ) -> None:
        """
        Disable a detector plugin.
        """
        self.set_plugin_enabled(
            plugin_id,
            False,
        )

    def plugin_count(self) -> int:
        """
        Return the total number of registered detector plugins.
        """
        return self.plugin_registry.count()

    def enabled_plugin_count(self) -> int:
        """
        Return the number of enabled detector plugins.
        """
        return self.plugin_registry.enabled_count()

    # ========================================================================
    # Metrics
    # ========================================================================

    @staticmethod
    def _metric_value(
        metric_name: str,
    ) -> int:
        """
        Return the aggregated value of a metric from the shared registry.

        Multiple labelled samples are summed so metrics can safely acquire
        bounded labels without changing service-level statistics semantics.
        """
        total = 0.0

        for sample in REGISTRY.snapshot():
            if sample.name != metric_name:
                continue

            total += float(
                sample.value,
            )

        return max(
            0,
            int(total),
        )

    def detection_evaluations(self) -> int:
        """
        Return the number of DetectionEngine event evaluations.
        """
        return self._metric_value(
            DETECTION_EVALUATIONS_METRIC,
        )

    def detection_matches(self) -> int:
        """
        Return the number of detection results counted by the DetectionEngine.
        """
        return self._metric_value(
            DETECTION_MATCHES_METRIC,
        )

    def detection_suppressed(self) -> int:
        """
        Return the number of detection matches suppressed by duplicate
        suppression.
        """
        return self._metric_value(
            DETECTION_SUPPRESSED_METRIC,
        )

    def detection_failures(self) -> int:
        """
        Return the number of DetectionEngine-level evaluation failures.
        """
        return self._metric_value(
            DETECTION_FAILURES_METRIC,
        )

    def plugin_evaluations(self) -> int:
        """
        Return the number of detector plugin evaluations.
        """
        return self._metric_value(
            PLUGIN_EVALUATIONS_METRIC,
        )

    def plugin_failures(self) -> int:
        """
        Return the number of detector plugin failures.
        """
        return self._metric_value(
            PLUGIN_FAILURES_METRIC,
        )

    # ========================================================================
    # Combined Statistics
    # ========================================================================

    def statistics(self) -> DetectionStatistics:
        """
        Return the canonical Detection subsystem statistics.
        """
        total_rules = self.total_rules()
        enabled_rules = self.enabled_rule_count()

        return DetectionStatistics(
            total_rules=total_rules,
            enabled_rules=enabled_rules,
            disabled_rules=(
                total_rules - enabled_rules
            ),
            total_plugins=self.plugin_count(),
            enabled_plugins=self.enabled_plugin_count(),
            total_evaluations=self.detection_evaluations(),
            detection_matches=self.detection_matches(),
            suppressed_matches=self.detection_suppressed(),
            evaluation_failures=self.detection_failures(),
            plugin_evaluations=self.plugin_evaluations(),
            plugin_failures=self.plugin_failures(),
        )

    def summary(self) -> dict[str, int]:
        """
        Return a backward-compatible dictionary representation of
        DetectionStatistics.

        This method is retained for existing API consumers while
        ``statistics()`` remains the canonical typed representation.
        """
        statistics = self.statistics()

        return {
            "total_rules": statistics.total_rules,
            "enabled_rules": statistics.enabled_rules,
            "disabled_rules": statistics.disabled_rules,
            "total_plugins": statistics.total_plugins,
            "enabled_plugins": statistics.enabled_plugins,
            "active_rules": statistics.active_rules,
            "total_evaluations": statistics.total_evaluations,
            "detection_matches": statistics.detection_matches,
            "suppressed_matches": statistics.suppressed_matches,
            "evaluation_failures": statistics.evaluation_failures,
            "plugin_evaluations": statistics.plugin_evaluations,
            "plugin_failures": statistics.plugin_failures,
            "failures": statistics.failures,
        }

    # ========================================================================
    # Bulk Operations
    # ========================================================================

    def register_rules(
        self,
        rules: Iterable[DetectionRule],
    ) -> tuple[DetectionRule, ...]:
        """
        Validate and register multiple detection rules.

        The registry performs duplicate protection for the complete batch.
        """
        normalized_rules: list[DetectionRule] = []

        for rule in rules:
            self._validate_rule(
                rule,
            )

            self.validator.validate(
                rule,
            )

            normalized_rules.append(
                rule,
            )

        self.rule_registry.register_many(
            normalized_rules,
        )

        return tuple(
            normalized_rules,
        )

    def replace_rules(
        self,
        rules: Iterable[DetectionRule],
    ) -> tuple[DetectionRule, ...]:
        """
        Validate and replace/register multiple detection rules.
        """
        normalized_rules: list[DetectionRule] = []

        for rule in rules:
            self._validate_rule(
                rule,
            )

            self.validator.validate(
                rule,
            )

            normalized_rules.append(
                rule,
            )

        self.rule_registry.replace_many(
            normalized_rules,
        )

        return tuple(
            normalized_rules,
        )

    def clear_rules(self) -> None:
        """
        Clear all runtime detection rules.

        Intended for controlled startup and test lifecycle operations.
        """
        self.rule_registry.clear()

    def clear_plugins(self) -> None:
        """
        Clear all registered detector plugins.

        Intended for controlled startup and test lifecycle operations.
        """
        self.plugin_registry.clear()

    # ========================================================================
    # Internal Validation
    # ========================================================================

    @staticmethod
    def _validate_rule(
        rule: DetectionRule,
    ) -> None:
        """
        Ensure the service receives a DetectionRule instance.
        """
        if not isinstance(
            rule,
            DetectionRule,
        ):
            raise TypeError(
                "detection service expects DetectionRule",
            )

    @staticmethod
    def _normalize_rule_id(
        rule_id: str,
    ) -> str:
        """
        Normalize and validate a detection rule ID.
        """
        if not isinstance(
            rule_id,
            str,
        ):
            raise ValueError(
                "detection rule ID must be a string",
            )

        normalized = rule_id.strip()

        if not normalized:
            raise ValueError(
                "detection rule ID must not be empty",
            )

        return normalized

    @staticmethod
    def _normalize_plugin_id(
        plugin_id: str,
    ) -> str:
        """
        Normalize and validate a detector plugin ID.
        """
        if not isinstance(
            plugin_id,
            str,
        ):
            raise ValueError(
                "detector plugin ID must be a string",
            )

        normalized = plugin_id.strip()

        if not normalized:
            raise ValueError(
                "detector plugin ID must not be empty",
            )

        return normalized


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "DetectionService",
    "DetectionStatistics",
    "DETECTION_EVALUATIONS_METRIC",
    "DETECTION_MATCHES_METRIC",
    "DETECTION_SUPPRESSED_METRIC",
    "DETECTION_FAILURES_METRIC",
    "PLUGIN_EVALUATIONS_METRIC",
    "PLUGIN_FAILURES_METRIC",
]