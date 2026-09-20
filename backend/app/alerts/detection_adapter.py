from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from uuid import UUID

from app.alerts.models import AlertCreate, AlertSeverity, AlertSourceType
from app.detection.result import DetectionResult


@dataclass(frozen=True, slots=True)
class DetectionAlertAdapter:
    """
    Converts DetectionResult objects into AlertCreate objects.

    Responsibility:
        DetectionResult -> AlertCreate

    This adapter is intentionally kept outside DetectionEngine so that
    detection evaluation remains independent from alert management.
    """

    default_priority: str = "medium"

    def to_alert(self, result: DetectionResult) -> AlertCreate:
        """
        Convert one DetectionResult into an AlertCreate.

        The resulting AlertCreate contains all information required by the
        alert lifecycle, deduplication, persistence, and analyst-facing APIs.
        """

        if not isinstance(result, DetectionResult):
            raise TypeError(
                "DetectionAlertAdapter expects DetectionResult"
            )

        severity = self._resolve_severity(result.severity)
        priority = self._resolve_priority(
            severity=severity,
            risk_score=self._calculate_risk_score(result),
        )

        risk_score = self._calculate_risk_score(result)

        return AlertCreate(
            source_type=AlertSourceType.DETECTION,
            source_id=str(result.detection_id),
            rule_id=result.rule_id,
            title=self._build_title(result),
            description=self._build_description(result),
            severity=severity,
            risk_score=risk_score,
            priority=priority,
            evidence_ids=(str(result.event_id),),
            asset_id=self._extract_asset_id(result),
            user_id=self._extract_user_id(result),
            deduplication_key=self._build_deduplication_key(result),
        )

    def to_alerts(
        self,
        results: tuple[DetectionResult, ...] | list[DetectionResult],
    ) -> tuple[AlertCreate, ...]:
        """
        Convert multiple DetectionResult objects into AlertCreate objects.
        """

        return tuple(
            self.to_alert(result)
            for result in results
        )

    def _build_title(self, result: DetectionResult) -> str:
        """
        Build the analyst-facing alert title.

        Prefer the detection rule name because it is more meaningful than
        exposing an internal detection UUID in the alert queue.
        """

        rule_name = result.rule_name.strip()

        if rule_name:
            return f"Detection: {rule_name}"

        return f"Detection: {result.rule_id}"

    def _build_description(self, result: DetectionResult) -> str:
        """
        Build the alert description from the detection result.

        DetectionResult.description is already the authoritative description
        produced by the detection layer, so it is preserved rather than
        regenerated here.
        """

        description = result.description.strip()

        if description:
            return description

        return (
            f"Detection rule {result.rule_id} matched event "
            f"{result.event_id}."
        )

    def _resolve_severity(self, value: str) -> AlertSeverity:
        """
        Convert detection severity into the canonical AlertSeverity enum.
        """

        normalized = str(value).strip().lower()

        try:
            return AlertSeverity(normalized)
        except ValueError:
            return AlertSeverity.MEDIUM

    def _calculate_risk_score(self, result: DetectionResult) -> float:
        """
        Determine the alert risk score from detection severity.

        DetectionResult currently does not contain a dedicated risk_score,
        therefore the adapter provides the centralized mapping.

        Mapping:
            info     -> 10
            low      -> 25
            medium   -> 50
            high     -> 80
            critical -> 100
        """

        severity = str(result.severity).strip().lower()

        risk_scores = {
            "info": 10.0,
            "low": 25.0,
            "medium": 50.0,
            "high": 80.0,
            "critical": 100.0,
        }

        return risk_scores.get(severity, 50.0)

    def _resolve_priority(
        self,
        *,
        severity: AlertSeverity,
        risk_score: float,
    ) -> str:
        """
        Resolve analyst-facing alert priority from severity/risk.

        Priority is intentionally kept as a string because AlertCreate uses
        a flexible priority field rather than a separate enum.
        """

        if severity == AlertSeverity.CRITICAL or risk_score >= 90:
            return "critical"

        if severity == AlertSeverity.HIGH or risk_score >= 80:
            return "high"

        if severity == AlertSeverity.MEDIUM or risk_score >= 50:
            return "medium"

        if severity == AlertSeverity.LOW or risk_score >= 25:
            return "low"

        return "info"

    def _build_deduplication_key(
        self,
        result: DetectionResult,
    ) -> str:
        """
        Build a stable detection-level deduplication key.

        The event ID is deliberately excluded.

        Multiple events matching the same detection rule should increase
        occurrence_count on the same alert rather than creating a new alert
        for every matching event.

        The rule ID is the primary identity of the detection alert. The
        detection source type is included to keep the namespace explicit.
        """

        material = "|".join(
            (
                AlertSourceType.DETECTION.value,
                result.rule_id,
            )
        )

        return sha256(
            material.encode("utf-8")
        ).hexdigest()

    def _extract_asset_id(
        self,
        result: DetectionResult,
    ) -> str | None:
        """
        Extract asset identity when the DetectionResult provides one.

        DetectionResult currently has no dedicated asset_id field, so this
        method intentionally checks optional dynamic/model fields without
        changing DetectionResult itself.
        """

        value = self._get_optional_value(result, "asset_id")

        if value is None:
            return None

        normalized = str(value).strip()

        return normalized or None

    def _extract_user_id(
        self,
        result: DetectionResult,
    ) -> str | None:
        """
        Extract user identity when the DetectionResult provides one.

        DetectionResult currently has no dedicated user_id field, so this
        method keeps the adapter forward-compatible without modifying the
        detection domain model.
        """

        value = self._get_optional_value(result, "user_id")

        if value is None:
            return None

        normalized = str(value).strip()

        return normalized or None

    @staticmethod
    def _get_optional_value(
        result: DetectionResult,
        field_name: str,
    ) -> Any:
        """
        Safely retrieve an optional DetectionResult field.

        Current DetectionResult does not define asset_id/user_id, but future
        detection implementations may expose them. Keeping this logic here
        avoids coupling DetectionEngine to alert-specific fields.
        """

        if hasattr(result, field_name):
            return getattr(result, field_name)

        return None


__all__ = [
    "DetectionAlertAdapter",
]
