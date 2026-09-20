from __future__ import annotations

import hashlib

from app.alerts.models import (
    AlertCreate,
    AlertSeverity,
    AlertSourceType,
)
from app.correlation.result import CorrelationResult


class CorrelationAlertAdapter:
    """
    Convert CorrelationResult objects into AlertCreate objects.

    CorrelationEngine remains responsible only for evaluating
    multi-event patterns. Alert creation is kept in the alert
    layer through this adapter.
    """

    _SEVERITY_MAP: dict[str, AlertSeverity] = {
        "info": AlertSeverity.INFO,
        "low": AlertSeverity.LOW,
        "medium": AlertSeverity.MEDIUM,
        "high": AlertSeverity.HIGH,
        "critical": AlertSeverity.CRITICAL,
    }

    _RISK_SCORE_MAP: dict[AlertSeverity, float] = {
        AlertSeverity.INFO: 10.0,
        AlertSeverity.LOW: 25.0,
        AlertSeverity.MEDIUM: 50.0,
        AlertSeverity.HIGH: 80.0,
        AlertSeverity.CRITICAL: 100.0,
    }

    _PRIORITY_MAP: dict[AlertSeverity, str] = {
        AlertSeverity.INFO: "info",
        AlertSeverity.LOW: "low",
        AlertSeverity.MEDIUM: "medium",
        AlertSeverity.HIGH: "high",
        AlertSeverity.CRITICAL: "critical",
    }

    @classmethod
    def _severity(cls, value: str) -> AlertSeverity:
        normalized = str(value).strip().lower()
        return cls._SEVERITY_MAP.get(
            normalized,
            AlertSeverity.MEDIUM,
        )

    @classmethod
    def _deduplication_key(
        cls,
        result: CorrelationResult,
    ) -> str:
        """
        Correlation alerts should deduplicate around the
        correlation rule and grouping context rather than
        a single evidence event.

        The correlation engine already consumes a matched
        state window, so a new correlation_id represents a
        new occurrence.
        """

        material = "|".join(
            (
                AlertSourceType.CORRELATION.value,
                result.rule_id,
                repr(result.group_key),
            )
        )

        return hashlib.sha256(
            material.encode("utf-8"),
        ).hexdigest()

    @classmethod
    def to_alert(
        cls,
        result: CorrelationResult,
    ) -> AlertCreate:
        """
        Convert one CorrelationResult into AlertCreate.
        """

        if not isinstance(result, CorrelationResult):
            raise TypeError(
                "correlation alert adapter expects "
                "CorrelationResult",
            )

        severity = cls._severity(result.severity)

        return AlertCreate(
            source_type=AlertSourceType.CORRELATION,
            source_id=result.correlation_id,
            rule_id=result.rule_id,
            title=f"Correlation: {result.rule_id}",
            description=result.description,
            severity=severity,
            risk_score=cls._RISK_SCORE_MAP[severity],
            priority=cls._PRIORITY_MAP[severity],
            evidence_ids=tuple(result.event_ids),
            deduplication_key=cls._deduplication_key(result),
        )

    @classmethod
    def to_alerts(
        cls,
        results: tuple[CorrelationResult, ...] | list[CorrelationResult],
    ) -> tuple[AlertCreate, ...]:
        """
        Convert multiple correlation results.
        """

        return tuple(
            cls.to_alert(result)
            for result in results
        )


__all__ = [
    "CorrelationAlertAdapter",
]
