from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.alerts.deduplication import AlertDeduplicator
from app.alerts.escalation import AlertEscalator
from app.alerts.lifecycle import AlertLifecycle
from app.alerts.models import (
    Alert,
    AlertAuditEntry,
    AlertCreate,
    AlertStatus,
)
from app.alerts.notification import AlertNotificationSink
from app.alerts.suppression import AlertSuppression
from app.core.metrics import REGISTRY

logger = logging.getLogger(__name__)

_ALERTS_CREATED_HELP = "Total alerts created."
_ALERTS_DEDUPLICATED_HELP = "Total duplicate alert occurrences merged."
_ALERTS_SUPPRESSED_HELP = "Total alerts suppressed by policy."
_ALERTS_ESCALATED_HELP = "Total alerts escalated."


AlertRealtimePublisher = Callable[
    [dict[str, Any]],
    Awaitable[int],
]


class AlertManager:
    """
    Manage alert creation, deduplication, lifecycle, ownership and audit.

    Realtime publication is intentionally injected through an optional
    async callback so the alert domain remains independent from Redis
    and WebSocket infrastructure.
    """

    def __init__(
        self,
        *,
        lifecycle: AlertLifecycle | None = None,
        deduplicator: AlertDeduplicator | None = None,
        suppression: AlertSuppression | None = None,
        escalator: AlertEscalator | None = None,
        notification_sink: AlertNotificationSink | None = None,
        realtime_publisher: AlertRealtimePublisher | None = None,
    ) -> None:
        self._lifecycle = lifecycle or AlertLifecycle()
        self._deduplicator = deduplicator or AlertDeduplicator()
        self._suppression = suppression or AlertSuppression()
        self._escalator = escalator or AlertEscalator()
        self._notification_sink = notification_sink
        self._realtime_publisher = realtime_publisher

        self._alerts: dict[UUID, Alert] = {}
        self._dedup_index: dict[str, UUID] = {}
        self._audit: dict[UUID, list[AlertAuditEntry]] = {}

    def set_realtime_publisher(
        self,
        publisher: AlertRealtimePublisher | None,
    ) -> None:
        """
        Configure or replace the realtime alert publisher.

        The publisher is intentionally optional so AlertManager remains
        fully usable in unit tests and non-realtime contexts.
        """
        self._realtime_publisher = publisher

    def create(
        self,
        data: AlertCreate,
        *,
        actor: str = "system",
    ) -> Alert:
        """
        Create an alert or merge it with an existing duplicate.

        A realtime event is emitted after the final alert state for this
        operation has been determined.
        """
        now = datetime.now(UTC)
        key = self._deduplicator.build_key(data)
        existing_id = self._dedup_index.get(key)

        if existing_id is not None:
            existing = self._alerts[existing_id]

            updated = existing.model_copy(
                update={
                    "occurrence_count": existing.occurrence_count + 1,
                    "last_seen_at": now,
                    "updated_at": now,
                    "risk_score": max(
                        existing.risk_score,
                        data.risk_score,
                    ),
                },
            )

            self._alerts[existing_id] = updated

            self._record(
                updated,
                AlertAuditEntry(
                    alert_id=existing_id,
                    action="deduplicated",
                    actor=actor,
                    reason="duplicate alert occurrence merged",
                    created_at=now,
                ),
            )

            REGISTRY.inc_counter(
                "siem_alerts_deduplicated_total",
                help_text=_ALERTS_DEDUPLICATED_HELP,
            )

            self._schedule_realtime_publish(
                updated,
                event_type="deduplicated",
            )

            return updated

        alert = Alert(
            source_type=data.source_type,
            source_id=data.source_id,
            rule_id=data.rule_id,
            title=data.title,
            description=data.description,
            severity=data.severity,
            risk_score=data.risk_score,
            priority=data.priority,
            evidence_ids=data.evidence_ids,
            asset_id=data.asset_id,
            user_id=data.user_id,
            deduplication_key=key,
            first_seen_at=now,
            last_seen_at=now,
            updated_at=now,
        )

        self._alerts[alert.alert_id] = alert
        self._dedup_index[key] = alert.alert_id
        self._audit[alert.alert_id] = []

        self._record(
            alert,
            AlertAuditEntry(
                alert_id=alert.alert_id,
                action="created",
                actor=actor,
                to_status=AlertStatus.NEW,
                created_at=now,
            ),
        )

        REGISTRY.inc_counter(
            "siem_alerts_created_total",
            help_text=_ALERTS_CREATED_HELP,
        )

        if self._suppression.should_suppress(alert):
            alert = self._transition(
                alert,
                AlertStatus.SUPPRESSED,
                actor=actor,
                reason="suppression policy",
            )

        self._schedule_realtime_publish(
            alert,
            event_type="created",
        )

        return alert

    def evaluate_escalation(
        self,
        alert_id: UUID,
        *,
        actor: str,
    ) -> Alert:
        """Evaluate and apply escalation without bypassing lifecycle rules."""
        alert = self.get(alert_id)

        if not self._escalator.should_escalate(alert):
            return alert

        if alert.status == AlertStatus.NEW:
            alert = self._transition(
                alert,
                AlertStatus.ACKNOWLEDGED,
                actor=actor,
                reason="automatic acknowledgement before escalation",
            )

        if alert.status in {
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.INVESTIGATING,
        }:
            return self._transition(
                alert,
                AlertStatus.ESCALATED,
                actor=actor,
                reason="escalation policy",
            )

        return alert

    def transition(
        self,
        alert_id: UUID,
        target: AlertStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """Apply a validated lifecycle transition."""
        alert = self.get(alert_id)

        return self._transition(
            alert,
            target,
            actor=actor,
            reason=reason,
        )

    def assign(
        self,
        alert_id: UUID,
        *,
        assignee: str | None,
        ownership_group: str | None = None,
        actor: str,
    ) -> Alert:
        """Assign or reassign an alert and record the change."""
        if not actor.strip():
            raise ValueError("actor is required")

        alert = self.get(alert_id)
        now = datetime.now(UTC)

        updated = alert.model_copy(
            update={
                "assigned_to": assignee,
                "ownership_group": ownership_group,
                "updated_at": now,
            },
        )

        self._alerts[alert_id] = updated

        self._record(
            updated,
            AlertAuditEntry(
                alert_id=alert_id,
                action="assignment_changed",
                actor=actor,
                reason=(
                    f"assignee={assignee or 'none'}; "
                    f"group={ownership_group or 'none'}"
                ),
                created_at=now,
            ),
        )

        self._schedule_realtime_publish(
            updated,
            event_type="assignment_changed",
        )

        return updated

    def get(
        self,
        alert_id: UUID,
    ) -> Alert:
        """Return an alert by identifier."""
        try:
            return self._alerts[alert_id]
        except KeyError as exc:
            raise KeyError(
                f"alert not found: {alert_id}",
            ) from exc

    def list_alerts(self) -> list[Alert]:
        """Return all managed alerts."""
        return list(self._alerts.values())

    def audit_history(
        self,
        alert_id: UUID,
    ) -> tuple[AlertAuditEntry, ...]:
        """Return immutable audit history for an alert."""
        self.get(alert_id)

        return tuple(
            self._audit[alert_id],
        )

    def _transition(
        self,
        alert: Alert,
        target: AlertStatus,
        *,
        actor: str,
        reason: str,
    ) -> Alert:
        """Apply lifecycle transition, audit it and notify listeners."""
        updated, audit = self._lifecycle.transition(
            alert,
            target,
            actor=actor,
            reason=reason,
        )

        self._alerts[alert.alert_id] = updated
        self._record(
            updated,
            audit,
        )

        if target is AlertStatus.SUPPRESSED:
            REGISTRY.inc_counter(
                "siem_alerts_suppressed_total",
                help_text=_ALERTS_SUPPRESSED_HELP,
            )

        if target is AlertStatus.ESCALATED:
            REGISTRY.inc_counter(
                "siem_alerts_escalated_total",
                help_text=_ALERTS_ESCALATED_HELP,
            )

        if self._notification_sink is not None:
            self._notification_sink.notify(
                updated,
                f"status:{target.value}",
            )

        self._schedule_realtime_publish(
            updated,
            event_type=f"status:{target.value}",
        )

        return updated

    def _record(
        self,
        alert: Alert,
        audit: AlertAuditEntry,
    ) -> None:
        """Append an immutable audit entry to the alert history."""
        self._audit.setdefault(
            alert.alert_id,
            [],
        ).append(audit)

    def _schedule_realtime_publish(
        self,
        alert: Alert,
        *,
        event_type: str,
    ) -> None:
        """
        Schedule realtime publication without turning the synchronous
        AlertManager API into an async API.

        Realtime delivery must never break alert creation, lifecycle
        transitions, or assignment operations.
        """
        publisher = self._realtime_publisher

        if publisher is None:
            return

        payload = {
            "event_type": event_type,
            "alert": alert.model_dump(
                mode="json",
            ),
        }

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug(
                "Realtime alert publication skipped because "
                "no running event loop is available.",
            )
            return

        task = loop.create_task(
            self._publish_realtime(
                publisher,
                payload,
            ),
            name="alert-realtime-publisher",
        )

        task.add_done_callback(
            self._handle_realtime_task_result,
        )

    async def _publish_realtime(
        self,
        publisher: AlertRealtimePublisher,
        payload: dict[str, Any],
    ) -> None:
        """Publish one alert payload through the injected publisher."""
        try:
            delivered = await publisher(
                payload,
            )

            logger.debug(
                "Alert realtime payload published "
                "(delivered=%d, event_type=%s).",
                delivered,
                payload.get("event_type"),
            )

        except Exception:
            logger.exception(
                "Alert realtime publication failed "
                "(event_type=%s).",
                payload.get("event_type"),
            )

    @staticmethod
    def _handle_realtime_task_result(
        task: asyncio.Task[Any],
    ) -> None:
        """Consume completed realtime task exceptions defensively."""
        if task.cancelled():
            return

        try:
            task.result()
        except Exception:
            logger.exception(
                "Unexpected alert realtime publisher task failure."
            )