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

_ALERT_PERSISTENCE_FAILURES_HELP = (
    "Total alert persistence operation failures."
)

_ALERT_AUDIT_PERSISTENCE_FAILURES_HELP = (
    "Total alert audit persistence operation failures."
)


AlertRealtimePublisher = Callable[
    [dict[str, Any]],
    Awaitable[int],
]


class AlertRepositoryProtocol:
    """
    Minimal repository boundary required by AlertManager.

    The concrete OpenSearch implementation can satisfy this protocol
    without making AlertManager depend directly on OpenSearch.
    """

    async def save(self, alert: Alert) -> None:
        raise NotImplementedError

    async def get(self, alert_id: UUID) -> Alert | None:
        raise NotImplementedError

    async def save_audit_entry(
        self,
        audit: AlertAuditEntry,
    ) -> None:
        raise NotImplementedError

    async def get_audit_history(
        self,
        alert_id: UUID,
    ) -> tuple[AlertAuditEntry, ...]:
        raise NotImplementedError


class AlertManager:
    """
    Manage alert creation, deduplication, suppression, lifecycle,
    escalation, ownership, audit and realtime publication.

    Architecture boundary:

        AlertService
              ↓
        AlertManager
              ↓
        AlertRepository
              ↓
        OpenSearch

    The manager owns alert-domain orchestration. Persistence is injected
    through a repository boundary so the manager remains independent of
    the underlying storage technology.

    The public manager API remains synchronous. Persistence is therefore
    scheduled asynchronously when an event loop is available.
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
        repository: AlertRepositoryProtocol | None = None,
    ) -> None:
        self._lifecycle = lifecycle or AlertLifecycle()
        self._deduplicator = deduplicator or AlertDeduplicator()
        self._suppression = suppression or AlertSuppression()
        self._escalator = escalator or AlertEscalator()
        self._notification_sink = notification_sink
        self._realtime_publisher = realtime_publisher
        self._repository = repository

        # In-memory working state.
        #
        # This remains useful for:
        #   - fast lifecycle operations
        #   - unit tests
        #   - non-persistent runtime
        #   - deduplication cache
        self._alerts: dict[UUID, Alert] = {}
        self._dedup_index: dict[str, UUID] = {}
        self._audit: dict[UUID, list[AlertAuditEntry]] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_repository(
        self,
        repository: AlertRepositoryProtocol | None,
    ) -> None:
        """
        Configure or replace the alert repository.

        Passing None disables persistence while preserving in-memory
        manager behaviour.
        """
        self._repository = repository

    def set_realtime_publisher(
        self,
        publisher: AlertRealtimePublisher | None,
    ) -> None:
        """
        Configure or replace the realtime alert publisher.

        The publisher remains optional so AlertManager can operate in
        unit tests and non-realtime contexts.
        """
        self._realtime_publisher = publisher

    # ------------------------------------------------------------------
    # Creation / Deduplication
    # ------------------------------------------------------------------

    def create(
        self,
        data: AlertCreate,
        *,
        actor: str = "system",
    ) -> Alert:
        """
        Create an alert or merge a duplicate occurrence.

        Duplicate flow:

            duplicate
                ↓
            occurrence_count += 1
                ↓
            suppression policy
                ↓
            threshold reached?
              /       \
            yes        no
             ↓          ↓
        SUPPRESSED    keep state

        A realtime event is emitted after the final state for this
        operation has been determined.
        """
        self._validate_actor(actor)

        if not isinstance(data, AlertCreate):
            raise TypeError(
                "AlertManager.create expects AlertCreate",
            )

        now = datetime.now(UTC)
        key = self._deduplicator.build_key(data)

        existing_id = self._dedup_index.get(key)

        if existing_id is not None:
            existing = self._alerts.get(existing_id)

            if existing is None:
                # Defensive recovery for an inconsistent in-memory index.
                self._dedup_index.pop(key, None)
            else:
                return self._merge_duplicate(
                    existing,
                    data,
                    actor=actor,
                    now=now,
                )

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

        self._persist_alert(alert)
        self._persist_latest_audit(alert.alert_id)

        REGISTRY.inc_counter(
            "siem_alerts_created_total",
            help_text=_ALERTS_CREATED_HELP,
        )

        # Suppression is evaluated for the initial occurrence.
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

    def _merge_duplicate(
        self,
        existing: Alert,
        data: AlertCreate,
        *,
        actor: str,
        now: datetime,
    ) -> Alert:
        """
        Merge a duplicate alert occurrence.

        Suppression is intentionally evaluated AFTER occurrence_count is
        incremented. This fixes the previous bug where an alert could reach
        the suppression threshold without ever being evaluated again.
        """

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

        self._alerts[existing.alert_id] = updated

        self._record(
            updated,
            AlertAuditEntry(
                alert_id=existing.alert_id,
                action="deduplicated",
                actor=actor,
                from_status=existing.status,
                to_status=updated.status,
                reason="duplicate alert occurrence merged",
                created_at=now,
            ),
        )

        self._persist_alert(updated)
        self._persist_latest_audit(updated.alert_id)

        REGISTRY.inc_counter(
            "siem_alerts_deduplicated_total",
            help_text=_ALERTS_DEDUPLICATED_HELP,
        )

        # --------------------------------------------------------------
        # IMPORTANT:
        # Suppression must be evaluated after occurrence_count changes.
        # --------------------------------------------------------------
        if (
            updated.status not in {
                AlertStatus.SUPPRESSED,
                AlertStatus.CLOSED,
            }
            and self._suppression.should_suppress(updated)
        ):
            updated = self._transition(
                updated,
                AlertStatus.SUPPRESSED,
                actor=actor,
                reason="suppression threshold reached after duplicate occurrence",
            )

            event_type = "suppressed"
        else:
            event_type = "deduplicated"

        self._schedule_realtime_publish(
            updated,
            event_type=event_type,
        )

        return updated

    # ------------------------------------------------------------------
    # Escalation
    # ------------------------------------------------------------------

    def evaluate_escalation(
        self,
        alert_id: UUID,
        *,
        actor: str,
    ) -> Alert:
        """
        Evaluate and apply escalation without bypassing lifecycle rules.
        """
        self._validate_actor(actor)

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

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def transition(
        self,
        alert_id: UUID,
        target: AlertStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Apply a validated lifecycle transition.
        """
        self._validate_actor(actor)

        alert = self.get(alert_id)

        return self._transition(
            alert,
            target,
            actor=actor,
            reason=reason,
        )

    def _transition(
        self,
        alert: Alert,
        target: AlertStatus,
        *,
        actor: str,
        reason: str,
    ) -> Alert:
        """
        Apply lifecycle transition, persist it, audit it and notify
        listeners.
        """
        self._validate_actor(actor)

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

        self._persist_alert(updated)
        self._persist_audit(audit)

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
            try:
                self._notification_sink.notify(
                    updated,
                    f"status:{target.value}",
                )
            except Exception:
                # Notification must never break the alert lifecycle.
                logger.exception(
                    "Alert notification failed "
                    "(alert_id=%s, status=%s).",
                    updated.alert_id,
                    target.value,
                )

        self._schedule_realtime_publish(
            updated,
            event_type=f"status:{target.value}",
        )

        return updated

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------

    def assign(
        self,
        alert_id: UUID,
        *,
        assignee: str | None,
        ownership_group: str | None = None,
        actor: str,
    ) -> Alert:
        """
        Assign or reassign an alert and persist the change.
        """
        self._validate_actor(actor)

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

        audit = AlertAuditEntry(
            alert_id=alert_id,
            action="assignment_changed",
            actor=actor,
            from_status=alert.status,
            to_status=updated.status,
            reason=(
                f"assignee={assignee or 'none'}; "
                f"group={ownership_group or 'none'}"
            ),
            created_at=now,
        )

        self._record(
            updated,
            audit,
        )

        self._persist_alert(updated)
        self._persist_audit(audit)

        self._schedule_realtime_publish(
            updated,
            event_type="assignment_changed",
        )

        return updated

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(
        self,
        alert_id: UUID,
    ) -> Alert:
        """
        Return an alert by identifier.

        The manager first checks its in-memory working state. Persistent
        repository reads are available through load_from_repository() so
        synchronous manager methods do not unexpectedly become async.
        """
        try:
            return self._alerts[alert_id]
        except KeyError as exc:
            raise KeyError(
                f"alert not found: {alert_id}",
            ) from exc

    def list_alerts(self) -> list[Alert]:
        """
        Return all currently managed alerts.

        Persistent search/pagination belongs to AlertRepository and the
        application/API layer. This method intentionally preserves the
        existing synchronous manager contract.
        """
        return list(self._alerts.values())

    def audit_history(
        self,
        alert_id: UUID,
    ) -> tuple[AlertAuditEntry, ...]:
        """
        Return immutable audit history currently held by the manager.
        """
        self.get(alert_id)

        return tuple(
            self._audit.get(
                alert_id,
                [],
            ),
        )

    # ------------------------------------------------------------------
    # Repository hydration
    # ------------------------------------------------------------------

    async def load_from_repository(
        self,
        alert_id: UUID,
    ) -> Alert | None:
        """
        Load one alert from the repository and hydrate manager state.

        This is explicitly async because repository access is async.
        """
        repository = self._repository

        if repository is None:
            return self._alerts.get(alert_id)

        alert = await repository.get(alert_id)

        if alert is None:
            return None

        self._hydrate_alert(alert)

        audit_entries = await repository.get_audit_history(
            alert_id,
        )

        self._audit[alert_id] = list(audit_entries)

        return alert

    async def hydrate(
        self,
        alerts: list[Alert] | tuple[Alert, ...],
    ) -> None:
        """
        Hydrate manager state from repository-provided alerts.

        This is useful during application startup or worker bootstrap.
        """
        for alert in alerts:
            self._hydrate_alert(alert)

    def _hydrate_alert(
        self,
        alert: Alert,
    ) -> None:
        """
        Add a persisted alert to the in-memory working state.
        """
        self._alerts[alert.alert_id] = alert

        if alert.deduplication_key:
            self._dedup_index[
                alert.deduplication_key
            ] = alert.alert_id

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _record(
        self,
        alert: Alert,
        audit: AlertAuditEntry,
    ) -> None:
        """
        Append an immutable audit entry to local alert history.
        """
        self._audit.setdefault(
            alert.alert_id,
            [],
        ).append(audit)

    # ------------------------------------------------------------------
    # Persistence boundary
    # ------------------------------------------------------------------

    def _persist_alert(
        self,
        alert: Alert,
    ) -> None:
        """
        Persist an alert through the injected repository.

        AlertManager remains synchronous, therefore persistence is scheduled
        on the active event loop.

        In a non-async context, persistence is skipped because there is no
        safe event loop on which to execute the repository operation.
        """
        repository = self._repository

        if repository is None:
            return

        self._schedule_repository_task(
            self._persist_alert_async(
                repository,
                alert,
            ),
            task_name="alert-repository-save",
        )

    async def _persist_alert_async(
        self,
        repository: AlertRepositoryProtocol,
        alert: Alert,
    ) -> None:
        """
        Persist one alert.
        """
        try:
            await repository.save(alert)

        except Exception:
            REGISTRY.inc_counter(
                "siem_alert_persistence_failures_total",
                help_text=_ALERT_PERSISTENCE_FAILURES_HELP,
            )

            logger.exception(
                "Alert persistence failed (alert_id=%s).",
                alert.alert_id,
            )

            raise

    def _persist_audit(
        self,
        audit: AlertAuditEntry,
    ) -> None:
        """
        Persist one audit entry through the repository.
        """
        repository = self._repository

        if repository is None:
            return

        self._schedule_repository_task(
            self._persist_audit_async(
                repository,
                audit,
            ),
            task_name="alert-audit-repository-save",
        )

    def _persist_latest_audit(
        self,
        alert_id: UUID,
    ) -> None:
        """
        Persist the newest locally-recorded audit entry.

        Used after create/dedup operations where _record() has already
        appended the entry.
        """
        history = self._audit.get(alert_id)

        if not history:
            return

        self._persist_audit(
            history[-1],
        )

    async def _persist_audit_async(
        self,
        repository: AlertRepositoryProtocol,
        audit: AlertAuditEntry,
    ) -> None:
        """
        Persist one audit entry.
        """
        try:
            await repository.save_audit_entry(audit)

        except Exception:
            REGISTRY.inc_counter(
                "siem_alert_audit_persistence_failures_total",
                help_text=_ALERT_AUDIT_PERSISTENCE_FAILURES_HELP,
            )

            logger.exception(
                "Alert audit persistence failed (alert_id=%s, audit_id=%s).",
                audit.alert_id,
                audit.audit_id,
            )

            raise

    def _schedule_repository_task(
        self,
        coroutine: Awaitable[Any],
        *,
        task_name: str,
    ) -> None:
        """
        Schedule repository work without converting the public manager API
        into async methods.
        """
        try:
            loop = asyncio.get_running_loop()

        except RuntimeError:
            logger.debug(
                "Repository persistence skipped because no running "
                "event loop is available (task=%s).",
                task_name,
            )

            # Prevent an un-awaited coroutine warning when the manager is
            # used synchronously outside an event loop.
            if hasattr(coroutine, "close"):
                coroutine.close()  # type: ignore[attr-defined]

            return

        task = loop.create_task(
            coroutine,
            name=task_name,
        )

        task.add_done_callback(
            self._handle_repository_task_result,
        )

    @staticmethod
    def _handle_repository_task_result(
        task: asyncio.Task[Any],
    ) -> None:
        """
        Consume completed repository task exceptions defensively.

        The actual persistence coroutine already logs the failure and
        increments metrics. This callback prevents "Task exception was
        never retrieved" warnings.
        """
        if task.cancelled():
            return

        try:
            task.result()

        except Exception:
            logger.debug(
                "Repository background task completed with an error.",
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Realtime
    # ------------------------------------------------------------------

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
        transitions, assignment operations, or suppression.
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
                "Realtime alert publication skipped because no running "
                "event loop is available.",
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
        """
        Publish one alert payload through the injected publisher.
        """
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
        """
        Consume completed realtime task exceptions defensively.
        """
        if task.cancelled():
            return

        try:
            task.result()

        except Exception:
            logger.exception(
                "Unexpected alert realtime publisher task failure.",
            )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_actor(
        actor: str,
    ) -> None:
        """
        Validate the audit actor.
        """
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError(
                "actor is required",
            )


__all__ = [
    "AlertManager",
    "AlertRealtimePublisher",
    "AlertRepositoryProtocol",
]