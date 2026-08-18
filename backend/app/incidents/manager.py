from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable
from uuid import UUID

from app.incidents.assignment import IncidentAssignment
from app.incidents.evidence import EvidenceService
from app.incidents.investigation import InvestigationService
from app.incidents.lifecycle import IncidentLifecycle
from app.incidents.models import (
    EvidenceRecord,
    Incident,
    IncidentAuditEntry,
    IncidentCreate,
    IncidentStatus,
    InvestigationNote,
    TimelineEntry,
)
from app.incidents.timeline import IncidentTimeline


logger = logging.getLogger(__name__)

IncidentRealtimePublisher = Callable[
    [dict[str, Any]],
    Awaitable[int],
]


class IncidentManager:
    """Manage incident creation, investigation, ownership and lifecycle."""

    def __init__(
        self,
        *,
        lifecycle: IncidentLifecycle | None = None,
        investigation: InvestigationService | None = None,
        evidence: EvidenceService | None = None,
        timeline: IncidentTimeline | None = None,
        assignment: IncidentAssignment | None = None,
        realtime_publisher: IncidentRealtimePublisher | None = None,
    ) -> None:
        self._lifecycle = lifecycle or IncidentLifecycle()
        self._investigation = investigation or InvestigationService()
        self._evidence = evidence or EvidenceService()
        self._timeline = timeline or IncidentTimeline()
        self._assignment = assignment or IncidentAssignment()

        self._incidents: dict[UUID, Incident] = {}
        self._audit: dict[UUID, list[IncidentAuditEntry]] = {}

        self._realtime_publisher = realtime_publisher

    def set_realtime_publisher(
        self,
        publisher: IncidentRealtimePublisher | None,
    ) -> None:
        """Set or clear the asynchronous realtime publisher."""
        self._realtime_publisher = publisher

    def create(
        self,
        data: IncidentCreate,
        *,
        actor: str = "system",
    ) -> Incident:
        if not actor.strip():
            raise ValueError("actor is required")

        now = datetime.now(UTC)

        incident = Incident(
            title=data.title,
            description=data.description,
            severity=data.severity,
            alert_ids=data.alert_ids,
            evidence_ids=data.evidence_ids,
            related_event_ids=data.related_event_ids,
            related_ioc_ids=data.related_ioc_ids,
            asset_ids=data.asset_ids,
            assigned_to=data.initial_assignee,
            ownership_group=data.ownership_group,
            first_seen_at=now,
            last_updated_at=now,
        )

        self._incidents[incident.incident_id] = incident
        self._audit[incident.incident_id] = []

        self._record(
            incident,
            IncidentAuditEntry(
                incident_id=incident.incident_id,
                action="created",
                actor=actor,
                to_status=IncidentStatus.NEW,
                created_at=now,
            ),
        )

        self._timeline.add(
            incident.incident_id,
            event_type="incident_created",
            description=incident.title,
            actor=actor,
        )

        self._schedule_realtime_publish(
            incident,
            event_type="created",
        )

        return incident

    def get(
        self,
        incident_id: UUID,
    ) -> Incident:
        try:
            return self._incidents[incident_id]
        except KeyError as exc:
            raise KeyError(
                f"incident not found: {incident_id}",
            ) from exc

    def list_incidents(self) -> list[Incident]:
        return list(self._incidents.values())

    def transition(
        self,
        incident_id: UUID,
        target: IncidentStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Incident:
        incident = self.get(incident_id)

        updated, audit = self._lifecycle.transition(
            incident,
            target,
            actor=actor,
            reason=reason,
        )

        self._incidents[incident_id] = updated
        self._record(updated, audit)

        self._timeline.add(
            incident_id,
            event_type="status_transition",
            description=(
                f"{incident.status.value} -> {target.value}"
            ),
            actor=actor,
        )

        self._schedule_realtime_publish(
            updated,
            event_type=f"status:{target.value}",
        )

        return updated

    def assign(
        self,
        incident_id: UUID,
        *,
        assignee: str | None,
        ownership_group: str | None,
        actor: str,
    ) -> Incident:
        if not actor.strip():
            raise ValueError("actor is required")

        incident = self.get(incident_id)

        updated = self._assignment.assign(
            incident,
            assignee=assignee,
            ownership_group=ownership_group,
        )

        self._incidents[incident_id] = updated

        now = datetime.now(UTC)

        self._record(
            updated,
            IncidentAuditEntry(
                incident_id=incident_id,
                action="assignment_changed",
                actor=actor,
                reason=(
                    f"assignee={assignee or 'none'}; "
                    f"group={ownership_group or 'none'}"
                ),
                created_at=now,
            ),
        )

        self._timeline.add(
            incident_id,
            event_type="assignment_changed",
            description=(
                f"assignee={assignee or 'none'}; "
                f"group={ownership_group or 'none'}"
            ),
            actor=actor,
        )

        self._schedule_realtime_publish(
            updated,
            event_type="assignment_changed",
        )

        return updated

    def add_note(
        self,
        incident_id: UUID,
        *,
        author: str,
        content: str,
    ) -> InvestigationNote:
        self.get(incident_id)

        note = self._investigation.add_note(
            incident_id,
            author=author,
            content=content,
        )

        self._timeline.add(
            incident_id,
            event_type="investigation_note",
            description="Investigation note added",
            actor=author,
        )

        incident = self.get(incident_id)

        self._schedule_realtime_publish(
            incident,
            event_type="investigation_note",
            extra={
                "note": note.model_dump(mode="json"),
            },
        )

        return note

    def add_evidence(
        self,
        incident_id: UUID,
        *,
        evidence_id: str,
        evidence_type: str,
        reference: str,
        collected_by: str,
    ) -> EvidenceRecord:
        self.get(incident_id)

        record = self._evidence.add(
            incident_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            reference=reference,
            collected_by=collected_by,
        )

        incident = self.get(incident_id)

        if evidence_id not in incident.evidence_ids:
            updated = incident.model_copy(
                update={
                    "evidence_ids": (
                        incident.evidence_ids
                        + (evidence_id,)
                    ),
                    "last_updated_at": datetime.now(UTC),
                },
            )

            self._incidents[incident_id] = updated
            incident = updated

        self._timeline.add(
            incident_id,
            event_type="evidence_added",
            description=(
                f"{evidence_type}: {evidence_id}"
            ),
            actor=collected_by,
        )

        self._schedule_realtime_publish(
            incident,
            event_type="evidence_added",
            extra={
                "evidence": record.model_dump(mode="json"),
            },
        )

        return record

    def notes(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        self.get(incident_id)

        return self._investigation.list_notes(
            incident_id,
        )

    def evidence(
        self,
        incident_id: UUID,
    ) -> tuple[EvidenceRecord, ...]:
        self.get(incident_id)

        return self._evidence.list(
            incident_id,
        )

    def timeline(
        self,
        incident_id: UUID,
    ) -> tuple[TimelineEntry, ...]:
        self.get(incident_id)

        return self._timeline.list(
            incident_id,
        )

    def audit_history(
        self,
        incident_id: UUID,
    ) -> tuple[IncidentAuditEntry, ...]:
        self.get(incident_id)

        return tuple(
            self._audit[incident_id],
        )

    def _record(
        self,
        incident: Incident,
        audit: IncidentAuditEntry,
    ) -> None:
        self._audit.setdefault(
            incident.incident_id,
            [],
        ).append(audit)

    def _schedule_realtime_publish(
        self,
        incident: Incident,
        *,
        event_type: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        publisher = self._realtime_publisher

        if publisher is None:
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug(
                "Skipping incident realtime publish because "
                "no running event loop is available",
            )
            return

        payload: dict[str, Any] = {
            "event_type": event_type,
            "incident": incident.model_dump(
                mode="json",
            ),
        }

        if extra:
            payload.update(extra)

        task = loop.create_task(
            self._publish_realtime(
                publisher,
                payload,
            ),
        )

        task.add_done_callback(
            self._handle_realtime_task_result,
        )

    async def _publish_realtime(
        self,
        publisher: IncidentRealtimePublisher,
        payload: dict[str, Any],
    ) -> None:
        try:
            delivered = await publisher(payload)

            logger.debug(
                "Incident realtime event published "
                "(event_type=%s delivered=%s)",
                payload.get("event_type"),
                delivered,
            )

        except Exception:
            logger.exception(
                "Incident realtime publish failed",
            )

    @staticmethod
    def _handle_realtime_task_result(
        task: asyncio.Task[None],
    ) -> None:
        if task.cancelled():
            return

        try:
            task.result()
        except Exception:
            logger.exception(
                "Unhandled incident realtime task failure",
            )
