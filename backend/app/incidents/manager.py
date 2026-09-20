from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.incidents.assignment import IncidentAssignment
from app.incidents.evidence import EvidenceService
from app.incidents.investigation import InvestigationService
from app.incidents.lifecycle import IncidentLifecycle
from app.incidents.models import (
    EvidenceRecord,
    Incident,
    IncidentAuditEntry,
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
    InvestigationNote,
    TimelineEntry,
)
from app.incidents.timeline import IncidentTimeline


logger = logging.getLogger(__name__)


# =============================================================================
# Callback Contracts
# =============================================================================


IncidentRealtimePublisher = Callable[
    [dict[str, Any]],
    Awaitable[int],
]

IncidentPersistenceCallback = Callable[
    [Incident],
    Awaitable[None],
]

IncidentAuditPersistenceCallback = Callable[
    [IncidentAuditEntry],
    Awaitable[None],
]

IncidentNotePersistenceCallback = Callable[
    [InvestigationNote],
    Awaitable[None],
]

IncidentEvidencePersistenceCallback = Callable[
    [EvidenceRecord],
    Awaitable[None],
]

IncidentTimelinePersistenceCallback = Callable[
    [TimelineEntry],
    Awaitable[None],
]


# =============================================================================
# Incident Manager
# =============================================================================


class IncidentManager:
    """
    Application/domain orchestration layer for Security Incidents.

    Canonical responsibilities:

        - Incident creation
        - Alert -> Incident creation
        - Incident retrieval
        - Incident hydration
        - Incident metadata updates
        - Severity changes
        - Assignment/reassignment
        - Lifecycle transitions
        - Investigation notes
        - Evidence
        - Timeline
        - Audit history
        - Incident number generation
        - Persistence orchestration
        - Realtime publication

    Final Incident contract:

        Status:
            OPEN
            INVESTIGATING
            CONTAINED
            RESOLVED
            CLOSED

        Severity:
            CRITICAL
            HIGH
            MEDIUM
            LOW
            INFORMATIONAL

        Assignment:
            assigned_to -> User UUID

    Intentionally excluded:

        - priority
        - ownership_group
        - Incident deletion
        - Alert lookup
        - duplicate Alert promotion detection

    Alert lookup and duplicate-promotion protection remain in the
    Alert -> Incident promotion/application layer.
    """

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        *,
        lifecycle: IncidentLifecycle | None = None,
        investigation: InvestigationService | None = None,
        evidence: EvidenceService | None = None,
        timeline: IncidentTimeline | None = None,
        assignment: IncidentAssignment | None = None,
        realtime_publisher: IncidentRealtimePublisher | None = None,
        incident_persister: IncidentPersistenceCallback | None = None,
        audit_persister: IncidentAuditPersistenceCallback | None = None,
        note_persister: IncidentNotePersistenceCallback | None = None,
        evidence_persister: (
            IncidentEvidencePersistenceCallback | None
        ) = None,
        timeline_persister: (
            IncidentTimelinePersistenceCallback | None
        ) = None,
    ) -> None:
        self._lifecycle = lifecycle or IncidentLifecycle()

        self._investigation = (
            investigation or InvestigationService()
        )

        self._evidence = (
            evidence or EvidenceService()
        )

        self._timeline = (
            timeline or IncidentTimeline()
        )

        self._assignment = (
            assignment or IncidentAssignment()
        )

        self._incidents: dict[
            UUID,
            Incident,
        ] = {}

        self._audit: dict[
            UUID,
            list[IncidentAuditEntry],
        ] = {}

        self._realtime_publisher = realtime_publisher

        self._incident_persister = incident_persister
        self._audit_persister = audit_persister
        self._note_persister = note_persister
        self._evidence_persister = evidence_persister
        self._timeline_persister = timeline_persister

    # =========================================================================
    # Configuration
    # =========================================================================

    def set_realtime_publisher(
        self,
        publisher: IncidentRealtimePublisher | None,
    ) -> None:
        """Set or clear the Incident realtime publisher."""

        self._realtime_publisher = publisher

    def set_persistence_callbacks(
        self,
        *,
        incident_persister: IncidentPersistenceCallback | None = None,
        audit_persister: IncidentAuditPersistenceCallback | None = None,
        note_persister: IncidentNotePersistenceCallback | None = None,
        evidence_persister: (
            IncidentEvidencePersistenceCallback | None
        ) = None,
        timeline_persister: (
            IncidentTimelinePersistenceCallback | None
        ) = None,
    ) -> None:
        """Configure Incident persistence callbacks."""

        self._incident_persister = incident_persister
        self._audit_persister = audit_persister
        self._note_persister = note_persister
        self._evidence_persister = evidence_persister
        self._timeline_persister = timeline_persister

    # =========================================================================
    # Incident Number
    # =========================================================================

    @staticmethod
    def _generate_incident_number(
        incident_id: UUID,
        timestamp: datetime,
    ) -> str:
        """
        Generate a human-readable Incident number.

        Format:

            INC-YYYY-NNNNN
        """

        suffix = incident_id.int % 100000

        return (
            f"INC-{timestamp.year:04d}-"
            f"{suffix:05d}"
        )

    # =========================================================================
    # Create
    # =========================================================================

    def create(
        self,
        data: IncidentCreate,
        *,
        actor: str = "system",
    ) -> Incident:
        """
        Create an Incident.

        Initial status is always OPEN.
        """

        incident, audits, timeline_entry = (
            self._create_domain_state(
                data,
                actor=actor,
            )
        )

        self._schedule_incident_persistence(
            incident,
        )

        for audit in audits:
            self._schedule_audit_persistence(
                audit,
            )

        self._schedule_timeline_persistence(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            incident,
            event_type="created",
        )

        return incident

    async def create_persisted(
        self,
        data: IncidentCreate,
        *,
        actor: str = "system",
    ) -> Incident:
        """Create an Incident and wait for persistence."""

        incident, audits, timeline_entry = (
            self._create_domain_state(
                data,
                actor=actor,
            )
        )

        await self._persist_incident(
            incident,
        )

        for audit in audits:
            await self._persist_audit(
                audit,
            )

        await self._persist_timeline(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            incident,
            event_type="created",
        )

        return incident

    def _create_domain_state(
        self,
        data: IncidentCreate,
        *,
        actor: str,
    ) -> tuple[
        Incident,
        tuple[IncidentAuditEntry, ...],
        TimelineEntry,
    ]:
        """Build the initial Incident aggregate and audit state."""

        if not isinstance(
            data,
            IncidentCreate,
        ):
            raise TypeError(
                "data must be an IncidentCreate instance"
            )

        normalized_actor = (
            self._normalize_required_text(
                actor,
                "actor",
            )
        )

        now = datetime.now(UTC)
        incident_id = uuid4()

        incident_number = (
            self._generate_incident_number(
                incident_id,
                now,
            )
        )

        incident = Incident(
            incident_id=incident_id,
            incident_number=incident_number,
            title=data.title,
            description=data.description,
            severity=data.severity,
            status=IncidentStatus.OPEN,
            tags=data.tags,
            alert_ids=tuple(
                dict.fromkeys(
                    data.alert_ids,
                )
            ),
            evidence_ids=tuple(
                dict.fromkeys(
                    data.evidence_ids,
                )
            ),
            related_event_ids=tuple(
                dict.fromkeys(
                    data.related_event_ids,
                )
            ),
            related_ioc_ids=tuple(
                dict.fromkeys(
                    data.related_ioc_ids,
                )
            ),
            asset_ids=tuple(
                dict.fromkeys(
                    data.asset_ids,
                )
            ),
            assigned_to=data.initial_assignee,
            created_by=normalized_actor,
            created_at=now,
            updated_at=now,
        )

        self._incidents[
            incident.incident_id
        ] = incident

        self._audit[
            incident.incident_id
        ] = []

        created_audit = IncidentAuditEntry(
            incident_id=incident.incident_id,
            action="incident_created",
            actor=normalized_actor,
            to_status=IncidentStatus.OPEN,
            to_severity=incident.severity,
            to_assignee=incident.assigned_to,
            reason="Incident created",
            created_at=now,
        )

        self._record(
            incident,
            created_audit,
        )

        timeline_entry = self._timeline.add(
            incident.incident_id,
            event_type="incident_created",
            description=(
                f"{incident.incident_number}: "
                f"{incident.title}"
            ),
            actor=normalized_actor,
        )

        return (
            incident,
            (created_audit,),
            timeline_entry,
        )

    # =========================================================================
    # Alert -> Incident
    # =========================================================================

    def create_from_alert(
        self,
        data: IncidentCreate,
        *,
        alert_id: UUID,
        actor: str = "system",
    ) -> Incident:
        """
        Create an Incident associated with an Alert.

        Alert lookup and duplicate-promotion validation remain outside this
        Manager.
        """

        if not isinstance(
            alert_id,
            UUID,
        ):
            raise TypeError(
                "alert_id must be a UUID"
            )

        alert_ids = tuple(
            dict.fromkeys(
                data.alert_ids
                + (alert_id,),
            )
        )

        if alert_ids != data.alert_ids:
            data = data.model_copy(
                update={
                    "alert_ids": alert_ids,
                },
            )

        return self.create(
            data,
            actor=actor,
        )

    async def create_from_alert_persisted(
        self,
        data: IncidentCreate,
        *,
        alert_id: UUID,
        actor: str = "system",
    ) -> Incident:
        """Persisted Alert -> Incident creation."""

        if not isinstance(
            alert_id,
            UUID,
        ):
            raise TypeError(
                "alert_id must be a UUID"
            )

        alert_ids = tuple(
            dict.fromkeys(
                data.alert_ids
                + (alert_id,),
            )
        )

        if alert_ids != data.alert_ids:
            data = data.model_copy(
                update={
                    "alert_ids": alert_ids,
                },
            )

        return await self.create_persisted(
            data,
            actor=actor,
        )

    # =========================================================================
    # Retrieval / Hydration
    # =========================================================================

    def get(
        self,
        incident_id: UUID,
    ) -> Incident:
        """Return one hydrated Incident."""

        incident = self._incidents.get(
            incident_id,
        )

        if incident is None:
            raise KeyError(
                f"incident not found: {incident_id}"
            )

        return incident

    def list_incidents(self) -> list[Incident]:
        """Return all hydrated Incidents."""

        return list(
            self._incidents.values(),
        )

    def hydrate(
        self,
        incidents: Iterable[Incident],
    ) -> None:
        """Hydrate persisted Incidents into domain state."""

        for incident in incidents:
            if not isinstance(
                incident,
                Incident,
            ):
                raise TypeError(
                    "incidents must contain Incident instances"
                )

            self._incidents[
                incident.incident_id
            ] = incident

            self._audit.setdefault(
                incident.incident_id,
                [],
            )

    def hydrate_audit(
        self,
        incident_id: UUID,
        entries: Iterable[IncidentAuditEntry],
    ) -> None:
        """Hydrate persisted audit entries."""

        hydrated: list[IncidentAuditEntry] = []
        seen_ids: set[UUID] = set()

        for entry in entries:
            if not isinstance(
                entry,
                IncidentAuditEntry,
            ):
                raise TypeError(
                    "entries must contain IncidentAuditEntry instances"
                )

            if entry.incident_id != incident_id:
                raise ValueError(
                    "audit incident_id does not match requested incident_id"
                )

            if entry.audit_id in seen_ids:
                continue

            seen_ids.add(
                entry.audit_id,
            )

            hydrated.append(
                entry,
            )

        hydrated.sort(
            key=lambda item: (
                item.created_at,
                str(item.audit_id),
            )
        )

        self._audit[
            incident_id
        ] = hydrated

    def hydrate_investigation(
        self,
        incident_id: UUID,
        notes: Iterable[InvestigationNote],
    ) -> tuple[InvestigationNote, ...]:
        """Hydrate persisted investigation notes."""

        self.get(
            incident_id,
        )

        return self._investigation.hydrate(
            incident_id,
            notes,
        )

    def hydrate_evidence(
        self,
        incident_id: UUID,
        records: Iterable[EvidenceRecord],
    ) -> tuple[EvidenceRecord, ...]:
        """Hydrate persisted evidence."""

        self.get(
            incident_id,
        )

        hydrated = self._evidence.hydrate(
            incident_id,
            records,
        )

        incident = self.get(
            incident_id,
        )

        evidence_ids = tuple(
            record.evidence_id
            for record in hydrated
        )

        merged_ids = tuple(
            dict.fromkeys(
                incident.evidence_ids
                + evidence_ids,
            )
        )

        if merged_ids != incident.evidence_ids:
            updated = incident.model_copy(
                update={
                    "evidence_ids": merged_ids,
                },
            )

            self._incidents[
                incident_id
            ] = updated

    def hydrate_timeline(
        self,
        incident_id: UUID,
        entries: Iterable[TimelineEntry],
    ) -> tuple[TimelineEntry, ...]:
        """Hydrate persisted timeline entries."""

        self.get(
            incident_id,
        )

        return self._timeline.hydrate(
            incident_id,
            entries,
        )

    def hydrate_related_state(
        self,
        incident: Incident,
        *,
        audit: Iterable[IncidentAuditEntry] = (),
        notes: Iterable[InvestigationNote] = (),
        evidence: Iterable[EvidenceRecord] = (),
        timeline: Iterable[TimelineEntry] = (),
    ) -> None:
        """Hydrate an Incident and all owned supporting state."""

        self.hydrate(
            [incident],
        )

        self.hydrate_audit(
            incident.incident_id,
            audit,
        )

        self.hydrate_investigation(
            incident.incident_id,
            notes,
        )

        self.hydrate_evidence(
            incident.incident_id,
            evidence,
        )

        self.hydrate_timeline(
            incident.incident_id,
            timeline,
        )

    # =========================================================================
    # Incident Update
    # =========================================================================

    def update(
        self,
        incident_id: UUID,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: IncidentSeverity | None = None,
        assignee: UUID | None = None,
        status: IncidentStatus | None = None,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """
        Update mutable Incident fields.

        Supported fields:

            - title
            - description
            - severity
            - assignee
            - status

        Status transitions are always validated through IncidentLifecycle.

        Assignee UUID validation beyond UUID syntax belongs to the API/
        application boundary through User Management.
        """

        (
            updated,
            audits,
            timeline_entries,
        ) = self._update_domain_state(
            incident_id,
            title=title,
            description=description,
            severity=severity,
            assignee=assignee,
            status=status,
            actor=actor,
            reason=reason,
        )

        self._schedule_incident_persistence(
            updated,
        )

        for audit in audits:
            self._schedule_audit_persistence(
                audit,
            )

        for entry in timeline_entries:
            self._schedule_timeline_persistence(
                entry,
            )

        self._schedule_realtime_publish(
            updated,
            event_type="updated",
        )

        return updated

    async def update_persisted(
        self,
        incident_id: UUID,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: IncidentSeverity | None = None,
        assignee: UUID | None = None,
        status: IncidentStatus | None = None,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """Update an Incident and wait for persistence."""

        (
            updated,
            audits,
            timeline_entries,
        ) = self._update_domain_state(
            incident_id,
            title=title,
            description=description,
            severity=severity,
            assignee=assignee,
            status=status,
            actor=actor,
            reason=reason,
        )

        await self._persist_incident(
            updated,
        )

        for audit in audits:
            await self._persist_audit(
                audit,
            )

        for entry in timeline_entries:
            await self._persist_timeline(
                entry,
            )

        self._schedule_realtime_publish(
            updated,
            event_type="updated",
        )

        return updated

    def _update_domain_state(
        self,
        incident_id: UUID,
        *,
        title: str | None,
        description: str | None,
        severity: IncidentSeverity | None,
        assignee: UUID | None,
        status: IncidentStatus | None,
        actor: str,
        reason: str,
    ) -> tuple[
        Incident,
        tuple[IncidentAuditEntry, ...],
        tuple[TimelineEntry, ...],
    ]:
        """Apply all requested Incident changes atomically in memory."""

        incident = self.get(
            incident_id,
        )

        normalized_actor = (
            self._normalize_required_text(
                actor,
                "actor",
            )
        )

        normalized_reason = reason.strip()

        update: dict[str, object] = {}

        audits: list[IncidentAuditEntry] = []
        timeline_entries: list[TimelineEntry] = []

        # ---------------------------------------------------------------------
        # Title
        # ---------------------------------------------------------------------

        if title is not None:
            normalized_title = (
                self._normalize_required_text(
                    title,
                    "title",
                )
            )

            if normalized_title != incident.title:
                update["title"] = normalized_title

                audit = IncidentAuditEntry(
                    incident_id=incident_id,
                    action="incident_updated",
                    actor=normalized_actor,
                    field_name="title",
                    from_value=incident.title,
                    to_value=normalized_title,
                    reason=normalized_reason,
                )

                audits.append(audit)

                timeline_entries.append(
                    self._timeline.add(
                        incident_id,
                        event_type="incident_updated",
                        description="Incident title changed",
                        actor=normalized_actor,
                    )
                )

        # ---------------------------------------------------------------------
        # Description
        # ---------------------------------------------------------------------

        if description is not None:
            normalized_description = (
                self._normalize_required_text(
                    description,
                    "description",
                )
            )

            if normalized_description != incident.description:
                update["description"] = normalized_description

                audit = IncidentAuditEntry(
                    incident_id=incident_id,
                    action="incident_updated",
                    actor=normalized_actor,
                    field_name="description",
                    from_value=incident.description,
                    to_value=normalized_description,
                    reason=normalized_reason,
                )

                audits.append(audit)

                timeline_entries.append(
                    self._timeline.add(
                        incident_id,
                        event_type="incident_updated",
                        description="Incident description changed",
                        actor=normalized_actor,
                    )
                )

        # ---------------------------------------------------------------------
        # Severity
        # ---------------------------------------------------------------------

        if severity is not None:
            if not isinstance(
                severity,
                IncidentSeverity,
            ):
                raise ValueError(
                    "severity must be a valid IncidentSeverity"
                )

            if severity != incident.severity:
                update["severity"] = severity

                audits.append(
                    IncidentAuditEntry(
                        incident_id=incident_id,
                        action="incident_severity_changed",
                        actor=normalized_actor,
                        from_severity=incident.severity,
                        to_severity=severity,
                        reason=normalized_reason,
                    )
                )

                timeline_entries.append(
                    self._timeline.add(
                        incident_id,
                        event_type="severity_changed",
                        description=(
                            f"{incident.severity.value}"
                            f" -> "
                            f"{severity.value}"
                        ),
                        actor=normalized_actor,
                    )
                )

        # ---------------------------------------------------------------------
        # Assignee
        # ---------------------------------------------------------------------

        if assignee is not None:
            if not isinstance(
                assignee,
                UUID,
            ):
                raise ValueError(
                    "assignee must be a valid user UUID"
                )

        # ``None`` is also a valid value for explicit unassignment.
        # Because None can mean "not supplied" or "unassign", the dedicated
        # assignment method below should be used when an API needs to clear
        # an assignee. This generic update only applies a concrete UUID.
        if assignee is not None and assignee != incident.assigned_to:
            update["assigned_to"] = assignee

            audits.append(
                IncidentAuditEntry(
                    incident_id=incident_id,
                    action=(
                        "incident_reassigned"
                        if incident.assigned_to is not None
                        else "incident_assigned"
                    ),
                    actor=normalized_actor,
                    from_assignee=incident.assigned_to,
                    to_assignee=assignee,
                    reason=normalized_reason,
                )
            )

            timeline_entries.append(
                self._timeline.add(
                    incident_id,
                    event_type="assignment_changed",
                    description="Incident assignee changed",
                    actor=normalized_actor,
                )
            )

        # ---------------------------------------------------------------------
        # Status
        # ---------------------------------------------------------------------

        current = incident

        if update:
            current = incident.model_copy(
                update=update,
            )

        if status is not None:
            if not isinstance(
                status,
                IncidentStatus,
            ):
                raise ValueError(
                    "status must be a valid IncidentStatus"
                )

            if status != current.status:
                current, status_audit = (
                    self._lifecycle.transition(
                        current,
                        status,
                        actor=normalized_actor,
                        reason=normalized_reason,
                    )
                )

                audits.append(
                    status_audit,
                )

                timeline_entries.append(
                    self._timeline.add(
                        incident_id,
                        event_type="status_changed",
                        description=(
                            f"{incident.status.value}"
                            f" -> "
                            f"{status.value}"
                        ),
                        actor=normalized_actor,
                    )
                )

        # ---------------------------------------------------------------------
        # Updated timestamp
        # ---------------------------------------------------------------------

        if update or status is not None:
            current = current.model_copy(
                update={
                    "updated_at": datetime.now(UTC),
                }
            )

        # ---------------------------------------------------------------------
        # No-op protection
        # ---------------------------------------------------------------------

        if current == incident:
            return (
                incident,
                (),
                (),
            )

        self._incidents[
            incident_id
        ] = current

        for audit in audits:
            self._record(
                current,
                audit,
            )

        return (
            current,
            tuple(audits),
            tuple(timeline_entries),
        )

    # =========================================================================
    # Dedicated Assignment
    # =========================================================================

    def assign(
        self,
        incident_id: UUID,
        *,
        assignee: UUID | None,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """
        Assign, reassign or explicitly unassign an Incident.

        ``None`` means unassigned.
        """

        incident = self.get(
            incident_id,
        )

        normalized_actor = (
            self._normalize_required_text(
                actor,
                "actor",
            )
        )

        if assignee is not None and not isinstance(
            assignee,
            UUID,
        ):
            raise ValueError(
                "assignee must be a valid user UUID or None"
            )

        if assignee == incident.assigned_to:
            return incident

        updated = self._assignment.assign(
            incident,
            assignee=assignee,
        )

        self._incidents[
            incident_id
        ] = updated

        action = (
            "incident_reassigned"
            if incident.assigned_to is not None
            and assignee is not None
            else "incident_assigned"
            if assignee is not None
            else "incident_reassigned"
        )

        audit = IncidentAuditEntry(
            incident_id=incident_id,
            action=action,
            actor=normalized_actor,
            from_assignee=incident.assigned_to,
            to_assignee=assignee,
            reason=reason.strip(),
            created_at=updated.updated_at,
        )

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="assignment_changed",
            description=(
                "Incident assigned"
                if assignee is not None
                else "Incident unassigned"
            ),
            actor=normalized_actor,
        )

        self._schedule_incident_persistence(
            updated,
        )

        self._schedule_audit_persistence(
            audit,
        )

        self._schedule_timeline_persistence(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type="assignment_changed",
        )

        return updated

    async def assign_persisted(
        self,
        incident_id: UUID,
        *,
        assignee: UUID | None,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """Assign/reassign/unassign and wait for persistence."""

        incident = self.get(
            incident_id,
        )

        normalized_actor = (
            self._normalize_required_text(
                actor,
                "actor",
            )
        )

        if assignee is not None and not isinstance(
            assignee,
            UUID,
        ):
            raise ValueError(
                "assignee must be a valid user UUID or None"
            )

        if assignee == incident.assigned_to:
            return incident

        updated = self._assignment.assign(
            incident,
            assignee=assignee,
        )

        self._incidents[
            incident_id
        ] = updated

        audit = IncidentAuditEntry(
            incident_id=incident_id,
            action=(
                "incident_reassigned"
                if incident.assigned_to is not None
                else "incident_assigned"
            ),
            actor=normalized_actor,
            from_assignee=incident.assigned_to,
            to_assignee=assignee,
            reason=reason.strip(),
            created_at=updated.updated_at,
        )

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="assignment_changed",
            description=(
                "Incident assigned"
                if assignee is not None
                else "Incident unassigned"
            ),
            actor=normalized_actor,
        )

        await self._persist_incident(
            updated,
        )

        await self._persist_audit(
            audit,
        )

        await self._persist_timeline(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type="assignment_changed",
        )

        return updated

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def transition(
        self,
        incident_id: UUID,
        target: IncidentStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """Apply one validated lifecycle transition."""

        incident = self.get(
            incident_id,
        )

        normalized_actor = (
            self._normalize_required_text(
                actor,
                "actor",
            )
        )

        updated, audit = self._lifecycle.transition(
            incident,
            target,
            actor=normalized_actor,
            reason=reason.strip(),
        )

        self._incidents[
            incident_id
        ] = updated

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="status_changed",
            description=(
                f"{incident.status.value}"
                f" -> "
                f"{target.value}"
            ),
            actor=normalized_actor,
        )

        self._schedule_incident_persistence(
            updated,
        )

        self._schedule_audit_persistence(
            audit,
        )

        self._schedule_timeline_persistence(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type=f"status:{target.value}",
        )

        return updated

    async def transition_persisted(
        self,
        incident_id: UUID,
        target: IncidentStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """Apply lifecycle transition and wait for persistence."""

        incident = self.get(
            incident_id,
        )

        normalized_actor = (
            self._normalize_required_text(
                actor,
                "actor",
            )
        )

        updated, audit = self._lifecycle.transition(
            incident,
            target,
            actor=normalized_actor,
            reason=reason.strip(),
        )

        self._incidents[
            incident_id
        ] = updated

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="status_changed",
            description=(
                f"{incident.status.value}"
                f" -> "
                f"{target.value}"
            ),
            actor=normalized_actor,
        )

        await self._persist_incident(
            updated,
        )

        await self._persist_audit(
            audit,
        )

        await self._persist_timeline(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type=f"status:{target.value}",
        )

        return updated

    # =========================================================================
    # Investigation
    # =========================================================================

    def add_note(
        self,
        incident_id: UUID,
        *,
        author: str,
        content: str,
    ) -> InvestigationNote:
        """Add an investigation note."""

        incident = self.get(
            incident_id,
        )

        note = self._investigation.add_note(
            incident_id,
            author=author,
            content=content,
        )

        updated = incident.model_copy(
            update={
                "updated_at": note.created_at,
            }
        )

        self._incidents[
            incident_id
        ] = updated

        audit = IncidentAuditEntry(
            incident_id=incident_id,
            action="incident_updated",
            actor=note.author,
            reason="Investigation note added",
            created_at=note.created_at,
        )

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="investigation_note_added",
            description="Investigation note added",
            actor=note.author,
        )

        self._schedule_incident_persistence(
            updated,
        )

        self._schedule_note_persistence(
            note,
        )

        self._schedule_audit_persistence(
            audit,
        )

        self._schedule_timeline_persistence(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type="investigation_note",
        )

        return note

    async def add_note_persisted(
        self,
        incident_id: UUID,
        *,
        author: str,
        content: str,
    ) -> InvestigationNote:
        """Add investigation note and wait for persistence."""

        incident = self.get(
            incident_id,
        )

        note = self._investigation.add_note(
            incident_id,
            author=author,
            content=content,
        )

        updated = incident.model_copy(
            update={
                "updated_at": note.created_at,
            }
        )

        self._incidents[
            incident_id
        ] = updated

        audit = IncidentAuditEntry(
            incident_id=incident_id,
            action="incident_updated",
            actor=note.author,
            reason="Investigation note added",
            created_at=note.created_at,
        )

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="investigation_note_added",
            description="Investigation note added",
            actor=note.author,
        )

        await self._persist_incident(
            updated,
        )

        await self._persist_note(
            note,
        )

        await self._persist_audit(
            audit,
        )

        await self._persist_timeline(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type="investigation_note",
        )

        return note

    def notes(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        """Return investigation notes."""

        self.get(
            incident_id,
        )

        return self._investigation.list_notes(
            incident_id,
        )

    # =========================================================================
    # Evidence
    # =========================================================================

    def add_evidence(
        self,
        incident_id: UUID,
        *,
        evidence_id: str,
        evidence_type: str,
        reference: str,
        collected_by: str,
    ) -> EvidenceRecord:
        """Attach evidence to an Incident."""

        incident = self.get(
            incident_id,
        )

        record = self._evidence.add(
            incident_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            reference=reference,
            collected_by=collected_by,
        )

        evidence_ids = tuple(
            dict.fromkeys(
                incident.evidence_ids
                + (record.evidence_id,),
            )
        )

        updated = incident.model_copy(
            update={
                "evidence_ids": evidence_ids,
                "updated_at": record.created_at,
            }
        )

        self._incidents[
            incident_id
        ] = updated

        audit = IncidentAuditEntry(
            incident_id=incident_id,
            action="incident_updated",
            actor=record.collected_by,
            reason=(
                f"Evidence added: "
                f"{record.evidence_id}"
            ),
            created_at=record.created_at,
        )

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="evidence_added",
            description=(
                f"{record.evidence_type}: "
                f"{record.evidence_id}"
            ),
            actor=record.collected_by,
        )

        self._schedule_incident_persistence(
            updated,
        )

        self._schedule_evidence_persistence(
            record,
        )

        self._schedule_audit_persistence(
            audit,
        )

        self._schedule_timeline_persistence(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type="evidence_added",
        )

        return record

    async def add_evidence_persisted(
        self,
        incident_id: UUID,
        *,
        evidence_id: str,
        evidence_type: str,
        reference: str,
        collected_by: str,
    ) -> EvidenceRecord:
        """Attach evidence and wait for persistence."""

        incident = self.get(
            incident_id,
        )

        record = self._evidence.add(
            incident_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            reference=reference,
            collected_by=collected_by,
        )

        evidence_ids = tuple(
            dict.fromkeys(
                incident.evidence_ids
                + (record.evidence_id,),
            )
        )

        updated = incident.model_copy(
            update={
                "evidence_ids": evidence_ids,
                "updated_at": record.created_at,
            }
        )

        self._incidents[
            incident_id
        ] = updated

        audit = IncidentAuditEntry(
            incident_id=incident_id,
            action="incident_updated",
            actor=record.collected_by,
            reason=(
                f"Evidence added: "
                f"{record.evidence_id}"
            ),
            created_at=record.created_at,
        )

        self._record(
            updated,
            audit,
        )

        timeline_entry = self._timeline.add(
            incident_id,
            event_type="evidence_added",
            description=(
                f"{record.evidence_type}: "
                f"{record.evidence_id}"
            ),
            actor=record.collected_by,
        )

        await self._persist_incident(
            updated,
        )

        await self._persist_evidence(
            record,
        )

        await self._persist_audit(
            audit,
        )

        await self._persist_timeline(
            timeline_entry,
        )

        self._schedule_realtime_publish(
            updated,
            event_type="evidence_added",
        )

        return record

    def evidence(
        self,
        incident_id: UUID,
    ) -> tuple[EvidenceRecord, ...]:
        """Return Incident evidence."""

        self.get(
            incident_id,
        )

        return self._evidence.list(
            incident_id,
        )

    # =========================================================================
    # Timeline
    # =========================================================================

    def timeline(
        self,
        incident_id: UUID,
    ) -> tuple[TimelineEntry, ...]:
        """Return Incident timeline."""

        self.get(
            incident_id,
        )

        return self._timeline.list(
            incident_id,
        )

    # =========================================================================
    # Audit
    # =========================================================================

    def audit_history(
        self,
        incident_id: UUID,
    ) -> tuple[IncidentAuditEntry, ...]:
        """Return Incident audit history chronologically."""

        self.get(
            incident_id,
        )

        entries = self._audit.get(
            incident_id,
            (),
        )

        return tuple(
            sorted(
                entries,
                key=lambda item: (
                    item.created_at,
                    str(item.audit_id),
                ),
            )
        )

    # =========================================================================
    # Internal Audit
    # =========================================================================

    def _record(
        self,
        incident: Incident,
        audit: IncidentAuditEntry,
    ) -> None:
        """Register one audit entry in in-memory state."""

        entries = self._audit.setdefault(
            incident.incident_id,
            [],
        )

        if any(
            item.audit_id == audit.audit_id
            for item in entries
        ):
            return

        entries.append(
            audit,
        )

    # =========================================================================
    # Persistence
    # =========================================================================

    async def _persist_incident(
        self,
        incident: Incident,
    ) -> None:
        callback = self._incident_persister

        if callback is None:
            return

        await callback(
            incident,
        )

    async def _persist_audit(
        self,
        audit: IncidentAuditEntry,
    ) -> None:
        callback = self._audit_persister

        if callback is None:
            return

        await callback(
            audit,
        )

    async def _persist_note(
        self,
        note: InvestigationNote,
    ) -> None:
        callback = self._note_persister

        if callback is None:
            return

        await callback(
            note,
        )

    async def _persist_evidence(
        self,
        evidence: EvidenceRecord,
    ) -> None:
        callback = self._evidence_persister

        if callback is None:
            return

        await callback(
            evidence,
        )

    async def _persist_timeline(
        self,
        entry: TimelineEntry,
    ) -> None:
        callback = self._timeline_persister

        if callback is None:
            return

        await callback(
            entry,
        )

    # =========================================================================
    # Background Persistence
    # =========================================================================

    def _schedule_incident_persistence(
        self,
        incident: Incident,
    ) -> None:
        callback = self._incident_persister

        if callback is None:
            return

        self._schedule_coroutine(
            callback(
                incident,
            ),
            operation="Incident persistence",
        )

    def _schedule_audit_persistence(
        self,
        audit: IncidentAuditEntry,
    ) -> None:
        callback = self._audit_persister

        if callback is None:
            return

        self._schedule_coroutine(
            callback(
                audit,
            ),
            operation="Incident audit persistence",
        )

    def _schedule_note_persistence(
        self,
        note: InvestigationNote,
    ) -> None:
        callback = self._note_persister

        if callback is None:
            return

        self._schedule_coroutine(
            callback(
                note,
            ),
            operation="Investigation note persistence",
        )

    def _schedule_evidence_persistence(
        self,
        evidence: EvidenceRecord,
    ) -> None:
        callback = self._evidence_persister

        if callback is None:
            return

        self._schedule_coroutine(
            callback(
                evidence,
            ),
            operation="Incident evidence persistence",
        )

    def _schedule_timeline_persistence(
        self,
        entry: TimelineEntry,
    ) -> None:
        callback = self._timeline_persister

        if callback is None:
            return

        self._schedule_coroutine(
            callback(
                entry,
            ),
            operation="Incident timeline persistence",
        )

    @staticmethod
    def _schedule_coroutine(
        coroutine: Awaitable[None],
        *,
        operation: str,
    ) -> None:
        """Schedule an asynchronous callback safely."""

        if not inspect.isawaitable(
            coroutine,
        ):
            logger.error(
                "%s did not return an awaitable.",
                operation,
            )
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.error(
                "Cannot schedule %s: no running event loop.",
                operation,
            )
            return

        task = loop.create_task(
            coroutine,
        )

        def _done_callback(
            completed_task: asyncio.Task[None],
        ) -> None:
            if completed_task.cancelled():
                return

            try:
                completed_task.result()
            except Exception:
                logger.exception(
                    "%s failed.",
                    operation,
                )

        task.add_done_callback(
            _done_callback,
        )

    # =========================================================================
    # Realtime
    # =========================================================================

    def _schedule_realtime_publish(
        self,
        incident: Incident,
        *,
        event_type: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Schedule one Incident realtime event."""

        publisher = self._realtime_publisher

        if publisher is None:
            return

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            logger.debug(
                "Skipping Incident realtime publication: "
                "no running event loop.",
            )
            return

        payload: dict[str, Any] = {
            "event_type": event_type,
            "incident": incident.model_dump(
                mode="json",
            ),
        }

        if extra:
            payload.update(
                extra,
            )

        task = asyncio.create_task(
            self._publish_realtime(
                publisher,
                payload,
            )
        )

        task.add_done_callback(
            self._handle_realtime_task_result,
        )

    async def _publish_realtime(
        self,
        publisher: IncidentRealtimePublisher,
        payload: dict[str, Any],
    ) -> None:
        """Publish one realtime Incident event."""

        try:
            delivered = await publisher(
                payload,
            )

            logger.debug(
                "Incident realtime event published "
                "(event_type=%s delivered=%s)",
                payload.get("event_type"),
                delivered,
            )

        except Exception:
            logger.exception(
                "Incident realtime publication failed.",
            )

    @staticmethod
    def _handle_realtime_task_result(
        task: asyncio.Task[None],
    ) -> None:
        """Consume a realtime task result."""

        if task.cancelled():
            return

        try:
            task.result()
        except Exception:
            logger.exception(
                "Unhandled Incident realtime task failure.",
            )

    # =========================================================================
    # Validation
    # =========================================================================

    @staticmethod
    def _normalize_required_text(
        value: str,
        field_name: str,
    ) -> str:
        """Normalize and validate required text."""

        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{field_name} must be a string."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                f"{field_name} is required."
            )

        return normalized


__all__ = [
    "IncidentManager",
    "IncidentRealtimePublisher",
    "IncidentPersistenceCallback",
    "IncidentAuditPersistenceCallback",
    "IncidentNotePersistenceCallback",
    "IncidentEvidencePersistenceCallback",
    "IncidentTimelinePersistenceCallback",
]