from __future__ import annotations

from uuid import UUID

from app.incidents.manager import IncidentManager
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


class IncidentService:
    """
    Application-facing facade for SentinelSIEM Incident workflows.

    The service intentionally remains thin.

    Responsibilities:

        - Expose Incident Manager operations to application/API layers
        - Keep domain orchestration inside IncidentManager
        - Provide a stable application-facing interface

    Business rules such as:

        - lifecycle transition validation
        - severity validation
        - assignment state changes
        - audit creation
        - timeline creation
        - persistence orchestration

    remain inside the IncidentManager/domain layer.

    User existence, role, active/locked state and permission checks belong
    to the API/application authorization boundary and User Management.
    """

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        manager: IncidentManager | None = None,
    ) -> None:
        self._manager = (
            manager
            or IncidentManager()
        )

    # =========================================================================
    # Incident
    # =========================================================================

    def create_incident(
        self,
        data: IncidentCreate,
        *,
        actor: str = "system",
    ) -> Incident:
        """
        Create a new security Incident.

        The Manager always creates the Incident with OPEN status.
        """

        return self._manager.create(
            data,
            actor=actor,
        )

    async def create_incident_persisted(
        self,
        data: IncidentCreate,
        *,
        actor: str = "system",
    ) -> Incident:
        """
        Create a new Incident and wait for persistence.
        """

        return await self._manager.create_persisted(
            data,
            actor=actor,
        )

    def create_from_alert(
        self,
        data: IncidentCreate,
        *,
        alert_id: UUID,
        actor: str = "system",
    ) -> Incident:
        """
        Create an Incident associated with an Alert.

        Alert lookup and duplicate-promotion checks are intentionally
        handled by the promotion/application layer.
        """

        return self._manager.create_from_alert(
            data,
            alert_id=alert_id,
            actor=actor,
        )

    async def create_from_alert_persisted(
        self,
        data: IncidentCreate,
        *,
        alert_id: UUID,
        actor: str = "system",
    ) -> Incident:
        """Create an Alert-linked Incident and wait for persistence."""

        return await self._manager.create_from_alert_persisted(
            data,
            alert_id=alert_id,
            actor=actor,
        )

    def get(
        self,
        incident_id: UUID,
    ) -> Incident:
        """Retrieve an Incident by ID."""

        return self._manager.get(
            incident_id,
        )

    def list_incidents(
        self,
    ) -> tuple[Incident, ...]:
        """Return all currently hydrated Incidents."""

        return tuple(
            self._manager.list_incidents(),
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
        Update an Incident.

        Supported mutable fields:

            - title
            - description
            - severity
            - assignee
            - status

        Lifecycle validation is delegated to IncidentManager.
        """

        return self._manager.update(
            incident_id,
            title=title,
            description=description,
            severity=severity,
            assignee=assignee,
            status=status,
            actor=actor,
            reason=reason,
        )

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
        """
        Update an Incident and wait for persistence.
        """

        return await self._manager.update_persisted(
            incident_id,
            title=title,
            description=description,
            severity=severity,
            assignee=assignee,
            status=status,
            actor=actor,
            reason=reason,
        )

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
        """
        Transition an Incident through the validated lifecycle.

        Canonical lifecycle:

            OPEN
              ↓
            INVESTIGATING
              ↓
            CONTAINED
              ↓
            RESOLVED
              ↓
            CLOSED
        """

        return self._manager.transition(
            incident_id,
            target,
            actor=actor,
            reason=reason,
        )

    async def transition_persisted(
        self,
        incident_id: UUID,
        target: IncidentStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """Transition an Incident and wait for persistence."""

        return await self._manager.transition_persisted(
            incident_id,
            target,
            actor=actor,
            reason=reason,
        )

    # =========================================================================
    # Assignment
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
        Assign, reassign or unassign an Incident.

        ``assignee`` is a User UUID.

        ``None`` explicitly means that the Incident is unassigned.

        User existence, role and account-state validation belongs to the
        API/application boundary through User Management.
        """

        return self._manager.assign(
            incident_id,
            assignee=assignee,
            actor=actor,
            reason=reason,
        )

    async def assign_persisted(
        self,
        incident_id: UUID,
        *,
        assignee: UUID | None,
        actor: str,
        reason: str = "",
    ) -> Incident:
        """Assign/reassign/unassign and wait for persistence."""

        return await self._manager.assign_persisted(
            incident_id,
            assignee=assignee,
            actor=actor,
            reason=reason,
        )

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
        """Add an investigation note to an Incident."""

        return self._manager.add_note(
            incident_id,
            author=author,
            content=content,
        )

    async def add_note_persisted(
        self,
        incident_id: UUID,
        *,
        author: str,
        content: str,
    ) -> InvestigationNote:
        """Add an investigation note and wait for persistence."""

        return await self._manager.add_note_persisted(
            incident_id,
            author=author,
            content=content,
        )

    def notes(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        """Return all investigation notes."""

        return self._manager.notes(
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
        """Attach an evidence record to an Incident."""

        return self._manager.add_evidence(
            incident_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            reference=reference,
            collected_by=collected_by,
        )

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

        return await self._manager.add_evidence_persisted(
            incident_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            reference=reference,
            collected_by=collected_by,
        )

    def evidence(
        self,
        incident_id: UUID,
    ) -> tuple[EvidenceRecord, ...]:
        """Return all evidence attached to an Incident."""

        return self._manager.evidence(
            incident_id,
        )

    # =========================================================================
    # Timeline
    # =========================================================================

    def timeline(
        self,
        incident_id: UUID,
    ) -> tuple[TimelineEntry, ...]:
        """Return the chronological Incident timeline."""

        return self._manager.timeline(
            incident_id,
        )

    # =========================================================================
    # Audit
    # =========================================================================

    def audit_history(
        self,
        incident_id: UUID,
    ) -> tuple[IncidentAuditEntry, ...]:
        """Return immutable Incident audit history."""

        return self._manager.audit_history(
            incident_id,
        )

    # =========================================================================
    # Hydration
    # =========================================================================

    def hydrate(
        self,
        incidents: list[Incident] | tuple[Incident, ...],
    ) -> None:
        """Hydrate persisted Incidents into the Manager."""

        self._manager.hydrate(
            incidents,
        )

    def hydrate_audit(
        self,
        incident_id: UUID,
        entries: list[IncidentAuditEntry]
        | tuple[IncidentAuditEntry, ...],
    ) -> None:
        """Hydrate persisted audit history."""

        self._manager.hydrate_audit(
            incident_id,
            entries,
        )

    def hydrate_investigation(
        self,
        incident_id: UUID,
        notes: list[InvestigationNote]
        | tuple[InvestigationNote, ...],
    ) -> tuple[InvestigationNote, ...]:
        """Hydrate persisted investigation notes."""

        return self._manager.hydrate_investigation(
            incident_id,
            notes,
        )

    def hydrate_evidence(
        self,
        incident_id: UUID,
        records: list[EvidenceRecord]
        | tuple[EvidenceRecord, ...],
    ) -> tuple[EvidenceRecord, ...]:
        """Hydrate persisted evidence."""

        return self._manager.hydrate_evidence(
            incident_id,
            records,
        )

    def hydrate_timeline(
        self,
        incident_id: UUID,
        entries: list[TimelineEntry]
        | tuple[TimelineEntry, ...],
    ) -> tuple[TimelineEntry, ...]:
        """Hydrate persisted timeline entries."""

        return self._manager.hydrate_timeline(
            incident_id,
            entries,
        )

    def hydrate_related_state(
        self,
        incident: Incident,
        *,
        audit: tuple[IncidentAuditEntry, ...] = (),
        notes: tuple[InvestigationNote, ...] = (),
        evidence: tuple[EvidenceRecord, ...] = (),
        timeline: tuple[TimelineEntry, ...] = (),
    ) -> None:
        """Hydrate an Incident together with its supporting state."""

        self._manager.hydrate_related_state(
            incident,
            audit=audit,
            notes=notes,
            evidence=evidence,
            timeline=timeline,
        )

    # =========================================================================
    # Manager Access
    # =========================================================================

    def manager(
        self,
    ) -> IncidentManager:
        """
        Return the underlying IncidentManager.

        Primarily intended for application wiring and dependency
        integration.
        """

        return self._manager


__all__ = [
    "IncidentService",
]