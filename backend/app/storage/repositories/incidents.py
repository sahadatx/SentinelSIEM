from __future__ import annotations

"""
SentinelSIEM — Incident Repository Contract.

This module defines the storage abstraction used by the Incident
application/domain layers.

The concrete OpenSearch implementation must satisfy this protocol.

Canonical Incident contract
----------------------------

Lifecycle:

    open
    investigating
    contained
    resolved
    closed

Severity:

    critical
    high
    medium
    low
    informational

Assignment:

    assigned_to -> User UUID | None

The repository contract intentionally does NOT expose:

    - priority
    - ownership_group
    - Incident deletion

The repository is responsible only for persistence and retrieval.
Authorization, User Management validation and Incident business rules
remain outside this abstraction.
"""

from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.incidents.models import (
    EvidenceRecord,
    Incident,
    IncidentAuditEntry,
    InvestigationNote,
    TimelineEntry,
)


# =============================================================================
# Search Result
# =============================================================================


class IncidentSearchResult:
    """
    Result returned by IncidentRepository.search().
    """

    __slots__ = (
        "incidents",
        "total",
    )

    def __init__(
        self,
        incidents: tuple[Incident, ...],
        total: int,
    ) -> None:
        if not isinstance(
            incidents,
            tuple,
        ):
            raise TypeError(
                "incidents must be a tuple.",
            )

        if not isinstance(
            total,
            int,
        ):
            raise TypeError(
                "total must be an integer.",
            )

        if total < 0:
            raise ValueError(
                "total must be greater than or equal to 0.",
            )

        if total < len(incidents):
            raise ValueError(
                "total cannot be smaller than the number of returned "
                "incidents.",
            )

        self.incidents = incidents
        self.total = total

    def __repr__(self) -> str:
        return (
            "IncidentSearchResult("
            f"incidents={self.incidents!r}, "
            f"total={self.total!r}"
            ")"
        )


# =============================================================================
# Repository Protocol
# =============================================================================


class IncidentRepository(Protocol):
    """
    Persistence contract for SentinelSIEM security Incidents.

    The domain/application layer depends only on this abstraction.

    Concrete implementations may use:

        - OpenSearch
        - another search datastore
        - a test/in-memory repository

    Storage-specific details must remain outside this protocol.
    """

    # =========================================================================
    # Index / Storage Initialization
    # =========================================================================

    async def ensure_index(
        self,
    ) -> None:
        """
        Ensure all Incident-related persistence indexes exist.

        Implementations should provide storage for:

            - Incident documents
            - audit history
            - investigation notes
            - evidence
            - timeline entries
            - any required Incident metadata
        """

        ...

    # =========================================================================
    # Incident Persistence
    # =========================================================================

    async def save(
        self,
        incident: Incident,
    ) -> None:
        """
        Create or replace an Incident.

        The Incident aggregate is authoritative for:

            - incident_id
            - incident_number
            - title
            - description
            - severity
            - status
            - tags
            - alert relationships
            - evidence relationships
            - event relationships
            - IOC relationships
            - asset relationships
            - assignment
            - created_by
            - created_at
            - updated_at
            - resolved_at
            - closed_at

        The repository must not introduce additional domain fields.
        """

        ...

    async def get(
        self,
        incident_id: UUID,
    ) -> Incident | None:
        """
        Retrieve an Incident by UUID.

        Returns:

            Incident -> when the Incident exists.
            None     -> when it does not exist.
        """

        ...

    async def search(
        self,
        *,
        query: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: UUID | str | None = None,
        alert_id: UUID | None = None,
        asset_id: str | None = None,
        related_event_id: str | None = None,
        related_ioc_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> IncidentSearchResult:
        """
        Search persisted Incidents.

        Supported filters:

            - free-text query
            - lifecycle status
            - severity
            - assignee
            - related Alert
            - affected Asset
            - related Event
            - related IOC
            - updated-at time range
            - pagination

        The free-text query should support Incident identity/content such as:

            - incident_number
            - incident_id
            - title
            - description

        Results must be deterministic and pagination-safe.

        No priority or ownership-group filtering exists in the canonical
        Incident contract.
        """

        ...

    # =========================================================================
    # Incident Number
    # =========================================================================

    async def get_by_incident_number(
        self,
        incident_number: str,
    ) -> Incident | None:
        """
        Retrieve an Incident by its human-readable Incident number.

        Example:

            INC-2026-00021

        Incident numbers are expected to be unique.
        """

        ...

    # =========================================================================
    # Alert → Incident Promotion / Duplicate Protection
    # =========================================================================

    async def get_by_alert_id(
        self,
        alert_id: UUID,
    ) -> Incident | None:
        """
        Find the Incident already associated with an Alert.

        This is the repository-level duplicate-promotion lookup.

        If an Alert has already been promoted, the existing Incident is
        returned so the promotion service can reject a duplicate promotion.
        """

        ...

    async def get_related_alert_ids(
        self,
        incident_id: UUID,
    ) -> tuple[UUID, ...]:
        """
        Return Alert UUIDs related to an Incident.

        The repository returns relationship identifiers only.

        Alert details remain owned by the Alert domain/repository.
        """

        ...

    # =========================================================================
    # Investigation Notes
    # =========================================================================

    async def save_note(
        self,
        note: InvestigationNote,
    ) -> None:
        """
        Persist one immutable investigation note.

        A note belongs to exactly one Incident.
        """

        ...

    async def get_notes(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        """
        Retrieve all investigation notes for an Incident.

        Results must be returned in chronological order.
        """

        ...

    # =========================================================================
    # Evidence
    # =========================================================================

    async def save_evidence(
        self,
        evidence: EvidenceRecord,
    ) -> None:
        """
        Persist one immutable evidence record.

        Evidence belongs to exactly one Incident.
        """

        ...

    async def get_evidence(
        self,
        incident_id: UUID,
    ) -> tuple[EvidenceRecord, ...]:
        """
        Retrieve all evidence records for an Incident.

        Results must be returned in chronological order.
        """

        ...

    # =========================================================================
    # Timeline
    # =========================================================================

    async def save_timeline_entry(
        self,
        entry: TimelineEntry,
    ) -> None:
        """
        Persist one immutable Incident timeline entry.
        """

        ...

    async def get_timeline(
        self,
        incident_id: UUID,
    ) -> tuple[TimelineEntry, ...]:
        """
        Retrieve the complete chronological timeline for an Incident.
        """

        ...

    # =========================================================================
    # Audit
    # =========================================================================

    async def save_audit_entry(
        self,
        entry: IncidentAuditEntry,
    ) -> None:
        """
        Persist one immutable Incident audit entry.

        Audit entries may represent changes to:

            - status
            - severity
            - assignee
            - title
            - description
            - other explicitly auditable Incident fields
        """

        ...

    async def get_audit_history(
        self,
        incident_id: UUID,
    ) -> tuple[IncidentAuditEntry, ...]:
        """
        Retrieve immutable audit history for an Incident.

        Results must be returned in chronological order.
        """

        ...

    # =========================================================================
    # Statistics
    # =========================================================================

    async def count(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
    ) -> int:
        """
        Count persisted Incidents.

        Optional filters allow callers to obtain a scoped count without
        loading Incident documents.
        """

        ...

    async def statistics(
        self,
    ) -> dict[str, int]:
        """
        Return backend-authoritative Incident KPI statistics.

        Canonical response keys:

            total
            open
            investigating
            critical
            high
            resolved

        Values must be obtained from persisted Incident data.

        The repository must not calculate these values from a paginated
        Incident list.
        """

        ...

    async def summary(
        self,
    ) -> dict[str, int]:
        """
        Backward-compatible Incident KPI summary.

        New application/API code should prefer ``statistics()``.

        Implementations may delegate this method to ``statistics()``.

        Canonical response keys:

            total
            open
            investigating
            critical
            high
            resolved
        """

        ...

    async def count_by_status(
        self,
    ) -> dict[str, int]:
        """
        Return Incident counts grouped by canonical lifecycle status.

        Example:

            {
                "open": 5,
                "investigating": 2,
                "contained": 1,
                "resolved": 3,
                "closed": 4,
            }
        """

        ...

    async def count_by_severity(
        self,
    ) -> dict[str, int]:
        """
        Return Incident counts grouped by canonical severity.

        Example:

            {
                "critical": 2,
                "high": 4,
                "medium": 7,
                "low": 1,
                "informational": 2,
            }
        """

        ...

    # =========================================================================
    # Filter Options
    # =========================================================================

    async def get_filter_options(
        self,
    ) -> dict[str, tuple[str, ...]]:
        """
        Return distinct values used by the Incident filter UI.

        Canonical keys:

            statuses
            severities
            assignees

        Values must originate from persisted backend data.

        The repository must not introduce frontend/static filter values.
        """

        ...


# =============================================================================
# Public API
# =============================================================================


__all__ = [
    "IncidentRepository",
    "IncidentSearchResult",
]