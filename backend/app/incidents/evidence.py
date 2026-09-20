from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from app.incidents.models import EvidenceRecord


class EvidenceService:
    """
    Manage immutable evidence records associated with Incidents.

    Evidence is historical investigation data. Once created, the domain
    service does not expose destructive removal operations.
    """

    def __init__(self) -> None:
        self._evidence: dict[
            UUID,
            dict[str, EvidenceRecord],
        ] = {}

    # ------------------------------------------------------------------------
    # Add
    # ------------------------------------------------------------------------

    def add(
        self,
        incident_id: UUID,
        *,
        evidence_id: str,
        evidence_type: str,
        reference: str,
        collected_by: str,
    ) -> EvidenceRecord:
        """
        Create and register one evidence record.

        Evidence IDs must be unique within an Incident.
        """

        if not isinstance(incident_id, UUID):
            raise ValueError("incident_id must be a valid UUID")

        normalized_evidence_id = evidence_id.strip()
        normalized_evidence_type = evidence_type.strip()
        normalized_reference = reference.strip()
        normalized_collected_by = collected_by.strip()

        if not normalized_evidence_id:
            raise ValueError("evidence_id is required")

        if not normalized_evidence_type:
            raise ValueError("evidence_type is required")

        if not normalized_reference:
            raise ValueError("reference is required")

        if not normalized_collected_by:
            raise ValueError("collected_by is required")

        bucket = self._evidence.setdefault(
            incident_id,
            {},
        )

        if normalized_evidence_id in bucket:
            raise ValueError(
                f"duplicate evidence: {normalized_evidence_id}"
            )

        record = EvidenceRecord(
            evidence_id=normalized_evidence_id,
            incident_id=incident_id,
            evidence_type=normalized_evidence_type,
            reference=normalized_reference,
            collected_by=normalized_collected_by,
        )

        bucket[normalized_evidence_id] = record

        return record

    # ------------------------------------------------------------------------
    # Hydration
    # ------------------------------------------------------------------------

    def hydrate(
        self,
        incident_id: UUID,
        records: Iterable[EvidenceRecord],
    ) -> tuple[EvidenceRecord, ...]:
        """
        Replace in-memory evidence state with persisted records.

        Duplicate evidence IDs are ignored.
        """

        if not isinstance(incident_id, UUID):
            raise ValueError("incident_id must be a valid UUID")

        hydrated: dict[str, EvidenceRecord] = {}

        for record in records:
            if not isinstance(record, EvidenceRecord):
                raise TypeError(
                    "records must contain EvidenceRecord instances"
                )

            if record.incident_id != incident_id:
                raise ValueError(
                    "evidence incident_id does not match "
                    "requested incident_id"
                )

            evidence_id = record.evidence_id.strip()

            if not evidence_id:
                raise ValueError(
                    "persisted evidence_id is required"
                )

            if evidence_id in hydrated:
                continue

            hydrated[evidence_id] = record

        if hydrated:
            self._evidence[incident_id] = hydrated
        else:
            self._evidence.pop(
                incident_id,
                None,
            )

        return self.list(incident_id)

    def hydrate_evidence(
        self,
        incident_id: UUID,
        records: Iterable[EvidenceRecord],
    ) -> tuple[EvidenceRecord, ...]:
        """Explicit alias for hydrate()."""

        return self.hydrate(
            incident_id,
            records,
        )

    # ------------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------------

    def get(
        self,
        incident_id: UUID,
        evidence_id: str,
    ) -> EvidenceRecord | None:
        """Return one evidence record by Incident and evidence ID."""

        normalized_evidence_id = evidence_id.strip()

        if not normalized_evidence_id:
            return None

        return self._evidence.get(
            incident_id,
            {},
        ).get(normalized_evidence_id)

    def list(
        self,
        incident_id: UUID,
    ) -> tuple[EvidenceRecord, ...]:
        """
        Return all evidence records chronologically.

        Evidence ID is used as a deterministic tie-breaker.
        """

        bucket = self._evidence.get(incident_id)

        if not bucket:
            return ()

        return tuple(
            sorted(
                bucket.values(),
                key=lambda record: (
                    record.created_at,
                    record.evidence_id,
                ),
            )
        )

    # ------------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------------

    def exists(
        self,
        incident_id: UUID,
        evidence_id: str,
    ) -> bool:
        """Return True when evidence exists."""

        return self.get(
            incident_id,
            evidence_id,
        ) is not None

    def count(
        self,
        incident_id: UUID,
    ) -> int:
        """Return the number of evidence records."""

        return len(
            self._evidence.get(
                incident_id,
                {},
            )
        )


__all__ = [
    "EvidenceService",
]