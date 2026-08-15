from __future__ import annotations

from uuid import UUID

from app.incidents.models import EvidenceRecord


class EvidenceService:
    """Attach and retrieve evidence records for incidents."""

    def __init__(self) -> None:
        self._evidence: dict[UUID, dict[str, EvidenceRecord]] = {}

    def add(
        self,
        incident_id: UUID,
        *,
        evidence_id: str,
        evidence_type: str,
        reference: str,
        collected_by: str,
    ) -> EvidenceRecord:
        if not collected_by.strip():
            raise ValueError("collected_by is required")

        record = EvidenceRecord(
            evidence_id=evidence_id,
            incident_id=incident_id,
            evidence_type=evidence_type,
            reference=reference,
            collected_by=collected_by,
        )
        bucket = self._evidence.setdefault(incident_id, {})
        if evidence_id in bucket:
            raise ValueError(f"duplicate evidence: {evidence_id}")
        bucket[evidence_id] = record
        return record

    def list(self, incident_id: UUID) -> tuple[EvidenceRecord, ...]:
        return tuple(self._evidence.get(incident_id, {}).values())
