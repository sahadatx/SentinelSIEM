from __future__ import annotations

from uuid import UUID

from app.incidents.models import InvestigationNote


class InvestigationService:
    """Manage investigator notes for an incident."""

    def __init__(self) -> None:
        self._notes: dict[UUID, list[InvestigationNote]] = {}

    def add_note(
        self,
        incident_id: UUID,
        *,
        author: str,
        content: str,
    ) -> InvestigationNote:
        if not author.strip():
            raise ValueError("author is required")

        note = InvestigationNote(
            incident_id=incident_id,
            author=author,
            content=content,
        )
        self._notes.setdefault(incident_id, []).append(note)
        return note

    def list_notes(self, incident_id: UUID) -> tuple[InvestigationNote, ...]:
        return tuple(self._notes.get(incident_id, ()))
