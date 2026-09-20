"""
SentinelSIEM Incident Investigation Service

============================================

In-memory domain service for incident investigation notes.

Responsibilities
----------------

This module is responsible only for:

    - creating investigation notes
    - storing notes in application-scoped in-memory state
    - hydrating persisted notes
    - retrieving individual notes
    - listing notes
    - removing notes from in-memory state
    - clearing incident note state

Persistence remains owned by the IncidentManager/repository layer.

This service does NOT:

    - access OpenSearch
    - access PostgreSQL
    - perform authentication
    - perform authorization
    - persist audit records
    - perform HTTP handling
    - contain API/business orchestration
"""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from app.incidents.models import InvestigationNote


# ============================================================================
# Investigation Service
# ============================================================================


class InvestigationService:
    """
    Manage investigator notes for an incident.

    Notes are maintained in application-scoped in-memory state.

    Persistence is intentionally delegated to the IncidentManager and
    repository layers.
    """

    def __init__(self) -> None:
        """
        Initialize the investigation note store.
        """

        self._notes: dict[UUID, list[InvestigationNote]] = {}

    # =========================================================================
    # Create
    # =========================================================================

    def add_note(
        self,
        incident_id: UUID,
        *,
        author: str,
        content: str,
    ) -> InvestigationNote:
        """
        Add one investigation note to an incident.

        The newly created note is stored in the in-memory domain state
        and returned to the caller for persistence by the manager/repository.
        """

        normalized_author = author.strip()
        normalized_content = content.strip()

        if not normalized_author:
            raise ValueError(
                "author is required",
            )

        if not normalized_content:
            raise ValueError(
                "content is required",
            )

        note = InvestigationNote(
            incident_id=incident_id,
            author=normalized_author,
            content=normalized_content,
        )

        self._notes.setdefault(
            incident_id,
            [],
        ).append(note)

        return note

    # =========================================================================
    # Hydration
    # =========================================================================

    def hydrate_notes(
        self,
        incident_id: UUID,
        notes: Iterable[InvestigationNote],
    ) -> tuple[InvestigationNote, ...]:
        """
        Load persisted investigation notes into the in-memory service.

        Existing notes for the incident are replaced with the supplied
        persisted state.

        Duplicate note IDs are ignored.

        Notes are ordered chronologically by creation time with note_id
        used as a deterministic tie-breaker.
        """

        hydrated: list[InvestigationNote] = []
        seen_ids: set[UUID] = set()

        for note in notes:
            if not isinstance(
                note,
                InvestigationNote,
            ):
                raise TypeError(
                    "notes must contain InvestigationNote instances",
                )

            if note.incident_id != incident_id:
                raise ValueError(
                    "note incident_id does not match requested incident_id",
                )

            if note.note_id in seen_ids:
                continue

            seen_ids.add(
                note.note_id,
            )

            hydrated.append(
                note,
            )

        hydrated.sort(
            key=lambda item: (
                item.created_at,
                str(item.note_id),
            ),
        )

        if hydrated:
            self._notes[incident_id] = hydrated
        else:
            self._notes.pop(
                incident_id,
                None,
            )

        return tuple(
            hydrated,
        )

    def hydrate(
        self,
        incident_id: UUID,
        notes: Iterable[InvestigationNote],
    ) -> tuple[InvestigationNote, ...]:
        """
        Hydrate persisted investigation notes.

        This is the primary short-form hydration API used by the
        IncidentManager.
        """

        return self.hydrate_notes(
            incident_id,
            notes,
        )

    # =========================================================================
    # Retrieval
    # =========================================================================

    def get_note(
        self,
        incident_id: UUID,
        note_id: UUID,
    ) -> InvestigationNote | None:
        """
        Retrieve one investigation note by note ID.
        """

        notes = self._notes.get(
            incident_id,
            (),
        )

        for note in notes:
            if note.note_id == note_id:
                return note

        return None

    def list_notes(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        """
        Return all investigation notes for an incident.

        Notes are returned chronologically with note_id used as a
        deterministic tie-breaker.
        """

        notes = self._notes.get(
            incident_id,
            (),
        )

        if not notes:
            return ()

        return tuple(
            sorted(
                notes,
                key=lambda item: (
                    item.created_at,
                    str(item.note_id),
                ),
            )
        )

    # =========================================================================
    # Existence / Count
    # =========================================================================

    def has_notes(
        self,
        incident_id: UUID,
    ) -> bool:
        """
        Return True when the incident has at least one investigation note.
        """

        return bool(
            self._notes.get(
                incident_id,
            )
        )

    def count_notes(
        self,
        incident_id: UUID,
    ) -> int:
        """
        Return the number of investigation notes for an incident.
        """

        return len(
            self._notes.get(
                incident_id,
                (),
            )
        )

    # =========================================================================
    # Removal
    # =========================================================================

    def remove_note(
        self,
        incident_id: UUID,
        note_id: UUID,
    ) -> InvestigationNote | None:
        """
        Remove one investigation note from in-memory state.

        Returns the removed note, or None when the note does not exist.
        """

        notes = self._notes.get(
            incident_id,
        )

        if not notes:
            return None

        for index, note in enumerate(notes):
            if note.note_id != note_id:
                continue

            removed = notes.pop(
                index,
            )

            if not notes:
                self._notes.pop(
                    incident_id,
                    None,
                )

            return removed

        return None

    # =========================================================================
    # Clear
    # =========================================================================

    def clear_notes(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        """
        Remove and return all investigation notes for an incident.

        Returned notes remain chronologically ordered.
        """

        notes = self._notes.pop(
            incident_id,
            None,
        )

        if not notes:
            return ()

        return tuple(
            sorted(
                notes,
                key=lambda item: (
                    item.created_at,
                    str(item.note_id),
                ),
            )
        )

    def clear_incident(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        """
        Remove all in-memory investigation notes for an incident.

        Explicit alias for clear_notes().
        """

        return self.clear_notes(
            incident_id,
        )


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "InvestigationService",
]