from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from app.incidents.models import TimelineEntry


class IncidentTimeline:
    """
    Maintain an ordered Incident activity timeline.

    Timeline entries are immutable historical records. They are created by
    domain/application workflows and persisted by the repository layer.
    """

    def __init__(self) -> None:
        self._entries: dict[UUID, list[TimelineEntry]] = {}

    # ------------------------------------------------------------------------
    # Add
    # ------------------------------------------------------------------------

    def add(
        self,
        incident_id: UUID,
        *,
        event_type: str,
        description: str,
        actor: str,
    ) -> TimelineEntry:
        """Create and register one Incident timeline entry."""

        if not isinstance(incident_id, UUID):
            raise ValueError("incident_id must be a valid UUID")

        normalized_event_type = event_type.strip()
        normalized_description = description.strip()
        normalized_actor = actor.strip()

        if not normalized_event_type:
            raise ValueError("event_type is required")

        if not normalized_description:
            raise ValueError("description is required")

        if not normalized_actor:
            raise ValueError("actor is required")

        entry = TimelineEntry(
            incident_id=incident_id,
            event_type=normalized_event_type,
            description=normalized_description,
            actor=normalized_actor,
        )

        self._entries.setdefault(
            incident_id,
            [],
        ).append(entry)

        return entry

    # ------------------------------------------------------------------------
    # Hydration
    # ------------------------------------------------------------------------

    def hydrate(
        self,
        incident_id: UUID,
        entries: Iterable[TimelineEntry],
    ) -> tuple[TimelineEntry, ...]:
        """
        Replace in-memory timeline state with persisted entries.

        Duplicate entry IDs are ignored.
        """

        if not isinstance(incident_id, UUID):
            raise ValueError("incident_id must be a valid UUID")

        hydrated: list[TimelineEntry] = []
        seen_ids: set[UUID] = set()

        for entry in entries:
            if not isinstance(entry, TimelineEntry):
                raise TypeError(
                    "entries must contain TimelineEntry instances"
                )

            if entry.incident_id != incident_id:
                raise ValueError(
                    "timeline entry incident_id does not match "
                    "requested incident_id"
                )

            if entry.entry_id in seen_ids:
                continue

            seen_ids.add(entry.entry_id)
            hydrated.append(entry)

        hydrated.sort(
            key=lambda item: (
                item.occurred_at,
                str(item.entry_id),
            )
        )

        if hydrated:
            self._entries[incident_id] = hydrated
        else:
            self._entries.pop(
                incident_id,
                None,
            )

        return tuple(hydrated)

    def hydrate_entries(
        self,
        incident_id: UUID,
        entries: Iterable[TimelineEntry],
    ) -> tuple[TimelineEntry, ...]:
        """Explicit alias for hydrate()."""

        return self.hydrate(
            incident_id,
            entries,
        )

    # ------------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------------

    def get(
        self,
        incident_id: UUID,
        entry_id: UUID,
    ) -> TimelineEntry | None:
        """Return one timeline entry by ID."""

        entries = self._entries.get(
            incident_id,
            (),
        )

        for entry in entries:
            if entry.entry_id == entry_id:
                return entry

        return None

    def list(
        self,
        incident_id: UUID,
    ) -> tuple[TimelineEntry, ...]:
        """Return Incident timeline entries chronologically."""

        entries = self._entries.get(
            incident_id,
            (),
        )

        return tuple(
            sorted(
                entries,
                key=lambda item: (
                    item.occurred_at,
                    str(item.entry_id),
                ),
            )
        )

    # ------------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------------

    def exists(
        self,
        incident_id: UUID,
        entry_id: UUID,
    ) -> bool:
        """Return True when the specified timeline entry exists."""

        return self.get(
            incident_id,
            entry_id,
        ) is not None

    def count(
        self,
        incident_id: UUID,
    ) -> int:
        """Return the number of timeline entries."""

        return len(
            self._entries.get(
                incident_id,
                (),
            )
        )


__all__ = [
    "IncidentTimeline",
]