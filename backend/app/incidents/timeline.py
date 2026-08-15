from __future__ import annotations

from uuid import UUID

from app.incidents.models import TimelineEntry


class IncidentTimeline:
    """Maintain an ordered timeline of incident activity."""

    def __init__(self) -> None:
        self._entries: dict[UUID, list[TimelineEntry]] = {}

    def add(
        self,
        incident_id: UUID,
        *,
        event_type: str,
        description: str,
        actor: str,
    ) -> TimelineEntry:
        if not actor.strip():
            raise ValueError("actor is required")

        entry = TimelineEntry(
            incident_id=incident_id,
            event_type=event_type,
            description=description,
            actor=actor,
        )
        self._entries.setdefault(incident_id, []).append(entry)
        return entry

    def list(self, incident_id: UUID) -> tuple[TimelineEntry, ...]:
        entries = self._entries.get(incident_id, ())
        return tuple(sorted(entries, key=lambda item: item.occurred_at))
