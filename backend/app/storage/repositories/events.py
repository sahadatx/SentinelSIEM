from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent


class EventSearchResult:
    """Immutable search result returned by event repositories."""

    def __init__(
        self,
        events: Sequence[CanonicalSecurityEvent | EnrichedEvent],
        total: int,
    ) -> None:
        self.events = tuple(events)
        self.total = total


class EventRepository(Protocol):
    """Repository contract for persisted security events."""

    async def save(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> None: ...

    async def get(
        self,
        event_id: UUID,
    ) -> CanonicalSecurityEvent | EnrichedEvent | None: ...

    async def search(
        self,
        *,
        query: str | None = None,
        source: str | None = None,
        source_ip: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> EventSearchResult: ...

    async def count(self) -> int: ...


class EventDocumentMapper(Protocol):
    """Contract for converting security events to and from documents."""

    def to_document(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> Mapping[str, object]: ...

    def from_document(
        self,
        document: Mapping[str, object],
    ) -> CanonicalSecurityEvent | EnrichedEvent: ...
