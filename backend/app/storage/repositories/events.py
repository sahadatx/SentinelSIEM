from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
)


class EventSearchResult:
    """Immutable search result returned by event repositories."""

    def __init__(
        self,
        events: Sequence[CanonicalSecurityEvent | EnrichedEvent],
        total: int,
    ) -> None:
        self.events = tuple(events)
        self.total = total


class EventFilterOptionsResult:
    """
    Immutable dynamic values used by Events filter dropdowns.

    Values are supplied by the persistence layer from actual
    persisted event data. The repository must not hardcode them.
    """

    def __init__(
        self,
        *,
        sources: Sequence[str] = (),
        users: Sequence[str] = (),
        actions: Sequence[str] = (),
        outcomes: Sequence[str] = (),
        severities: Sequence[str] = (),
        categories: Sequence[str] = (),
    ) -> None:
        self.sources = tuple(sources)
        self.users = tuple(users)
        self.actions = tuple(actions)
        self.outcomes = tuple(outcomes)
        self.severities = tuple(severities)
        self.categories = tuple(categories)


class EventStatisticsResult:
    """
    Immutable aggregate statistics for persisted security events.

    Statistics represent the complete filtered dataset and are
    intentionally independent of pagination.
    """

    def __init__(
        self,
        *,
        total: int = 0,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        info: int = 0,
    ) -> None:
        self.total = total
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.info = info


class EventRepository(Protocol):
    """Repository contract for persisted security events."""

    async def save(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> None:
        """Persist a canonical or enriched security event."""
        ...

    async def get(
        self,
        event_id: UUID,
    ) -> CanonicalSecurityEvent | EnrichedEvent | None:
        """Retrieve a single event by its event ID."""
        ...

    async def search(
        self,
        *,
        query: str | None = None,
        source: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        username: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> EventSearchResult:
        """
        Search persisted security events.

        Supported filtering dimensions:

        - free-text query
        - source
        - source IP
        - destination IP
        - username
        - action
        - outcome
        - severity
        - category
        - start timestamp
        - end timestamp

        Pagination is expressed through zero-based offset and limit.
        """
        ...

    async def get_statistics(
        self,
        *,
        query: str | None = None,
        source: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        username: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> EventStatisticsResult:
        """
        Return aggregate statistics for persisted security events.

        The statistics must represent the complete filtered dataset
        and must not be affected by search pagination.

        Supported filtering dimensions:

        - free-text query
        - source
        - source IP
        - destination IP
        - username
        - action
        - outcome
        - severity
        - category
        - start timestamp
        - end timestamp

        Implementations should calculate the severity distribution
        from the persistence layer rather than from the current
        paginated event page.
        """
        ...

    async def get_filter_options(
        self,
    ) -> EventFilterOptionsResult:
        """
        Return unique values for Events filter dropdowns.

        Values must be derived from persisted event data rather than
        hardcoded in the repository or frontend.
        """
        ...

    async def count(self) -> int:
        """Return the total number of persisted security events."""
        ...


class EventDocumentMapper(Protocol):
    """Contract for converting security events to and from documents."""

    def to_document(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> Mapping[str, object]:
        """Convert a security event into a persistence document."""
        ...

    def from_document(
        self,
        document: Mapping[str, object],
    ) -> CanonicalSecurityEvent | EnrichedEvent:
        """Reconstruct a security event from a persistence document."""
        ...