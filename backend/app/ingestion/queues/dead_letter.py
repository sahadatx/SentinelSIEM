from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.domain.events.models import RawEvent


@dataclass(frozen=True, slots=True)
class DeadLetterRecord:
    """A permanently failed ingestion event."""

    event: RawEvent
    reason: str
    attempts: int
    failed_at: datetime

    def __post_init__(self) -> None:
        """Validate dead-letter record invariants."""
        if not self.reason.strip():
            raise ValueError("dead-letter reason must not be empty")

        if self.failed_at.tzinfo is None or self.failed_at.utcoffset() is None:
            raise ValueError("failed_at must be timezone-aware")

        if self.attempts < 1:
            raise ValueError("attempts must be greater than or equal to 1")

    @property
    def failed_at_utc(self) -> datetime:
        """Return the failure timestamp normalized to UTC."""
        return self.failed_at.astimezone(UTC)


class InMemoryDeadLetterQueue:
    """Deterministic in-memory DLQ for tests and local development."""

    def __init__(self) -> None:
        """Initialize an empty dead-letter queue."""
        self._records: list[DeadLetterRecord] = []

    async def put(
        self,
        record: DeadLetterRecord,
    ) -> None:
        """Append a failed event to the dead-letter queue."""
        self._records.append(record)

    async def all(self) -> tuple[DeadLetterRecord, ...]:
        """Return all stored dead-letter records."""
        return tuple(self._records)

    def size(self) -> int:
        """Return the current number of dead-letter records."""
        return len(self._records)

    def clear(self) -> None:
        """Remove all records from the in-memory queue."""
        self._records.clear()
