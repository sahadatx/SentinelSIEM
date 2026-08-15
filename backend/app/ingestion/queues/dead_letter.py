from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.domain.events.models import RawEvent


@dataclass(frozen=True, slots=True)
class DeadLetterRecord:
    event: RawEvent
    reason: str
    attempts: int
    failed_at: datetime

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("dead-letter reason must not be empty")
        if self.failed_at.tzinfo is None or self.failed_at.utcoffset() is None:
            raise ValueError("failed_at must be timezone-aware")

    @property
    def failed_at_utc(self) -> datetime:
        return self.failed_at.astimezone(UTC)


class InMemoryDeadLetterQueue:
    """Deterministic DLQ foundation for tests and local development."""

    def __init__(self) -> None:
        self._records: list[DeadLetterRecord] = []

    async def put(self, record: DeadLetterRecord) -> None:
        self._records.append(record)

    async def all(self) -> tuple[DeadLetterRecord, ...]:
        return tuple(self._records)

    def size(self) -> int:
        return len(self._records)
