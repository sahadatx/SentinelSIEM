from __future__ import annotations

from typing import Protocol
from threading import RLock

from .models import AuditRecord


class AuditSink(Protocol):
    def record(self, event: AuditRecord) -> None: ...


class InMemoryAuditSink:
    """Deterministic sink for tests and local development.

    Production deployments should provide a durable repository adapter backed
    by the `siem_auth_audit` table from the migration.
    """

    def __init__(self) -> None:
        self._events: list[AuditRecord] = []
        self._lock = RLock()

    def record(self, event: AuditRecord) -> None:
        with self._lock:
            self._events.append(event)

    def all(self) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._events)
