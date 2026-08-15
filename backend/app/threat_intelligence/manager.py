from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from app.threat_intelligence.models import (
    IOC,
    IOCCreate,
    IOCStatus,
    Reputation,
    utcnow,
)
from app.threat_intelligence.normalizer import IOCNormalizer
from app.threat_intelligence.validator import IOCValidator


class IOCManager:
    """Manage IOC lifecycle and in-memory IOC state."""

    def __init__(
        self,
        *,
        normalizer: IOCNormalizer | None = None,
        validator: IOCValidator | None = None,
    ) -> None:
        self._normalizer = normalizer or IOCNormalizer()
        self._validator = validator or IOCValidator()
        self._iocs: dict[UUID, IOC] = {}
        self._index: dict[tuple[str, str], UUID] = {}

    def create(self, data: IOCCreate) -> IOC:
        normalized = self._normalizer.normalize(
            data.ioc_type,
            data.value,
        )
        self._validator.validate(
            data.ioc_type,
            normalized,
            data.expiration,
        )

        key = (data.ioc_type.value, normalized)
        existing_id = self._index.get(key)
        now = utcnow()

        if existing_id is not None:
            existing = self._iocs[existing_id]
            updated = existing.model_copy(
                update={
                    "last_seen": now,
                    "confidence": max(existing.confidence, data.confidence),
                    "reputation": self._stronger_reputation(
                        existing.reputation,
                        data.reputation,
                    ),
                    "expiration": data.expiration or existing.expiration,
                }
            )
            self._iocs[existing_id] = updated
            return updated

        ioc = IOC(
            ioc_type=data.ioc_type,
            value=data.value,
            normalized_value=normalized,
            confidence=data.confidence,
            source=data.source,
            first_seen=now,
            last_seen=now,
            expiration=data.expiration,
            reputation=data.reputation,
            feed=data.feed,
            metadata=data.metadata,
        )
        self._iocs[ioc.ioc_id] = ioc
        self._index[key] = ioc.ioc_id
        return ioc

    def get(self, ioc_id: UUID) -> IOC:
        try:
            return self._iocs[ioc_id]
        except KeyError as exc:
            raise KeyError(f"IOC not found: {ioc_id}") from exc

    def list_active(self) -> list[IOC]:
        return [
            ioc
            for ioc in self._iocs.values()
            if self._effective_status(ioc) == IOCStatus.ACTIVE
        ]

    def revoke(self, ioc_id: UUID) -> IOC:
        ioc = self.get(ioc_id)
        updated = ioc.model_copy(
            update={
                "status": IOCStatus.REVOKED,
                "last_seen": datetime.now(UTC),
            }
        )
        self._iocs[ioc_id] = updated
        return updated

    def _effective_status(self, ioc: IOC) -> IOCStatus:
        if (
            ioc.expiration is not None
            and ioc.expiration <= datetime.now(UTC)
            and ioc.status == IOCStatus.ACTIVE
        ):
            return IOCStatus.EXPIRED
        return ioc.status

    @staticmethod
    def _stronger_reputation(
        current: Reputation,
        incoming: Reputation,
    ) -> Reputation:
        ranking = {
            Reputation.UNKNOWN: 0,
            Reputation.BENIGN: 1,
            Reputation.SUSPICIOUS: 2,
            Reputation.MALICIOUS: 3,
        }
        return (
            incoming
            if ranking[incoming] > ranking[current]
            else current
        )
