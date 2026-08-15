from __future__ import annotations

from uuid import UUID

from app.threat_intelligence.cache import IOCMatchCache
from app.threat_intelligence.enrichment import IOCEnricher
from app.threat_intelligence.manager import IOCManager
from app.threat_intelligence.models import IOC, IOCCreate, IOCMatch


class ThreatIntelligenceService:
    """Application-facing service for IOC management and enrichment."""

    def __init__(
        self,
        *,
        manager: IOCManager | None = None,
        enricher: IOCEnricher | None = None,
        cache: IOCMatchCache | None = None,
    ) -> None:
        self._manager = manager or IOCManager()
        self._enricher = enricher or IOCEnricher()
        self._cache = cache or IOCMatchCache()

    def add_ioc(self, data: IOCCreate) -> IOC:
        ioc = self._manager.create(data)
        self._cache.clear()
        return ioc

    def get_ioc(self, ioc_id: UUID) -> IOC:
        return self._manager.get(ioc_id)

    def revoke_ioc(self, ioc_id: UUID) -> IOC:
        ioc = self._manager.revoke(ioc_id)
        self._cache.clear()
        return ioc

    def enrich(self, observable: str) -> tuple[IOCMatch, ...]:
        key = observable.strip().lower()
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        matches = self._enricher.enrich(
            observable,
            self._manager.list_active(),
        )
        self._cache.set(key, matches)
        return matches
