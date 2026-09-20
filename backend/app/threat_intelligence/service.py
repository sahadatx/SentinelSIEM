from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.threat_intelligence.cache import IOCMatchCache
from app.threat_intelligence.enrichment import IOCEnricher
from app.threat_intelligence.manager import IOCManager
from app.threat_intelligence.models import (
    IOC,
    IOCCreate,
    IOCMatch,
    IOCRelationships,
    IOCSeverity,
    IOCStatus,
    Reputation,
    utcnow,
)


# ============================================================================
# Repository Contract
# ============================================================================


class IOCRepositoryProtocol(Protocol):
    """
    Persistence contract required by Threat Intelligence.

    The service depends only on this protocol and therefore remains
    independent from the concrete PostgreSQL repository implementation.

    IOC deletion is intentionally not part of the contract.

    Lifecycle operations are represented by persisted IOC updates:

        ACTIVE
        EXPIRED
        REVOKED
    """

    async def create(
        self,
        ioc: IOC,
    ) -> IOC:
        ...

    async def get(
        self,
        ioc_id: UUID,
    ) -> IOC | None:
        ...

    async def get_by_normalized_value(
        self,
        *,
        ioc_type: str,
        normalized_value: str,
    ) -> IOC | None:
        ...

    async def list(
        self,
        *,
        query: str | None = None,
        ioc_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        reputation: str | None = None,
        feed: str | None = None,
        active: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        page: int = 1,
        page_size: int = 30,
    ) -> tuple[list[IOC], int]:
        ...

    async def update(
        self,
        ioc: IOC,
    ) -> IOC:
        ...

    async def summary(
        self,
        *,
        recently_updated_since: datetime | None = None,
    ) -> dict[str, object]:
        ...

    async def filter_options(
        self,
    ) -> dict[str, list[str]]:
        ...

    async def relationships(
        self,
        ioc_id: UUID,
    ) -> dict[str, object]:
        ...


# ============================================================================
# Threat Intelligence Service
# ============================================================================


class ThreatIntelligenceService:
    """
    Application-facing Threat Intelligence service.

    Responsibilities:

        - IOC creation
        - IOC retrieval
        - IOC update
        - IOC search
        - IOC filtering
        - IOC pagination
        - IOC lifecycle orchestration
        - normalization
        - validation
        - persistence-aware deduplication
        - intelligence merging
        - severity management
        - reputation management
        - Enable / Activate IOC
        - Disable / Revoke IOC
        - enrichment / matching
        - match caching
        - relationship lookup
        - dashboard statistics
        - backend filter catalogues

    Architecture:

        API
          |
          v
        Service
          |
          +---- IOCManager
          |       |
          |       +---- normalization
          |       +---- validation
          |       +---- deduplication
          |       +---- domain rules
          |
          +---- IOCRepository
          |       |
          |       +---- PostgreSQL persistence
          |
          +---- IOCEnricher
          |
          +---- IOCMatchCache

    The manager owns domain rules.

    The repository owns persistence.

    The service orchestrates application behavior.

    IOC hard deletion is intentionally unsupported.
    """

    DEFAULT_PAGE_SIZE = 30
    MAX_PAGE_SIZE = 200

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        *,
        manager: IOCManager | None = None,
        enricher: IOCEnricher | None = None,
        cache: IOCMatchCache | None = None,
        repository: IOCRepositoryProtocol | None = None,
    ) -> None:
        self._manager = (
            manager
            or IOCManager()
        )

        self._enricher = (
            enricher
            or IOCEnricher()
        )

        self._cache = (
            cache
            or IOCMatchCache()
        )

        self._repository = repository

    # =========================================================================
    # Repository Configuration
    # =========================================================================

    def set_repository(
        self,
        repository: IOCRepositoryProtocol,
    ) -> None:
        """
        Attach the persistence repository.

        Kept for compatibility with existing application bootstrap code.
        """

        self._repository = repository

    def _require_repository(
        self,
    ) -> IOCRepositoryProtocol:
        """
        Return the configured repository.

        Raises:
            RuntimeError:
                Repository is not configured.
        """

        if self._repository is None:
            raise RuntimeError(
                "ThreatIntelligenceService repository is not configured",
            )

        return self._repository

    # =========================================================================
    # Manager Synchronization
    # =========================================================================

    def _sync_manager(
        self,
        ioc: IOC,
    ) -> IOC:
        """
        Hydrate a persisted IOC into IOCManager runtime state.

        Repository-backed records may have been created before the current
        process started. The manager therefore needs to be synchronized
        before manager-level operations are performed.

        No new UUID is generated and lifecycle timestamps are preserved.
        """

        manager_state = self._manager._iocs
        manager_index = self._manager._index

        manager_state[ioc.ioc_id] = ioc

        key = (
            ioc.ioc_type.value.lower(),
            ioc.normalized_value,
        )

        manager_index[key] = ioc.ioc_id

        return ioc

    def _remove_from_manager(
        self,
        ioc: IOC,
    ) -> None:
        """
        Remove an IOC from manager runtime state.

        Used when an operation fails before persistence is completed.
        """

        manager_state = self._manager._iocs
        manager_index = self._manager._index

        key = (
            ioc.ioc_type.value.lower(),
            ioc.normalized_value,
        )

        manager_index.pop(
            key,
            None,
        )

        manager_state.pop(
            ioc.ioc_id,
            None,
        )

    # =========================================================================
    # Create IOC
    # =========================================================================

    async def add_ioc(
        self,
        data: IOCCreate,
    ) -> IOC:
        """
        Create a new IOC or merge intelligence into an existing IOC.

        Application flow:

            normalize
                ↓
            validate
                ↓
            persistence deduplication
                ↓
             ┌──┴──┐
             │     │
           exists  new
             │     │
             ↓     ↓
           merge  create
             │     │
             └──┬──┘
                ↓
             persist
                ↓
          invalidate cache
        """

        manager = self._manager
        repository = self._repository

        # ---------------------------------------------------------------------
        # Normalize
        # ---------------------------------------------------------------------

        normalized = manager.normalize(
            data.ioc_type,
            data.value,
        )

        # ---------------------------------------------------------------------
        # Validate
        # ---------------------------------------------------------------------

        manager.validate(
            data.ioc_type,
            normalized,
            data.expiration,
        )

        # ---------------------------------------------------------------------
        # Persistence-aware deduplication
        # ---------------------------------------------------------------------

        if repository is not None:
            existing = (
                await repository.get_by_normalized_value(
                    ioc_type=data.ioc_type.value,
                    normalized_value=normalized,
                )
            )

            if existing is not None:
                self._sync_manager(
                    existing,
                )

                merged = manager.merge(
                    existing.ioc_id,
                    data,
                )

                try:
                    persisted = await repository.update(
                        merged,
                    )
                except Exception:
                    self._sync_manager(
                        existing,
                    )
                    raise

                self._sync_manager(
                    persisted,
                )

                self._cache.clear()

                return persisted

        # ---------------------------------------------------------------------
        # Create through domain manager
        # ---------------------------------------------------------------------

        ioc = manager.create(
            data,
        )

        # ---------------------------------------------------------------------
        # Persist
        # ---------------------------------------------------------------------

        if repository is not None:
            try:
                persisted = await repository.create(
                    ioc,
                )
            except Exception:
                self._remove_from_manager(
                    ioc,
                )
                raise

            self._sync_manager(
                persisted,
            )

            self._cache.clear()

            return persisted

        self._cache.clear()

        return ioc

    # =========================================================================
    # Get IOC
    # =========================================================================

    async def get_ioc(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Retrieve an IOC by UUID.

        Repository is authoritative whenever configured.
        """

        if self._repository is not None:
            ioc = await self._repository.get(
                ioc_id,
            )

            if ioc is None:
                raise KeyError(
                    f"IOC not found: {ioc_id}",
                )

            self._sync_manager(
                ioc,
            )

            return ioc

        return self._manager.get(
            ioc_id,
        )

    # =========================================================================
    # List / Search / Filters / Pagination
    # =========================================================================

    async def list_iocs(
        self,
        *,
        query: str | None = None,
        ioc_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        reputation: str | None = None,
        feed: str | None = None,
        active: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> tuple[list[IOC], int]:
        """
        Search, filter and paginate IOC inventory.

        Backend pagination remains authoritative when a repository is
        configured.

        Returns:

            items
            total
        """

        page = max(
            1,
            page,
        )

        page_size = min(
            max(
                1,
                page_size,
            ),
            self.MAX_PAGE_SIZE,
        )

        # ---------------------------------------------------------------------
        # PostgreSQL-backed inventory
        # ---------------------------------------------------------------------

        if self._repository is not None:
            records, total = await self._repository.list(
                query=(
                    query.strip()
                    if query
                    else None
                ),
                ioc_type=(
                    ioc_type.strip().lower()
                    if ioc_type
                    else None
                ),
                severity=(
                    severity.strip().lower()
                    if severity
                    else None
                ),
                status=(
                    status.strip().lower()
                    if status
                    else None
                ),
                source=(
                    source.strip()
                    if source
                    else None
                ),
                reputation=(
                    reputation.strip().lower()
                    if reputation
                    else None
                ),
                feed=(
                    feed.strip()
                    if feed
                    else None
                ),
                active=active,
                start_time=start_time,
                end_time=end_time,
                page=page,
                page_size=page_size,
            )

            for ioc in records:
                self._sync_manager(
                    ioc,
                )

            return records, total

        # ---------------------------------------------------------------------
        # In-memory fallback
        # ---------------------------------------------------------------------

        records = self._manager.list_all()

        # ---------------------------------------------------------------------
        # Search
        # ---------------------------------------------------------------------

        if query:
            needle = query.strip().lower()

            if needle:
                records = [
                    ioc
                    for ioc in records
                    if (
                        needle
                        in str(ioc.ioc_id).lower()
                        or needle
                        in ioc.ioc_type.value.lower()
                        or needle
                        in ioc.value.lower()
                        or needle
                        in ioc.normalized_value.lower()
                        or needle
                        in ioc.source.lower()
                        or (
                            ioc.feed is not None
                            and needle
                            in ioc.feed.lower()
                        )
                        or needle
                        in ioc.reputation.value.lower()
                        or needle
                        in ioc.status.value.lower()
                        or needle
                        in ioc.severity.value.lower()
                        or (
                            ioc.description is not None
                            and needle
                            in ioc.description.lower()
                        )
                        or any(
                            needle
                            in tag.lower()
                            for tag in ioc.tags
                        )
                    )
                ]

        # ---------------------------------------------------------------------
        # Type
        # ---------------------------------------------------------------------

        if ioc_type:
            type_value = (
                ioc_type.strip().lower()
            )

            records = [
                ioc
                for ioc in records
                if ioc.ioc_type.value
                == type_value
            ]

        # ---------------------------------------------------------------------
        # Severity
        # ---------------------------------------------------------------------

        if severity:
            severity_value = (
                severity.strip().lower()
            )

            records = [
                ioc
                for ioc in records
                if ioc.severity.value
                == severity_value
            ]

        # ---------------------------------------------------------------------
        # Status
        # ---------------------------------------------------------------------

        if status:
            status_value = (
                status.strip().lower()
            )

            records = [
                ioc
                for ioc in records
                if ioc.status.value
                == status_value
            ]

        # ---------------------------------------------------------------------
        # Source
        # ---------------------------------------------------------------------

        if source:
            source_value = (
                source.strip().lower()
            )

            records = [
                ioc
                for ioc in records
                if ioc.source.lower()
                == source_value
            ]

        # ---------------------------------------------------------------------
        # Reputation
        # ---------------------------------------------------------------------

        if reputation:
            reputation_value = (
                reputation.strip().lower()
            )

            records = [
                ioc
                for ioc in records
                if ioc.reputation.value
                == reputation_value
            ]

        # ---------------------------------------------------------------------
        # Feed
        # ---------------------------------------------------------------------

        if feed:
            feed_value = (
                feed.strip().lower()
            )

            records = [
                ioc
                for ioc in records
                if (
                    ioc.feed is not None
                    and ioc.feed.lower()
                    == feed_value
                )
            ]

        # ---------------------------------------------------------------------
        # Active
        # ---------------------------------------------------------------------

        if active is not None:
            records = [
                ioc
                for ioc in records
                if (
                    ioc.status
                    == IOCStatus.ACTIVE
                ) == active
            ]

        # ---------------------------------------------------------------------
        # Last Seen range
        # ---------------------------------------------------------------------

        if start_time is not None:
            records = [
                ioc
                for ioc in records
                if ioc.last_seen >= start_time
            ]

        if end_time is not None:
            records = [
                ioc
                for ioc in records
                if ioc.last_seen <= end_time
            ]

        # ---------------------------------------------------------------------
        # Deterministic ordering
        # ---------------------------------------------------------------------

        records.sort(
            key=lambda ioc: (
                ioc.last_seen,
                ioc.ioc_id,
            ),
            reverse=True,
        )

        total = len(
            records,
        )

        offset = (
            (page - 1)
            * page_size
        )

        return (
            records[
                offset : offset + page_size
            ],
            total,
        )

    # =========================================================================
    # Update IOC
    # =========================================================================

    async def update_ioc(
        self,
        ioc_id: UUID,
        *,
        value: str | None = None,
        confidence: float | None = None,
        severity: IOCSeverity | None = None,
        source: str | None = None,
        expiration: datetime | None = None,
        reputation: Reputation | None = None,
        status: IOCStatus | None = None,
        feed: str | None = None,
        description: str | None = None,
        tags: tuple[str, ...] | None = None,
        metadata: dict[str, str] | None = None,
        relationships: IOCRelationships | None = None,
    ) -> IOC:
        """
        Update an existing IOC.

        Manager performs normalization, validation and domain rules.

        Repository persists the updated canonical IOC.
        """

        existing = await self.get_ioc(
            ioc_id,
        )

        self._sync_manager(
            existing,
        )

        updated = self._manager.update(
            ioc_id,
            value=value,
            confidence=confidence,
            severity=severity,
            source=source,
            expiration=expiration,
            reputation=reputation,
            status=status,
            feed=feed,
            description=description,
            tags=tags,
            metadata=metadata,
            relationships=relationships,
        )

        if self._repository is not None:
            try:
                updated = await self._repository.update(
                    updated,
                )
            except Exception:
                self._sync_manager(
                    existing,
                )
                raise

            self._sync_manager(
                updated,
            )

        self._cache.clear()

        return updated

    # =========================================================================
    # Revoke / Disable IOC
    # =========================================================================

    async def revoke_ioc(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Disable an IOC by changing its lifecycle status to REVOKED.

        The IOC remains persisted.

        Historical relationships and intelligence remain available.
        """

        existing = await self.get_ioc(
            ioc_id,
        )

        self._sync_manager(
            existing,
        )

        updated = self._manager.revoke(
            ioc_id,
        )

        if self._repository is not None:
            try:
                updated = await self._repository.update(
                    updated,
                )
            except Exception:
                self._sync_manager(
                    existing,
                )
                raise

            self._sync_manager(
                updated,
            )

        self._cache.clear()

        return updated

    # =========================================================================
    # Activate / Enable IOC
    # =========================================================================

    async def activate_ioc(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Enable an IOC by changing its lifecycle status to ACTIVE.

        IOCManager enforces expiration rules.
        """

        existing = await self.get_ioc(
            ioc_id,
        )

        self._sync_manager(
            existing,
        )

        updated = self._manager.activate(
            ioc_id,
        )

        if self._repository is not None:
            try:
                updated = await self._repository.update(
                    updated,
                )
            except Exception:
                self._sync_manager(
                    existing,
                )
                raise

            self._sync_manager(
                updated,
            )

        self._cache.clear()

        return updated

    # =========================================================================
    # Lookup by Type + Value
    # =========================================================================

    async def lookup_ioc(
        self,
        *,
        ioc_type: str,
        value: str,
    ) -> IOC | None:
        """
        Lookup an IOC by IOC type and observable value.
        """

        ioc_type_enum = (
            self._manager._coerce_ioc_type(
                ioc_type,
            )
        )

        normalized = self._manager.normalize(
            ioc_type_enum,
            value,
        )

        if self._repository is not None:
            result = (
                await self._repository
                .get_by_normalized_value(
                    ioc_type=ioc_type_enum.value,
                    normalized_value=normalized,
                )
            )

            if result is not None:
                self._sync_manager(
                    result,
                )

            return result

        return self._manager.lookup(
            ioc_type=ioc_type_enum.value,
            value=value,
        )

    # =========================================================================
    # Lookup by Value
    # =========================================================================

    async def lookup_value(
        self,
        value: str,
    ) -> IOC | None:
        """
        Lookup an IOC when IOC type is unknown.
        """

        if self._repository is None:
            return self._manager.lookup_value(
                value,
            )

        for ioc_type in (
            self._manager._supported_types()
        ):
            try:
                normalized = self._manager.normalize(
                    ioc_type,
                    value,
                )
            except Exception:
                continue

            result = (
                await self._repository
                .get_by_normalized_value(
                    ioc_type=ioc_type.value,
                    normalized_value=normalized,
                )
            )

            if result is not None:
                self._sync_manager(
                    result,
                )

                return result

        return None

    # =========================================================================
    # Enrichment
    # =========================================================================

    async def enrich(
        self,
        observable: str,
    ) -> tuple[IOCMatch, ...]:
        """
        Enrich an observable using active IOC intelligence.

        Match results are cached.

        Only ACTIVE IOCs participate in threat matching.
        """

        cache_key = observable.strip().lower()

        if not cache_key:
            return ()

        cached = self._cache.get(
            cache_key,
        )

        if cached is not None:
            return cached

        # ---------------------------------------------------------------------
        # Load active IOCs
        # ---------------------------------------------------------------------

        if self._repository is not None:
            active_iocs, _ = (
                await self._repository.list(
                    status=IOCStatus.ACTIVE.value,
                    active=True,
                    page=1,
                    page_size=self.MAX_PAGE_SIZE,
                )
            )

            for ioc in active_iocs:
                self._sync_manager(
                    ioc,
                )
        else:
            active_iocs = (
                self._manager.list_active()
            )

        # ---------------------------------------------------------------------
        # Enrich / match
        # ---------------------------------------------------------------------

        matches = self._enricher.enrich(
            observable,
            active_iocs,
        )

        self._cache.set(
            cache_key,
            matches,
        )

        return matches

    # =========================================================================
    # Match
    # =========================================================================

    async def match(
        self,
        observable: str,
    ) -> tuple[IOCMatch, ...]:
        """
        Backward-compatible alias for enrich().
        """

        return await self.enrich(
            observable,
        )

    # =========================================================================
    # Relationships
    # =========================================================================

    async def get_relationships(
        self,
        ioc_id: UUID,
    ) -> dict[str, object]:
        """
        Return lightweight cross-module IOC relationships.
        """

        ioc = await self.get_ioc(
            ioc_id,
        )

        if self._repository is not None:
            return await self._repository.relationships(
                ioc_id,
            )

        relationships = (
            ioc.relationships
        )

        event_ids = list(
            relationships.event_ids,
        )

        alert_ids = list(
            relationships.alert_ids,
        )

        incident_ids = list(
            relationships.incident_ids,
        )

        asset_ids = list(
            relationships.asset_ids,
        )

        mitre_technique_ids = list(
            relationships.mitre_technique_ids,
        )

        return {
            "event_ids": event_ids,
            "alert_ids": alert_ids,
            "incident_ids": incident_ids,
            "asset_ids": asset_ids,
            "mitre_technique_ids": (
                mitre_technique_ids
            ),
            "event_count": len(
                event_ids,
            ),
            "alert_count": len(
                alert_ids,
            ),
            "incident_count": len(
                incident_ids,
            ),
            "asset_count": len(
                asset_ids,
            ),
            "mitre_technique_count": len(
                mitre_technique_ids,
            ),
        }

    # =========================================================================
    # Add Relationships
    # =========================================================================

    async def add_relationships(
        self,
        ioc_id: UUID,
        relationships: IOCRelationships,
    ) -> IOC:
        """
        Add cross-module relationships to an existing IOC.
        """

        existing = await self.get_ioc(
            ioc_id,
        )

        self._sync_manager(
            existing,
        )

        updated = (
            self._manager.add_relationships(
                ioc_id,
                relationships,
            )
        )

        if self._repository is not None:
            try:
                updated = await self._repository.update(
                    updated,
                )
            except Exception:
                self._sync_manager(
                    existing,
                )
                raise

            self._sync_manager(
                updated,
            )

        self._cache.clear()

        return updated

    # =========================================================================
    # Summary / KPI
    # =========================================================================

    async def summary(
        self,
        *,
        recently_updated_since: datetime | None = None,
    ) -> dict[str, object]:
        """
        Return backend-authoritative Threat Intelligence statistics.

        Primary dashboard KPI:

            total
            active
            high_risk
            expired

        Additional statistics may be returned by the repository.
        """

        if recently_updated_since is None:
            recently_updated_since = (
                utcnow().replace(
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                )
            )

        if self._repository is not None:
            return await self._repository.summary(
                recently_updated_since=(
                    recently_updated_since
                ),
            )

        records = (
            self._manager.list_all()
        )

        total = len(
            records,
        )

        active = sum(
            1
            for ioc in records
            if ioc.status
            == IOCStatus.ACTIVE
        )

        expired = sum(
            1
            for ioc in records
            if ioc.status
            == IOCStatus.EXPIRED
        )

        revoked = sum(
            1
            for ioc in records
            if ioc.status
            == IOCStatus.REVOKED
        )

        high_risk = sum(
            1
            for ioc in records
            if (
                ioc.severity
                in {
                    IOCSeverity.HIGH,
                    IOCSeverity.CRITICAL,
                }
                or ioc.reputation
                in {
                    Reputation.SUSPICIOUS,
                    Reputation.MALICIOUS,
                }
            )
        )

        malicious = sum(
            1
            for ioc in records
            if ioc.reputation
            == Reputation.MALICIOUS
        )

        recently_updated = sum(
            1
            for ioc in records
            if ioc.last_seen
            >= recently_updated_since
        )

        by_type: dict[str, int] = {}
        by_source: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_reputation: dict[str, int] = {}

        for ioc in records:
            type_value = (
                ioc.ioc_type.value
            )

            by_type[type_value] = (
                by_type.get(
                    type_value,
                    0,
                )
                + 1
            )

            source_value = (
                ioc.source
            )

            by_source[source_value] = (
                by_source.get(
                    source_value,
                    0,
                )
                + 1
            )

            severity_value = (
                ioc.severity.value
            )

            by_severity[severity_value] = (
                by_severity.get(
                    severity_value,
                    0,
                )
                + 1
            )

            status_value = (
                ioc.status.value
            )

            by_status[status_value] = (
                by_status.get(
                    status_value,
                    0,
                )
                + 1
            )

            reputation_value = (
                ioc.reputation.value
            )

            by_reputation[
                reputation_value
            ] = (
                by_reputation.get(
                    reputation_value,
                    0,
                )
                + 1
            )

        return {
            # Canonical dashboard KPI
            "total": total,
            "active": active,
            "high_risk": high_risk,
            "expired": expired,

            # Additional statistics
            "total_iocs": total,
            "malicious": malicious,
            "recently_updated": recently_updated,
            "revoked": revoked,

            # Breakdowns
            "by_type": by_type,
            "by_source": by_source,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_reputation": by_reputation,
        }

    # =========================================================================
    # Filter Options
    # =========================================================================

    async def filter_options(
        self,
    ) -> dict[str, list[str]]:
        """
        Return backend-authoritative IOC filter catalogues.

        Canonical values:

            Type
            Severity
            Status
            Reputation

        Dynamic source values are supplied by the persistence layer.
        """

        if self._repository is not None:
            return await self._repository.filter_options()

        # ---------------------------------------------------------------------
        # In-memory fallback
        # ---------------------------------------------------------------------

        from app.threat_intelligence.models import (
            IOCSeverity,
            IOCStatus,
            IOCType,
            Reputation,
        )

        sources = sorted(
            {
                ioc.source.strip()
                for ioc in self._manager.list_all()
                if ioc.source.strip()
            },
            key=str.lower,
        )

        return {
            "types": [
                item.value
                for item in IOCType
            ],
            "severities": [
                item.value
                for item in IOCSeverity
            ],
            "statuses": [
                item.value
                for item in IOCStatus
            ],
            "sources": sources,
            "reputations": [
                item.value
                for item in Reputation
            ],
        }

    # =========================================================================
    # Compatibility Aliases
    # =========================================================================

    async def add(
        self,
        data: IOCCreate,
    ) -> IOC:
        """
        Backward-compatible alias for add_ioc().
        """

        return await self.add_ioc(
            data,
        )

    async def get(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Backward-compatible alias for get_ioc().
        """

        return await self.get_ioc(
            ioc_id,
        )

    async def update(
        self,
        ioc_id: UUID,
        **kwargs,
    ) -> IOC:
        """
        Backward-compatible alias for update_ioc().
        """

        return await self.update_ioc(
            ioc_id,
            **kwargs,
        )

    async def revoke(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Backward-compatible alias for revoke_ioc().
        """

        return await self.revoke_ioc(
            ioc_id,
        )

    async def activate(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Backward-compatible alias for activate_ioc().
        """

        return await self.activate_ioc(
            ioc_id,
        )


__all__ = [
    "IOCRepositoryProtocol",
    "ThreatIntelligenceService",
]