from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.postgres.models import StorageRecord
from app.threat_intelligence.models import (
    IOC,
    IOCSeverity,
    IOCStatus,
    IOCType,
    Reputation,
)


class IOCRepository:
    """
    PostgreSQL persistence repository for SentinelSIEM Threat Intelligence.

    IOC records are persisted through the existing generic StorageRecord
    boundary.

    Storage layout:

        entity_type = "threat_intelligence_ioc"
        entity_id   = IOC UUID as string
        payload     = serialized IOC domain model

    Transaction ownership:

        This repository does not commit or rollback transactions.

        The request/session transaction boundary owns commit and rollback.

    IOC lifecycle:

        ACTIVE
          │
          ├── expiration reached → EXPIRED
          │
          └── revoke()           → REVOKED

        REVOKED
          │
          └── activate()         → ACTIVE

    IOC hard deletion is intentionally not supported.

    Historical IOC records must remain available for investigation,
    correlation, reporting and audit workflows.
    """

    ENTITY_TYPE = "threat_intelligence_ioc"

    DEFAULT_PAGE_SIZE = 30
    MAX_PAGE_SIZE = 200

    # =========================================================================
    # Canonical Catalogues
    # =========================================================================

    IOC_TYPES: tuple[str, ...] = tuple(
        item.value for item in IOCType
    )

    SEVERITIES: tuple[str, ...] = tuple(
        item.value for item in IOCSeverity
    )

    STATUSES: tuple[str, ...] = tuple(
        item.value for item in IOCStatus
    )

    REPUTATIONS: tuple[str, ...] = tuple(
        item.value for item in Reputation
    )

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self._session = session

    # =========================================================================
    # Serialization
    # =========================================================================

    @classmethod
    def _to_payload(
        cls,
        ioc: IOC,
    ) -> dict[str, Any]:
        """
        Serialize an IOC domain model into JSON-compatible PostgreSQL data.
        """

        return ioc.model_dump(
            mode="json",
        )

    @staticmethod
    def _from_payload(
        payload: dict[str, Any],
    ) -> IOC:
        """
        Reconstruct an IOC domain model from persisted JSON data.
        """

        return IOC.model_validate(
            payload,
        )

    # =========================================================================
    # Internal Queries
    # =========================================================================

    def _base_query(self):
        """
        Return the base query restricted to IOC StorageRecord rows.
        """

        return select(StorageRecord).where(
            StorageRecord.entity_type
            == self.ENTITY_TYPE,
        )

    async def _get_record(
        self,
        ioc_id: UUID,
    ) -> StorageRecord | None:
        """
        Retrieve one IOC StorageRecord by UUID.
        """

        result = await self._session.execute(
            self._base_query().where(
                StorageRecord.entity_id
                == str(ioc_id),
            ),
        )

        return result.scalar_one_or_none()

    async def _get_all_records(
        self,
    ) -> list[StorageRecord]:
        """
        Retrieve all persisted IOC StorageRecord rows.

        IOC filtering is performed against the serialized domain payload.
        """

        result = await self._session.execute(
            self._base_query(),
        )

        return list(
            result.scalars().all(),
        )

    # =========================================================================
    # Lifecycle Helpers
    # =========================================================================

    @staticmethod
    def _effective_status(
        ioc: IOC,
    ) -> IOCStatus:
        """
        Resolve the effective lifecycle status.

        Only ACTIVE indicators can become EXPIRED automatically.

        REVOKED remains REVOKED even if its expiration time has passed.
        """

        if (
            ioc.status == IOCStatus.ACTIVE
            and ioc.expiration is not None
            and ioc.expiration <= datetime.now(UTC)
        ):
            return IOCStatus.EXPIRED

        return ioc.status

    @classmethod
    def _with_effective_status(
        cls,
        ioc: IOC,
    ) -> IOC:
        """
        Return an IOC with its effective lifecycle status.

        The persisted record is not mutated.
        """

        effective_status = cls._effective_status(
            ioc,
        )

        if effective_status == ioc.status:
            return ioc

        return ioc.model_copy(
            update={
                "status": effective_status,
            },
        )

    @classmethod
    def _is_active(
        cls,
        ioc: IOC,
    ) -> bool:
        """
        Return whether the IOC is currently ACTIVE.
        """

        return (
            cls._effective_status(ioc)
            == IOCStatus.ACTIVE
        )

    # =========================================================================
    # Search / Filter Helpers
    # =========================================================================

    @staticmethod
    def _matches_query(
        ioc: IOC,
        query: str,
    ) -> bool:
        """
        Match free-text search against important IOC fields.

        Searchable:

            IOC ID
            value
            normalized value
            IOC type
            severity
            status
            reputation
            source
            feed
            description
            tags
        """

        needle = query.strip().lower()

        if not needle:
            return True

        candidates = (
            str(ioc.ioc_id),
            ioc.value,
            ioc.normalized_value,
            ioc.ioc_type.value,
            ioc.severity.value,
            ioc.status.value,
            ioc.reputation.value,
            ioc.source,
            ioc.feed or "",
            ioc.description or "",
            *ioc.tags,
        )

        return any(
            needle in str(candidate).lower()
            for candidate in candidates
        )

    @staticmethod
    def _matches_type(
        ioc: IOC,
        ioc_type: str,
    ) -> bool:
        """
        Match IOC type case-insensitively.
        """

        return (
            ioc.ioc_type.value
            == ioc_type.strip().lower()
        )

    @staticmethod
    def _matches_severity(
        ioc: IOC,
        severity: str,
    ) -> bool:
        """
        Match IOC severity case-insensitively.
        """

        return (
            ioc.severity.value
            == severity.strip().lower()
        )

    @classmethod
    def _matches_status(
        cls,
        ioc: IOC,
        status: str,
    ) -> bool:
        """
        Match effective IOC lifecycle status.
        """

        return (
            cls._effective_status(ioc).value
            == status.strip().lower()
        )

    @staticmethod
    def _matches_source(
        ioc: IOC,
        source: str,
    ) -> bool:
        """
        Match IOC source case-insensitively.
        """

        return (
            ioc.source.strip().lower()
            == source.strip().lower()
        )

    @staticmethod
    def _matches_reputation(
        ioc: IOC,
        reputation: str,
    ) -> bool:
        """
        Match IOC reputation case-insensitively.
        """

        return (
            ioc.reputation.value
            == reputation.strip().lower()
        )

    @staticmethod
    def _matches_feed(
        ioc: IOC,
        feed: str,
    ) -> bool:
        """
        Match IOC feed case-insensitively.
        """

        if ioc.feed is None:
            return False

        return (
            ioc.feed.strip().lower()
            == feed.strip().lower()
        )

    # =========================================================================
    # Create
    # =========================================================================

    async def create(
        self,
        ioc: IOC,
    ) -> IOC:
        """
        Persist a new IOC.

        Duplicate identity:

            IOC type + normalized value

        Raises:
            ValueError:
                If the normalized IOC already exists.
        """

        existing = await self.get_by_normalized_value(
            ioc_type=ioc.ioc_type.value,
            normalized_value=ioc.normalized_value,
        )

        if existing is not None:
            raise ValueError(
                "IOC already exists for IOC type "
                f"{ioc.ioc_type.value!r} and normalized value "
                f"{ioc.normalized_value!r}",
            )

        record = StorageRecord(
            entity_type=self.ENTITY_TYPE,
            entity_id=str(ioc.ioc_id),
            payload=self._to_payload(ioc),
        )

        self._session.add(
            record,
        )

        await self._session.flush()

        return self._with_effective_status(
            ioc,
        )

    # =========================================================================
    # Get
    # =========================================================================

    async def get(
        self,
        ioc_id: UUID,
    ) -> IOC | None:
        """
        Retrieve an IOC by UUID.

        Effective expiration status is applied to the returned model.
        """

        record = await self._get_record(
            ioc_id,
        )

        if record is None:
            return None

        ioc = self._from_payload(
            record.payload,
        )

        return self._with_effective_status(
            ioc,
        )

    # =========================================================================
    # Get By Normalized Value
    # =========================================================================

    async def get_by_normalized_value(
        self,
        *,
        ioc_type: str,
        normalized_value: str,
    ) -> IOC | None:
        """
        Find an IOC by:

            IOC type + normalized value
        """

        target_type = (
            ioc_type.strip().lower()
        )

        target_value = (
            normalized_value.strip().lower()
        )

        records = await self._get_all_records()

        for record in records:
            payload = record.payload

            stored_type = str(
                payload.get(
                    "ioc_type",
                    "",
                ),
            ).strip().lower()

            stored_value = str(
                payload.get(
                    "normalized_value",
                    "",
                ),
            ).strip().lower()

            if (
                stored_type != target_type
                or stored_value != target_value
            ):
                continue

            ioc = self._from_payload(
                payload,
            )

            return self._with_effective_status(
                ioc,
            )

        return None

    # =========================================================================
    # List / Search / Filter / Pagination
    # =========================================================================

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
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> tuple[list[IOC], int]:
        """
        Search, filter and paginate IOC inventory.

        Supported filters:

            query
            ioc_type
            severity
            status
            source
            reputation
            feed
            active
            start_time
            end_time

        Returns:

            (items, total)

        The API layer is responsible for exposing:

            page
            page_size
            total
            total_pages
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

        records = await self._get_all_records()

        matched: list[IOC] = []

        for record in records:
            ioc = self._from_payload(
                record.payload,
            )

            effective_ioc = self._with_effective_status(
                ioc,
            )

            # -----------------------------------------------------------------
            # Search
            # -----------------------------------------------------------------

            if (
                query
                and not self._matches_query(
                    effective_ioc,
                    query,
                )
            ):
                continue

            # -----------------------------------------------------------------
            # Type
            # -----------------------------------------------------------------

            if (
                ioc_type
                and not self._matches_type(
                    effective_ioc,
                    ioc_type,
                )
            ):
                continue

            # -----------------------------------------------------------------
            # Severity
            # -----------------------------------------------------------------

            if (
                severity
                and not self._matches_severity(
                    effective_ioc,
                    severity,
                )
            ):
                continue

            # -----------------------------------------------------------------
            # Status
            # -----------------------------------------------------------------

            if (
                status
                and not self._matches_status(
                    effective_ioc,
                    status,
                )
            ):
                continue

            # -----------------------------------------------------------------
            # Source
            # -----------------------------------------------------------------

            if (
                source
                and not self._matches_source(
                    effective_ioc,
                    source,
                )
            ):
                continue

            # -----------------------------------------------------------------
            # Reputation
            # -----------------------------------------------------------------

            if (
                reputation
                and not self._matches_reputation(
                    effective_ioc,
                    reputation,
                )
            ):
                continue

            # -----------------------------------------------------------------
            # Feed
            # -----------------------------------------------------------------

            if (
                feed
                and not self._matches_feed(
                    effective_ioc,
                    feed,
                )
            ):
                continue

            # -----------------------------------------------------------------
            # Active
            # -----------------------------------------------------------------

            if (
                active is not None
                and self._is_active(
                    effective_ioc,
                ) != active
            ):
                continue

            # -----------------------------------------------------------------
            # Last Seen Time Range
            # -----------------------------------------------------------------

            if (
                start_time is not None
                and effective_ioc.last_seen < start_time
            ):
                continue

            if (
                end_time is not None
                and effective_ioc.last_seen > end_time
            ):
                continue

            matched.append(
                effective_ioc,
            )

        # ---------------------------------------------------------------------
        # Backend-owned deterministic ordering
        # ---------------------------------------------------------------------

        matched.sort(
            key=lambda item: (
                item.last_seen,
                item.ioc_id,
            ),
            reverse=True,
        )

        total = len(
            matched,
        )

        offset = (
            (page - 1)
            * page_size
        )

        items = matched[
            offset : offset + page_size
        ]

        return items, total

    # =========================================================================
    # Update
    # =========================================================================

    async def update(
        self,
        ioc: IOC,
    ) -> IOC:
        """
        Update an existing IOC.

        The IOC UUID remains unchanged.

        Duplicate normalized indicators are rejected.
        """

        record = await self._get_record(
            ioc.ioc_id,
        )

        if record is None:
            raise KeyError(
                f"IOC not found: {ioc.ioc_id}",
            )

        duplicate = await self.get_by_normalized_value(
            ioc_type=ioc.ioc_type.value,
            normalized_value=ioc.normalized_value,
        )

        if (
            duplicate is not None
            and duplicate.ioc_id != ioc.ioc_id
        ):
            raise ValueError(
                "Another IOC already exists for IOC type "
                f"{ioc.ioc_type.value!r} and normalized value "
                f"{ioc.normalized_value!r}",
            )

        record.payload = self._to_payload(
            ioc,
        )

        await self._session.flush()

        return self._with_effective_status(
            ioc,
        )

    # =========================================================================
    # Revoke / Disable
    # =========================================================================

    async def revoke(
        self,
        ioc_id: UUID,
    ) -> IOC | None:
        """
        Revoke an IOC.

        This is the persistence operation behind the UI's
        "Disable IOC" action.

        The IOC record remains persisted.

        Returns:
            Updated IOC when found.
            None when the IOC does not exist.
        """

        record = await self._get_record(
            ioc_id,
        )

        if record is None:
            return None

        ioc = self._from_payload(
            record.payload,
        )

        revoked = ioc.model_copy(
            update={
                "status": IOCStatus.REVOKED,
            },
        )

        record.payload = self._to_payload(
            revoked,
        )

        await self._session.flush()

        return revoked

    # =========================================================================
    # Activate / Enable
    # =========================================================================

    async def activate(
        self,
        ioc_id: UUID,
    ) -> IOC | None:
        """
        Activate an IOC.

        This is the persistence operation behind the UI's
        "Enable IOC" action.

        Activation explicitly changes the lifecycle state to ACTIVE.

        If an expiration timestamp is already in the past, the IOC will
        subsequently be exposed as EXPIRED by expiration-aware reads.
        """

        record = await self._get_record(
            ioc_id,
        )

        if record is None:
            return None

        ioc = self._from_payload(
            record.payload,
        )

        activated = ioc.model_copy(
            update={
                "status": IOCStatus.ACTIVE,
            },
        )

        record.payload = self._to_payload(
            activated,
        )

        await self._session.flush()

        return self._with_effective_status(
            activated,
        )

    # =========================================================================
    # Summary / KPI
    # =========================================================================

    async def summary(
        self,
        *,
        recently_updated_since: datetime | None = None,
    ) -> dict[str, object]:
        """
        Build backend-authoritative Threat Intelligence dashboard statistics.

        Primary KPI values:

            total
            active
            high_risk
            expired

        Additional breakdowns are returned for future analytics and
        filtering workflows.

        High Risk is defined at the backend as:

            severity = HIGH or CRITICAL

        or:

            reputation = SUSPICIOUS or MALICIOUS
        """

        if recently_updated_since is None:
            recently_updated_since = (
                datetime.now(UTC).replace(
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                )
            )

        records = await self._get_all_records()

        total = 0
        active = 0
        high_risk = 0
        expired = 0

        malicious = 0
        recently_updated = 0
        revoked = 0

        by_type: dict[str, int] = {}
        by_source: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_reputation: dict[str, int] = {}

        for record in records:
            ioc = self._from_payload(
                record.payload,
            )

            ioc = self._with_effective_status(
                ioc,
            )

            total += 1

            # -----------------------------------------------------------------
            # Status
            # -----------------------------------------------------------------

            status_value = ioc.status.value

            by_status[status_value] = (
                by_status.get(
                    status_value,
                    0,
                )
                + 1
            )

            if ioc.status == IOCStatus.ACTIVE:
                active += 1

            elif ioc.status == IOCStatus.EXPIRED:
                expired += 1

            elif ioc.status == IOCStatus.REVOKED:
                revoked += 1

            # -----------------------------------------------------------------
            # Severity
            # -----------------------------------------------------------------

            severity_value = ioc.severity.value

            by_severity[severity_value] = (
                by_severity.get(
                    severity_value,
                    0,
                )
                + 1
            )

            # -----------------------------------------------------------------
            # Reputation
            # -----------------------------------------------------------------

            reputation_value = ioc.reputation.value

            by_reputation[reputation_value] = (
                by_reputation.get(
                    reputation_value,
                    0,
                )
                + 1
            )

            if (
                ioc.reputation
                == Reputation.MALICIOUS
            ):
                malicious += 1

            # -----------------------------------------------------------------
            # High Risk
            # -----------------------------------------------------------------

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
            ):
                high_risk += 1

            # -----------------------------------------------------------------
            # Recently Updated
            # -----------------------------------------------------------------

            if (
                ioc.last_seen
                >= recently_updated_since
            ):
                recently_updated += 1

            # -----------------------------------------------------------------
            # Type
            # -----------------------------------------------------------------

            type_value = ioc.ioc_type.value

            by_type[type_value] = (
                by_type.get(
                    type_value,
                    0,
                )
                + 1
            )

            # -----------------------------------------------------------------
            # Source
            # -----------------------------------------------------------------

            source_value = ioc.source

            by_source[source_value] = (
                by_source.get(
                    source_value,
                    0,
                )
                + 1
            )

        return {
            # -----------------------------------------------------------------
            # Canonical dashboard KPI
            # -----------------------------------------------------------------
            "total": total,
            "active": active,
            "high_risk": high_risk,
            "expired": expired,

            # -----------------------------------------------------------------
            # Additional backend statistics
            # -----------------------------------------------------------------
            "total_iocs": total,
            "malicious": malicious,
            "recently_updated": recently_updated,
            "revoked": revoked,

            # -----------------------------------------------------------------
            # Breakdowns
            # -----------------------------------------------------------------
            "by_type": by_type,
            "by_source": by_source,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_reputation": by_reputation,
        }

    # =========================================================================
    # Filter Options
    # =========================================================================

    async def filter_options(self) -> dict[str, list[str]]:
        """
        Return backend-authoritative IOC filter catalogues.

        Canonical catalogues are returned even when there are currently no
        persisted IOC records using a particular value.

        Dynamic source values are derived from persisted IOC data because
        sources are data-owned rather than a fixed enum.
        """

        records = await self._get_all_records()

        sources: set[str] = set()

        for record in records:
            ioc = self._from_payload(
                record.payload,
            )

            source = ioc.source.strip()

            if source:
                sources.add(source)

        return {
            "types": list(
                self.IOC_TYPES,
            ),
            "severities": list(
                self.SEVERITIES,
            ),
            "statuses": list(
                self.STATUSES,
            ),
            "sources": sorted(
                sources,
                key=str.lower,
            ),
            "reputations": list(
                self.REPUTATIONS,
            ),
        }

    # =========================================================================
    # Relationships
    # =========================================================================

    async def relationships(
        self,
        ioc_id: UUID,
    ) -> dict[str, object]:
        """
        Return lightweight cross-module IOC relationship references.

        Detailed related resource data remains owned by the corresponding
        application modules.
        """

        ioc = await self.get(
            ioc_id,
        )

        if ioc is None:
            raise KeyError(
                f"IOC not found: {ioc_id}",
            )

        relationships = ioc.relationships

        event_ids = list(
            relationships.event_ids,
        )

        alert_ids = [
            str(alert_id)
            for alert_id in relationships.alert_ids
        ]

        incident_ids = [
            str(incident_id)
            for incident_id in relationships.incident_ids
        ]

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
    # Exists
    # =========================================================================

    async def exists(
        self,
        ioc_id: UUID,
    ) -> bool:
        """
        Return whether an IOC exists.
        """

        return (
            await self._get_record(
                ioc_id,
            )
            is not None
        )

    # =========================================================================
    # Count
    # =========================================================================

    async def count(self) -> int:
        """
        Return the total number of persisted IOC records.
        """

        records = await self._get_all_records()

        return len(
            records,
        )


__all__ = [
    "IOCRepository",
]