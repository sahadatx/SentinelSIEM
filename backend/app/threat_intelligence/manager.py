from __future__ import annotations

from datetime import datetime
from uuid import UUID

from app.threat_intelligence.models import (
    IOC,
    IOCCreate,
    IOCRelationships,
    IOCSeverity,
    IOCStatus,
    Reputation,
    utcnow,
)
from app.threat_intelligence.normalizer import IOCNormalizer
from app.threat_intelligence.validator import IOCValidator


class IOCManager:
    """
    Domain-level manager for SentinelSIEM Threat Intelligence IOCs.

    Responsibilities:

        - Create IOC
        - Update IOC
        - Normalize indicators
        - Validate indicators
        - Deduplicate indicators
        - Merge duplicate IOC intelligence
        - Manage confidence
        - Manage severity
        - Manage reputation
        - Manage IOC lifecycle
        - Enable / activate IOC
        - Disable / revoke IOC
        - Lookup IOC by ID
        - Lookup IOC by type + value
        - Lookup IOC by value
        - Maintain lightweight cross-module relationships

    Persistence is intentionally kept outside this class.

    Repository/storage owns persistence.

    Lifecycle:

        ACTIVE
           │
           ├── expiration reached → EXPIRED
           │
           └── revoke()           → REVOKED
                                      │
                                      └── activate() → ACTIVE

    IOC hard deletion is intentionally not supported.
    """

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        *,
        normalizer: IOCNormalizer | None = None,
        validator: IOCValidator | None = None,
    ) -> None:
        self._normalizer = (
            normalizer
            or IOCNormalizer()
        )

        self._validator = (
            validator
            or IOCValidator()
        )

        # ---------------------------------------------------------------------
        # In-memory state
        #
        # Used for:
        #   - runtime fallback
        #   - isolated unit tests
        #   - domain-level operations
        #
        # Persistent state belongs to IOCRepository.
        # ---------------------------------------------------------------------

        self._iocs: dict[UUID, IOC] = {}

        # Canonical deduplication index:
        #
        #     (ioc_type, normalized_value) -> IOC UUID
        #
        self._index: dict[
            tuple[str, str],
            UUID,
        ] = {}

    # =========================================================================
    # Create
    # =========================================================================

    def create(
        self,
        data: IOCCreate,
    ) -> IOC:
        """
        Create a new IOC.

        Duplicate identity is:

            IOC type + normalized value

        Duplicate submissions are merged into the existing IOC rather than
        producing another IOC record.
        """

        normalized = self.normalize(
            data.ioc_type,
            data.value,
        )

        self.validate(
            data.ioc_type,
            normalized,
            data.expiration,
        )

        key = self._make_index_key(
            data.ioc_type.value,
            normalized,
        )

        existing_id = self._index.get(
            key,
        )

        if existing_id is not None:
            existing = self._iocs.get(
                existing_id,
            )

            if existing is not None:
                merged = self._merge_duplicate(
                    existing,
                    data,
                )

                self._iocs[existing_id] = merged

                return merged

            # Defensive index recovery.
            self._index.pop(
                key,
                None,
            )

        now = utcnow()

        ioc = IOC(
            ioc_type=data.ioc_type,
            value=data.value,
            normalized_value=normalized,
            confidence=data.confidence,
            severity=data.severity,
            reputation=data.reputation,
            status=data.status,
            source=data.source.strip(),
            feed=(
                data.feed.strip()
                if data.feed is not None
                else None
            ),
            description=(
                data.description.strip()
                if data.description is not None
                else None
            ),
            tags=self._normalise_tags(
                data.tags,
            ),
            first_seen=now,
            last_seen=now,
            expiration=data.expiration,
            metadata=dict(
                data.metadata,
            ),
            relationships=data.relationships,
        )

        # Resolve expiration-aware lifecycle state.
        ioc = self._with_effective_status(
            ioc,
        )

        self._iocs[ioc.ioc_id] = ioc

        self._index[key] = ioc.ioc_id

        return ioc

    # =========================================================================
    # Get
    # =========================================================================

    def get(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Return an IOC by UUID.

        Raises:
            KeyError:
                IOC does not exist.
        """

        ioc = self._iocs.get(
            ioc_id,
        )

        if ioc is None:
            raise KeyError(
                f"IOC not found: {ioc_id}",
            )

        return self._with_effective_status(
            ioc,
        )

    # =========================================================================
    # Lookup
    # =========================================================================

    def lookup(
        self,
        *,
        ioc_type: str,
        value: str,
    ) -> IOC | None:
        """
        Lookup an IOC by IOC type and indicator value.

        The supplied indicator is normalized before lookup.
        """

        coerced_type = self._coerce_ioc_type(
            ioc_type,
        )

        normalized = self.normalize(
            coerced_type,
            value,
        )

        key = self._make_index_key(
            coerced_type.value,
            normalized,
        )

        ioc_id = self._index.get(
            key,
        )

        if ioc_id is None:
            return None

        return self.get(
            ioc_id,
        )

    def lookup_value(
        self,
        value: str,
    ) -> IOC | None:
        """
        Lookup an IOC when only the indicator value is available.

        All supported IOC types are attempted through the canonical
        normalizer.
        """

        for ioc_type in self._supported_types():
            try:
                normalized = self.normalize(
                    ioc_type,
                    value,
                )
            except Exception:
                continue

            key = self._make_index_key(
                ioc_type.value,
                normalized,
            )

            ioc_id = self._index.get(
                key,
            )

            if ioc_id is None:
                continue

            return self.get(
                ioc_id,
            )

        return None

    # =========================================================================
    # List
    # =========================================================================

    def list_active(self) -> list[IOC]:
        """
        Return all currently active IOCs.

        Expired and revoked IOCs are excluded.
        """

        items: list[IOC] = []

        for ioc in self._iocs.values():
            effective = self._with_effective_status(
                ioc,
            )

            if effective.status == IOCStatus.ACTIVE:
                items.append(
                    effective,
                )

        return sorted(
            items,
            key=lambda item: (
                item.last_seen,
                item.ioc_id,
            ),
            reverse=True,
        )

    def list_all(self) -> list[IOC]:
        """
        Return all managed IOCs with effective lifecycle status.
        """

        items = [
            self._with_effective_status(
                ioc,
            )
            for ioc in self._iocs.values()
        ]

        return sorted(
            items,
            key=lambda item: (
                item.last_seen,
                item.ioc_id,
            ),
            reverse=True,
        )

    # =========================================================================
    # Update
    # =========================================================================

    def update(
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

        Editable intelligence fields are applied to an immutable domain
        object through model_copy().

        If the indicator value changes:

            1. Normalize
            2. Validate
            3. Check uniqueness
            4. Replace the deduplication index
        """

        existing = self.get(
            ioc_id,
        )

        # ---------------------------------------------------------------------
        # Indicator value
        # ---------------------------------------------------------------------

        next_value = (
            existing.value
            if value is None
            else value
        )

        next_normalized = (
            existing.normalized_value
        )

        next_expiration = (
            existing.expiration
            if expiration is None
            else expiration
        )

        if value is not None:
            next_normalized = self.normalize(
                existing.ioc_type,
                value,
            )

        # Validate the resulting indicator state.
        self.validate(
            existing.ioc_type,
            next_normalized,
            next_expiration,
        )

        # ---------------------------------------------------------------------
        # Deduplication
        # ---------------------------------------------------------------------

        new_key = self._make_index_key(
            existing.ioc_type.value,
            next_normalized,
        )

        existing_id = self._index.get(
            new_key,
        )

        if (
            existing_id is not None
            and existing_id != ioc_id
        ):
            raise ValueError(
                "IOC already exists for normalized indicator: "
                f"{next_normalized}",
            )

        old_key = self._make_index_key(
            existing.ioc_type.value,
            existing.normalized_value,
        )

        if old_key != new_key:
            self._index.pop(
                old_key,
                None,
            )

            self._index[new_key] = ioc_id

        # ---------------------------------------------------------------------
        # Status
        # ---------------------------------------------------------------------

        next_status = (
            existing.status
            if status is None
            else status
        )

        # Explicit REVOKED must remain revoked.
        # Explicit ACTIVE is allowed, but expiration is evaluated below.
        # EXPIRED is an effective state and can only be represented as such
        # when the expiration timestamp has actually passed.
        if (
            next_status == IOCStatus.EXPIRED
            and (
                next_expiration is None
                or next_expiration > utcnow()
            )
        ):
            raise ValueError(
                "IOC cannot be marked expired before its expiration time",
            )

        # ---------------------------------------------------------------------
        # Build updated domain object
        # ---------------------------------------------------------------------

        updated = existing.model_copy(
            update={
                "value": next_value,
                "normalized_value": next_normalized,
                "confidence": (
                    existing.confidence
                    if confidence is None
                    else confidence
                ),
                "severity": (
                    existing.severity
                    if severity is None
                    else severity
                ),
                "source": (
                    existing.source
                    if source is None
                    else source.strip()
                ),
                "expiration": next_expiration,
                "reputation": (
                    existing.reputation
                    if reputation is None
                    else reputation
                ),
                "status": next_status,
                "feed": (
                    existing.feed
                    if feed is None
                    else (
                        feed.strip()
                        if feed
                        else None
                    )
                ),
                "description": (
                    existing.description
                    if description is None
                    else (
                        description.strip()
                        if description
                        else None
                    )
                ),
                "tags": (
                    existing.tags
                    if tags is None
                    else self._normalise_tags(
                        tags,
                    )
                ),
                "metadata": (
                    existing.metadata
                    if metadata is None
                    else dict(metadata)
                ),
                "relationships": (
                    existing.relationships
                    if relationships is None
                    else relationships
                ),
                "last_seen": utcnow(),
            },
        )

        updated = self._with_effective_status(
            updated,
        )

        self._iocs[ioc_id] = updated

        return updated

    # =========================================================================
    # Revoke / Disable
    # =========================================================================

    def revoke(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Revoke an IOC.

        Product/UI meaning:

            Disable IOC

        The IOC remains persisted and available for investigation,
        historical correlation and audit.

        Raises:
            KeyError:
                IOC does not exist.
        """

        existing = self.get(
            ioc_id,
        )

        if existing.status == IOCStatus.REVOKED:
            return existing

        return self.update(
            ioc_id,
            status=IOCStatus.REVOKED,
        )

    # =========================================================================
    # Activate / Enable
    # =========================================================================

    def activate(
        self,
        ioc_id: UUID,
    ) -> IOC:
        """
        Activate an IOC.

        Product/UI meaning:

            Enable IOC

        An expired IOC cannot be activated while its expiration timestamp
        remains in the past.

        The expiration must first be updated through the Edit workflow.
        """

        existing = self.get(
            ioc_id,
        )

        if existing.expiration is not None:
            if existing.expiration <= utcnow():
                raise ValueError(
                    "Cannot enable an expired IOC. "
                    "Update its expiration first.",
                )

        if existing.status == IOCStatus.ACTIVE:
            return existing

        return self.update(
            ioc_id,
            status=IOCStatus.ACTIVE,
        )

    # =========================================================================
    # Normalize
    # =========================================================================

    def normalize(
        self,
        ioc_type,
        value: str,
    ) -> str:
        """
        Normalize an IOC indicator using the canonical IOC normalizer.
        """

        if not isinstance(value, str):
            raise ValueError(
                "IOC value must be a string",
            )

        value = value.strip()

        if not value:
            raise ValueError(
                "IOC value cannot be empty",
            )

        return self._normalizer.normalize(
            ioc_type,
            value,
        )

    # =========================================================================
    # Validate
    # =========================================================================

    def validate(
        self,
        ioc_type,
        normalized_value: str,
        expiration: datetime | None = None,
    ) -> None:
        """
        Validate an IOC after normalization.

        The IOCValidator remains the authoritative indicator validation
        component.
        """

        self._validator.validate(
            ioc_type,
            normalized_value,
            expiration,
        )

    # =========================================================================
    # Deduplication
    # =========================================================================

    def deduplicate(
        self,
        *,
        ioc_type: str,
        value: str,
    ) -> IOC | None:
        """
        Find an existing IOC by type + normalized value.
        """

        return self.lookup(
            ioc_type=ioc_type,
            value=value,
        )

    # =========================================================================
    # Merge
    # =========================================================================

    def merge(
        self,
        ioc_id: UUID,
        data: IOCCreate,
    ) -> IOC:
        """
        Merge incoming intelligence into an existing IOC.

        The incoming IOC must represent the same indicator identity.
        """

        existing = self.get(
            ioc_id,
        )

        normalized = self.normalize(
            data.ioc_type,
            data.value,
        )

        self.validate(
            data.ioc_type,
            normalized,
            data.expiration,
        )

        if data.ioc_type != existing.ioc_type:
            raise ValueError(
                "IOC type cannot change during merge",
            )

        if normalized != existing.normalized_value:
            raise ValueError(
                "IOC normalized value cannot change during merge",
            )

        merged = self._merge_duplicate(
            existing,
            data,
        )

        self._iocs[ioc_id] = merged

        return merged

    def _merge_duplicate(
        self,
        existing: IOC,
        incoming: IOCCreate,
    ) -> IOC:
        """
        Merge duplicate IOC intelligence.

        Merge rules:

            - last_seen is refreshed
            - highest confidence wins
            - highest severity wins
            - strongest reputation wins
            - incoming expiration wins when provided
            - incoming source replaces existing source when supplied
            - incoming feed replaces existing feed when supplied
            - incoming description replaces existing description when supplied
            - tags are unioned
            - metadata is merged
            - relationships are unioned
            - incoming lifecycle status is respected

        Severity:

            info < low < medium < high < critical

        Reputation:

            unknown < benign < suspicious < malicious
        """

        now = utcnow()

        merged_metadata = dict(
            existing.metadata,
        )

        merged_metadata.update(
            incoming.metadata,
        )

        merged_relationships = (
            self._merge_relationships(
                existing.relationships,
                incoming.relationships,
            )
        )

        merged_tags = self._merge_tags(
            existing.tags,
            incoming.tags,
        )

        merged_severity = (
            self._stronger_severity(
                existing.severity,
                incoming.severity,
            )
        )

        merged_reputation = (
            self._stronger_reputation(
                existing.reputation,
                incoming.reputation,
            )
        )

        merged_description = (
            incoming.description.strip()
            if incoming.description is not None
            else existing.description
        )

        merged_source = (
            incoming.source.strip()
            if incoming.source
            else existing.source
        )

        merged_feed = (
            incoming.feed.strip()
            if incoming.feed is not None
            else existing.feed
        )

        merged_expiration = (
            incoming.expiration
            if incoming.expiration is not None
            else existing.expiration
        )

        # Explicit incoming status is respected.
        merged_status = incoming.status

        merged = existing.model_copy(
            update={
                "last_seen": now,
                "confidence": max(
                    existing.confidence,
                    incoming.confidence,
                ),
                "severity": merged_severity,
                "reputation": merged_reputation,
                "status": merged_status,
                "expiration": merged_expiration,
                "source": merged_source,
                "feed": merged_feed,
                "description": merged_description,
                "tags": merged_tags,
                "metadata": merged_metadata,
                "relationships": merged_relationships,
            },
        )

        return self._with_effective_status(
            merged,
        )

    # =========================================================================
    # Relationship Management
    # =========================================================================

    def add_relationships(
        self,
        ioc_id: UUID,
        relationships: IOCRelationships,
    ) -> IOC:
        """
        Merge additional cross-module relationships into an IOC.
        """

        existing = self.get(
            ioc_id,
        )

        merged_relationships = (
            self._merge_relationships(
                existing.relationships,
                relationships,
            )
        )

        updated = existing.model_copy(
            update={
                "relationships": merged_relationships,
                "last_seen": utcnow(),
            },
        )

        self._iocs[ioc_id] = updated

        return self._with_effective_status(
            updated,
        )

    @staticmethod
    def _merge_relationships(
        current: IOCRelationships,
        incoming: IOCRelationships,
    ) -> IOCRelationships:
        """
        Merge cross-module relationship IDs without duplicates.
        """

        return IOCRelationships(
            event_ids=tuple(
                dict.fromkeys(
                    (
                        *current.event_ids,
                        *incoming.event_ids,
                    ),
                ),
            ),
            alert_ids=tuple(
                dict.fromkeys(
                    (
                        *current.alert_ids,
                        *incoming.alert_ids,
                    ),
                ),
            ),
            incident_ids=tuple(
                dict.fromkeys(
                    (
                        *current.incident_ids,
                        *incoming.incident_ids,
                    ),
                ),
            ),
            asset_ids=tuple(
                dict.fromkeys(
                    (
                        *current.asset_ids,
                        *incoming.asset_ids,
                    ),
                ),
            ),
            mitre_technique_ids=tuple(
                dict.fromkeys(
                    (
                        *current.mitre_technique_ids,
                        *incoming.mitre_technique_ids,
                    ),
                ),
            ),
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

        Only ACTIVE IOCs can become EXPIRED automatically.

        REVOKED remains REVOKED regardless of expiration.
        """

        if (
            ioc.status == IOCStatus.ACTIVE
            and ioc.expiration is not None
            and ioc.expiration <= utcnow()
        ):
            return IOCStatus.EXPIRED

        return ioc.status

    def _with_effective_status(
        self,
        ioc: IOC,
    ) -> IOC:
        """
        Return an IOC copy with expiration-aware lifecycle status.

        Persisted/in-memory source state is not mutated.
        """

        effective = self._effective_status(
            ioc,
        )

        if effective == ioc.status:
            return ioc

        return ioc.model_copy(
            update={
                "status": effective,
            },
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    @staticmethod
    def _make_index_key(
        ioc_type: str,
        normalized_value: str,
    ) -> tuple[str, str]:
        """
        Build canonical deduplication key.
        """

        return (
            str(ioc_type).strip().lower(),
            normalized_value.strip(),
        )

    @staticmethod
    def _stronger_severity(
        current: IOCSeverity,
        incoming: IOCSeverity,
    ) -> IOCSeverity:
        """
        Return the higher IOC severity.
        """

        ranking = {
            IOCSeverity.INFO: 0,
            IOCSeverity.LOW: 1,
            IOCSeverity.MEDIUM: 2,
            IOCSeverity.HIGH: 3,
            IOCSeverity.CRITICAL: 4,
        }

        if ranking[incoming] > ranking[current]:
            return incoming

        return current

    @staticmethod
    def _stronger_reputation(
        current: Reputation,
        incoming: Reputation,
    ) -> Reputation:
        """
        Return the stronger threat reputation.
        """

        ranking = {
            Reputation.UNKNOWN: 0,
            Reputation.BENIGN: 1,
            Reputation.SUSPICIOUS: 2,
            Reputation.MALICIOUS: 3,
        }

        if ranking[incoming] > ranking[current]:
            return incoming

        return current

    @staticmethod
    def _merge_tags(
        current: tuple[str, ...],
        incoming: tuple[str, ...],
    ) -> tuple[str, ...]:
        """
        Merge IOC tags without duplicates.

        Existing tag order is preserved.
        """

        values = (
            *current,
            *incoming,
        )

        return tuple(
            dict.fromkeys(
                tag.strip()
                for tag in values
                if tag and tag.strip()
            ),
        )

    @staticmethod
    def _normalise_tags(
        tags: tuple[str, ...],
    ) -> tuple[str, ...]:
        """
        Normalize tag whitespace and remove duplicates/empty tags.
        """

        return tuple(
            dict.fromkeys(
                tag.strip()
                for tag in tags
                if tag and tag.strip()
            ),
        )

    @staticmethod
    def _coerce_ioc_type(
        ioc_type: str,
    ):
        """
        Convert a string IOC type into the canonical IOCType enum.
        """

        from app.threat_intelligence.models import IOCType

        try:
            return IOCType(
                ioc_type.strip().lower(),
            )
        except ValueError as exc:
            raise ValueError(
                f"Unsupported IOC type: {ioc_type}",
            ) from exc

    @staticmethod
    def _supported_types():
        """
        Return every supported IOC type.
        """

        from app.threat_intelligence.models import IOCType

        return tuple(
            IOCType,
        )

    # =========================================================================
    # Testing / Introspection
    # =========================================================================

    def count(self) -> int:
        """
        Return the number of IOC records currently managed in memory.

        This does not represent the PostgreSQL record count.
        """

        return len(
            self._iocs,
        )

    def clear(self) -> None:
        """
        Clear in-memory IOC state.

        Intended primarily for isolated tests.
        """

        self._iocs.clear()
        self._index.clear()


__all__ = [
    "IOCManager",
]