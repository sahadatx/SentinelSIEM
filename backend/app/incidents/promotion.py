"""
SentinelSIEM — Alert → Incident Promotion

This module owns exactly one application workflow:

    Alert
      ↓
    check existing incident
      ↓
    if exists → duplicate promotion error
      ↓
    build canonical IncidentCreate
      ↓
    IncidentManager.create_from_alert()
      ↓
    return Incident

Promotion-specific logic intentionally does NOT belong in:

    - IncidentManager
    - IncidentService
    - AlertManager
    - API routes

The promotion service is the single application boundary responsible for
converting an existing Alert into an Incident.

Important domain rules:

    - Incident has no priority field.
    - Incident has no ownership_group field.
    - Incident severity is:
        critical
        high
        medium
        low
        informational

    - Incident assignment is represented by a User UUID.
    - New Incidents are created by IncidentManager with OPEN status.
    - Incident IDs, incident numbers, timestamps, audit and timeline state
      are owned by IncidentManager.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.incidents.manager import IncidentManager
from app.incidents.models import (
    Incident,
    IncidentCreate,
    IncidentSeverity,
)
from app.storage.opensearch.incidents import (
    OpenSearchIncidentRepository,
)


# ============================================================================
# Exceptions
# ============================================================================


class IncidentPromotionError(RuntimeError):
    """
    Base exception for Alert → Incident promotion failures.
    """


class IncidentAlreadyExistsError(IncidentPromotionError):
    """
    Raised when an Alert has already been promoted to an Incident.
    """

    def __init__(
        self,
        *,
        alert_id: UUID,
        incident_id: UUID,
    ) -> None:
        self.alert_id = alert_id
        self.incident_id = incident_id

        super().__init__(
            "alert has already been promoted to an incident: "
            f"alert_id={alert_id}, incident_id={incident_id}"
        )


class IncidentPromotionValidationError(
    IncidentPromotionError,
):
    """
    Raised when an Alert cannot be converted into a valid IncidentCreate.
    """


# ============================================================================
# Promotion Service
# ============================================================================


class IncidentPromotionService:
    """
    Application service for Alert → Incident promotion.

    Responsibilities
    ----------------
    1. Validate the source Alert ID.
    2. Check whether the Alert already belongs to an Incident.
    3. Build the canonical IncidentCreate payload.
    4. Delegate creation to IncidentManager.
    5. Return the created Incident.

    This service does NOT:

        - modify the Alert
        - transition the Alert
        - implement Incident lifecycle rules
        - persist Incidents directly
        - implement Incident audit logic
        - enrich Events, IOCs or Assets
        - validate Incident user permissions

    User existence / account-state / role validation belongs to the
    API/application boundary and User Management.
    """

    def __init__(
        self,
        *,
        incident_repository: OpenSearchIncidentRepository,
        manager: IncidentManager | None = None,
    ) -> None:
        if incident_repository is None:
            raise ValueError(
                "incident_repository is required",
            )

        self._incident_repository = incident_repository

        self._manager = (
            manager
            or IncidentManager()
        )

    # ========================================================================
    # Public API
    # ========================================================================

    async def promote_alert(
        self,
        alert: Any,
        *,
        actor: str = "system",
    ) -> Incident:
        """
        Promote an Alert into an Incident.

        The async path is the authoritative promotion path because
        duplicate protection requires a persistent repository lookup.

        Workflow:

            Alert
              ↓
            validate alert_id
              ↓
            persistent duplicate check
              ↓
            IncidentCreate
              ↓
            IncidentManager.create_from_alert_persisted()
              ↓
            Incident
        """

        alert_id = self._require_alert_id(
            alert,
        )

        await self._ensure_not_promoted(
            alert_id,
        )

        incident_data = self._build_incident_create(
            alert,
        )

        try:
            create_from_alert_persisted = getattr(
                self._manager,
                "create_from_alert_persisted",
            )
        except AttributeError as exc:
            raise IncidentPromotionError(
                "IncidentManager.create_from_alert_persisted() "
                "is required for Alert → Incident promotion"
            ) from exc

        try:
            incident = await create_from_alert_persisted(
                incident_data,
                alert_id=alert_id,
                actor=actor,
            )

        except IncidentPromotionError:
            raise

        except ValueError as exc:
            raise IncidentPromotionValidationError(
                str(exc),
            ) from exc

        if not isinstance(
            incident,
            Incident,
        ):
            raise IncidentPromotionError(
                "IncidentManager.create_from_alert_persisted() "
                "returned an invalid Incident",
            )

        return incident

    async def promote_alert_persisted(
        self,
        alert: Any,
        *,
        actor: str = "system",
    ) -> Incident:
        """
        Backward-compatible explicit persisted promotion entry point.

        ``promote_alert()`` is already persistent, but this method is kept
        as an explicit API-facing alias for callers that use the previous
        naming convention.
        """

        return await self.promote_alert(
            alert,
            actor=actor,
        )

    def promote_alert_sync(
        self,
        alert: Any,
        *,
        actor: str = "system",
    ) -> Incident:
        """
        Synchronous promotion path.

        This method intentionally does NOT perform an asynchronous
        OpenSearch duplicate lookup.

        It is suitable only when the caller has already performed the
        persistent duplicate check.

        API code should normally use ``promote_alert()``.
        """

        alert_id = self._require_alert_id(
            alert,
        )

        incident_data = self._build_incident_create(
            alert,
        )

        try:
            create_from_alert = getattr(
                self._manager,
                "create_from_alert",
            )
        except AttributeError as exc:
            raise IncidentPromotionError(
                "IncidentManager.create_from_alert() "
                "is required for synchronous Alert → Incident promotion"
            ) from exc

        try:
            incident = create_from_alert(
                incident_data,
                alert_id=alert_id,
                actor=actor,
            )

        except ValueError as exc:
            raise IncidentPromotionValidationError(
                str(exc),
            ) from exc

        if not isinstance(
            incident,
            Incident,
        ):
            raise IncidentPromotionError(
                "IncidentManager.create_from_alert() "
                "returned an invalid Incident",
            )

        return incident

    # ========================================================================
    # Duplicate Protection
    # ========================================================================

    async def _ensure_not_promoted(
        self,
        alert_id: UUID,
    ) -> None:
        """
        Verify that the Alert is not already attached to an Incident.

        The persistent repository is intentionally queried instead of
        relying on:

            - the Alert object
            - a process-local cache
            - the IncidentManager in-memory registry

        This keeps duplicate protection valid across API processes.
        """

        try:
            existing = await (
                self._incident_repository.get_by_alert_id(
                    alert_id,
                )
            )

        except Exception as exc:
            raise IncidentPromotionError(
                "unable to verify whether alert has already "
                "been promoted to an incident"
            ) from exc

        if existing is not None:
            raise IncidentAlreadyExistsError(
                alert_id=alert_id,
                incident_id=existing.incident_id,
            )

    # ========================================================================
    # Alert → Incident Mapping
    # ========================================================================

    @classmethod
    def _build_incident_create(
        cls,
        alert: Any,
    ) -> IncidentCreate:
        """
        Convert an Alert into the canonical IncidentCreate payload.

        Fields copied from Alert:

            - title
            - description
            - severity
            - alert_id
            - evidence_ids
            - asset_id
            - assigned_to

        Fields intentionally NOT copied:

            - priority
            - ownership_group
            - status
            - incident_id
            - incident_number
            - timestamps
            - audit state
            - timeline state

        IncidentManager owns the latter domain state.
        """

        alert_id = cls._require_alert_id(
            alert,
        )

        title = cls._normalize_text(
            getattr(
                alert,
                "title",
                None,
            ),
        )

        description = cls._normalize_text(
            getattr(
                alert,
                "description",
                None,
            ),
        )

        severity = cls._map_severity(
            getattr(
                alert,
                "severity",
                None,
            ),
        )

        evidence_ids = cls._normalize_sequence(
            getattr(
                alert,
                "evidence_ids",
                (),
            ),
        )

        asset_ids = cls._map_asset_ids(
            getattr(
                alert,
                "asset_id",
                None,
            ),
        )

        initial_assignee = cls._map_assignee(
            getattr(
                alert,
                "assigned_to",
                None,
            ),
        )

        try:
            return IncidentCreate(
                title=title,
                description=description,
                severity=severity,
                alert_ids=(
                    alert_id,
                ),
                evidence_ids=evidence_ids,
                asset_ids=asset_ids,
                initial_assignee=initial_assignee,
            )

        except ValueError as exc:
            raise IncidentPromotionValidationError(
                str(exc),
            ) from exc

    # ========================================================================
    # Alert ID
    # ========================================================================

    @staticmethod
    def _require_alert_id(
        alert: Any,
    ) -> UUID:
        """
        Extract and validate Alert ID.
        """

        if alert is None:
            raise IncidentPromotionValidationError(
                "alert is required",
            )

        alert_id = getattr(
            alert,
            "alert_id",
            None,
        )

        if alert_id is None:
            raise IncidentPromotionValidationError(
                "alert.alert_id is required",
            )

        if isinstance(
            alert_id,
            UUID,
        ):
            return alert_id

        try:
            return UUID(
                str(alert_id).strip(),
            )

        except (
            TypeError,
            ValueError,
            AttributeError,
        ) as exc:
            raise IncidentPromotionValidationError(
                "alert.alert_id must be a valid UUID",
            ) from exc

    # ========================================================================
    # Severity Mapping
    # ========================================================================

    @staticmethod
    def _map_severity(
        severity: Any,
    ) -> IncidentSeverity:
        """
        Map Alert severity to canonical Incident severity.

        Canonical Incident values:

            critical
            high
            medium
            low
            informational

        Alert ``info`` is normalized to Incident
        ``informational``.
        """

        if severity is None:
            raise IncidentPromotionValidationError(
                "alert.severity is required",
            )

        value = getattr(
            severity,
            "value",
            severity,
        )

        normalized = (
            str(value)
            .strip()
            .lower()
        )

        # Alert uses ``info`` while the canonical Incident model uses
        # ``informational``.
        if normalized == "info":
            normalized = "informational"

        try:
            return IncidentSeverity(
                normalized,
            )

        except ValueError as exc:
            raise IncidentPromotionValidationError(
                "alert severity cannot be mapped to incident severity: "
                f"'{normalized}'",
            ) from exc

    # ========================================================================
    # Assignee Mapping
    # ========================================================================

    @staticmethod
    def _map_assignee(
        assignee: Any,
    ) -> UUID | None:
        """
        Normalize Alert.assigned_to into an Incident User UUID.

        Incident stores only the User UUID.

        Human-readable name / role information must be resolved through
        User Management rather than copied into the Incident document.
        """

        if assignee is None:
            return None

        if isinstance(
            assignee,
            UUID,
        ):
            return assignee

        value = str(
            assignee,
        ).strip()

        if not value:
            return None

        try:
            return UUID(
                value,
            )

        except ValueError as exc:
            raise IncidentPromotionValidationError(
                "alert.assigned_to must be a valid user UUID",
            ) from exc

    # ========================================================================
    # Asset Mapping
    # ========================================================================

    @staticmethod
    def _map_asset_ids(
        asset_id: Any,
    ) -> tuple[str, ...]:
        """
        Convert the Alert's single asset_id into the Incident's
        asset_ids relationship tuple.
        """

        if asset_id is None:
            return ()

        value = str(
            asset_id,
        ).strip()

        if not value:
            return ()

        return (
            value,
        )

    # ========================================================================
    # Generic Text Normalization
    # ========================================================================

    @staticmethod
    def _normalize_text(
        value: Any,
    ) -> str:
        """
        Normalize optional text values into strings.

        IncidentCreate is responsible for applying the final Pydantic
        validation constraints.
        """

        if value is None:
            return ""

        return str(
            value,
        ).strip()

    # ========================================================================
    # Relationship Normalization
    # ========================================================================

    @staticmethod
    def _normalize_sequence(
        value: Any,
    ) -> tuple[str, ...]:
        """
        Normalize a relationship-ID collection.

        Duplicate values and empty values are removed while preserving
        original order.
        """

        if value is None:
            return ()

        if isinstance(
            value,
            (str, bytes),
        ):
            values = (
                value,
            )
        else:
            try:
                values = tuple(
                    value,
                )
            except TypeError:
                values = (
                    value,
                )

        normalized: list[str] = []

        for item in values:
            if item is None:
                continue

            text = str(
                item,
            ).strip()

            if not text:
                continue

            if text not in normalized:
                normalized.append(
                    text,
                )

        return tuple(
            normalized,
        )


# ============================================================================
# Functional Convenience API
# ============================================================================


async def promote_alert(
    alert: Any,
    *,
    incident_repository: OpenSearchIncidentRepository,
    manager: IncidentManager | None = None,
    actor: str = "system",
) -> Incident:
    """
    Functional entry point for Alert → Incident promotion.

    Persistent duplicate protection is always performed before creation.
    """

    service = IncidentPromotionService(
        incident_repository=incident_repository,
        manager=manager,
    )

    return await service.promote_alert(
        alert,
        actor=actor,
    )


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "IncidentAlreadyExistsError",
    "IncidentPromotionError",
    "IncidentPromotionService",
    "IncidentPromotionValidationError",
    "promote_alert",
]