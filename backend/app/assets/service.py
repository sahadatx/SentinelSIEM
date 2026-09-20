from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from typing import Any
from uuid import UUID, uuid4

from app.assets.repository import (
    AssetAlreadyExistsError,
    AssetRepository,
    AssetRepositoryError,
)


# ============================================================================
# Constants
# ============================================================================

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 30
MAX_PAGE_SIZE = 30

DEFAULT_RISK = "INFORMATIONAL"
DEFAULT_LIFECYCLE_STATUS = "ENABLED"
DEFAULT_OPERATIONAL_STATUS = "UNKNOWN"

LIFECYCLE_STATUSES = frozenset(
    {
        "ENABLED",
        "DISABLED",
    }
)

OPERATIONAL_STATUSES = frozenset(
    {
        "ONLINE",
        "OFFLINE",
        "UNKNOWN",
        "MAINTENANCE",
    }
)

RISK_LEVELS = frozenset(
    {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFORMATIONAL",
    }
)


# ============================================================================
# Exceptions
# ============================================================================


class AssetServiceError(Exception):
    """
    Base exception for asset-management service failures.
    """

    pass


class AssetValidationError(AssetServiceError):
    """
    Raised when an asset-management request violates service-level
    validation rules.
    """

    pass


class AssetNotFoundServiceError(AssetServiceError):
    """
    Raised when the requested asset does not exist.
    """

    pass


class AssetAlreadyExistsServiceError(AssetServiceError):
    """
    Raised when an asset cannot be created because it already exists.
    """

    pass


# ============================================================================
# Result Models
# ============================================================================


@dataclass(frozen=True)
class AssetListResult:
    """
    Result returned by the asset listing operation.

    Attributes:
        assets:
            Assets returned for the requested page.

        total:
            Total number of matching assets.

        page:
            Current page number.

        page_size:
            Number of assets requested per page.

        total_pages:
            Total number of available pages.
    """

    assets: list[dict[str, Any]]
    total: int
    page: int
    page_size: int
    total_pages: int


@dataclass(frozen=True)
class AssetStatisticsResult:
    """
    Aggregate asset-management statistics.

    Summary cards:
        - total
        - enabled
        - disabled
        - critical

    Grouped statistics:
        - by_type
        - by_risk
        - by_lifecycle_status
        - by_operational_status
    """

    total: int
    enabled: int
    disabled: int
    critical: int
    by_type: dict[str, int]
    by_risk: dict[str, int]
    by_lifecycle_status: dict[str, int]
    by_operational_status: dict[str, int]


# ============================================================================
# Normalization Helpers
# ============================================================================


def _normalize_required_text(
    value: str,
    field_name: str,
) -> str:
    """
    Normalize and validate a required string.
    """

    if not isinstance(value, str):
        raise AssetValidationError(
            f"{field_name} must be a string."
        )

    normalized = value.strip()

    if not normalized:
        raise AssetValidationError(
            f"{field_name} must not be empty."
        )

    return normalized


def _normalize_optional_text(
    value: str | None,
) -> str | None:
    """
    Normalize an optional string.

    Empty strings are treated as None.
    """

    if value is None:
        return None

    if not isinstance(value, str):
        raise AssetValidationError(
            "Optional text fields must be strings."
        )

    normalized = value.strip()

    return normalized or None


def _normalize_upper_optional(
    value: str | None,
    field_name: str,
) -> str | None:
    """
    Normalize an optional enum-like string to uppercase.
    """

    normalized = _normalize_optional_text(value)

    if normalized is None:
        return None

    return normalized.upper()


def _normalize_required_upper(
    value: str,
    field_name: str,
) -> str:
    """
    Normalize a required enum-like string to uppercase.
    """

    normalized = _normalize_required_text(
        value,
        field_name,
    )

    return normalized.upper()


def _normalize_metadata(
    metadata: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """
    Validate and defensively copy metadata.
    """

    if metadata is None:
        return None

    if not isinstance(metadata, dict):
        raise AssetValidationError(
            "metadata must be an object."
        )

    return dict(metadata)


def _normalize_tags(
    tags: list[str] | None,
) -> list[str] | None:
    """
    Validate and normalize asset tags.

    Empty tags are ignored.
    Duplicate tags are removed case-insensitively.
    """

    if tags is None:
        return None

    if not isinstance(tags, list):
        raise AssetValidationError(
            "tags must be a list."
        )

    normalized: list[str] = []
    seen: set[str] = set()

    for tag in tags:
        if not isinstance(tag, str):
            raise AssetValidationError(
                "Each tag must be a string."
            )

        value = tag.strip()

        if not value:
            continue

        key = value.lower()

        if key in seen:
            continue

        seen.add(key)
        normalized.append(value)

    return normalized


# ============================================================================
# Enum Validators
# ============================================================================


def _validate_lifecycle_status(
    status: str,
) -> str:
    """
    Validate an asset lifecycle status.

    Allowed:
        ENABLED
        DISABLED
    """

    normalized = _normalize_required_upper(
        status,
        "lifecycle_status",
    )

    if normalized not in LIFECYCLE_STATUSES:
        allowed = ", ".join(
            sorted(LIFECYCLE_STATUSES)
        )

        raise AssetValidationError(
            "Invalid lifecycle status. "
            f"Allowed values: {allowed}."
        )

    return normalized


def _validate_operational_status(
    status: str,
) -> str:
    """
    Validate an operational status.

    Allowed:
        ONLINE
        OFFLINE
        UNKNOWN
        MAINTENANCE
    """

    normalized = _normalize_required_upper(
        status,
        "operational_status",
    )

    if normalized not in OPERATIONAL_STATUSES:
        allowed = ", ".join(
            sorted(OPERATIONAL_STATUSES)
        )

        raise AssetValidationError(
            "Invalid operational status. "
            f"Allowed values: {allowed}."
        )

    return normalized


def _validate_risk(
    risk: str,
) -> str:
    """
    Validate an asset risk level.
    """

    normalized = _normalize_required_upper(
        risk,
        "risk",
    )

    if normalized not in RISK_LEVELS:
        allowed = ", ".join(
            sorted(RISK_LEVELS)
        )

        raise AssetValidationError(
            "Invalid risk level. "
            f"Allowed values: {allowed}."
        )

    return normalized


# ============================================================================
# Pagination
# ============================================================================


def _validate_pagination(
    page: int,
    page_size: int,
) -> None:
    """
    Validate page/page_size pagination.

    Locked contract:
        page >= 1
        1 <= page_size <= 30
    """

    if isinstance(page, bool) or not isinstance(page, int):
        raise AssetValidationError(
            "page must be an integer."
        )

    if isinstance(page_size, bool) or not isinstance(page_size, int):
        raise AssetValidationError(
            "page_size must be an integer."
        )

    if page < 1:
        raise AssetValidationError(
            "page must be greater than or equal to 1."
        )

    if page_size < 1:
        raise AssetValidationError(
            "page_size must be greater than zero."
        )

    if page_size > MAX_PAGE_SIZE:
        raise AssetValidationError(
            f"page_size must not exceed {MAX_PAGE_SIZE}."
        )


# ============================================================================
# Asset ID Validation
# ============================================================================


def _validate_asset_id(
    asset_id: UUID,
) -> None:
    """
    Validate an asset UUID.
    """

    if not isinstance(asset_id, UUID):
        raise AssetValidationError(
            "asset_id must be a UUID."
        )


# ============================================================================
# Filter Normalization
# ============================================================================


def _normalize_asset_type_filter(
    asset_type: str | None,
) -> str | None:
    """
    Normalize asset type filter.
    """

    return _normalize_upper_optional(
        asset_type,
        "asset_type",
    )


def _normalize_status_filter(
    status: str | None,
) -> str | None:
    """
    Normalize status filter.

    Status may represent either:

        lifecycle:
            ENABLED
            DISABLED

        operational:
            ONLINE
            OFFLINE
            UNKNOWN
            MAINTENANCE
    """

    normalized = _normalize_upper_optional(
        status,
        "status",
    )

    if normalized is None:
        return None

    if (
        normalized not in LIFECYCLE_STATUSES
        and normalized not in OPERATIONAL_STATUSES
    ):
        allowed = sorted(
            LIFECYCLE_STATUSES | OPERATIONAL_STATUSES
        )

        raise AssetValidationError(
            "Invalid status filter. "
            f"Allowed values: {', '.join(allowed)}."
        )

    return normalized


def _normalize_risk_filter(
    risk: str | None,
) -> str | None:
    """
    Normalize and validate risk filter.
    """

    normalized = _normalize_upper_optional(
        risk,
        "risk",
    )

    if normalized is None:
        return None

    if normalized not in RISK_LEVELS:
        raise AssetValidationError(
            f"Invalid risk filter: {risk!r}."
        )

    return normalized


# ============================================================================
# Service
# ============================================================================


class AssetService:
    """
    Business service for SentinelSIEM Asset Management.

    Responsibilities:
        - Validate asset-management input.
        - Normalize asset data.
        - Enforce lifecycle semantics.
        - Coordinate repository operations.
        - Translate repository failures into service errors.
        - Provide stable service-level result objects.

    Non-responsibilities:
        - Authentication.
        - Authorization.
        - FastAPI request/response handling.
        - HTTP status codes.
        - Audit policy.
        - Audit event persistence.
        - Database transaction commit/rollback.

    Authorization is enforced by the API dependency layer.
    """

    def __init__(
        self,
        repository: AssetRepository,
    ) -> None:
        self.repository = repository

    # ========================================================================
    # Create
    # ========================================================================

    async def create_asset(
        self,
        *,
        name: str,
        asset_type: str,
        hostname: str | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        operating_system: str | None = None,
        environment: str | None = None,
        risk: str = DEFAULT_RISK,
        owner: str | None = None,
        location: str | None = None,
        tags: list[str] | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new asset.

        Lifecycle status is always initialized as ENABLED.

        Operational status defaults to UNKNOWN.

        Status is intentionally NOT accepted as a create input from
        the service contract.
        """

        normalized_name = _normalize_required_text(
            name,
            "name",
        )

        normalized_asset_type = _normalize_required_upper(
            asset_type,
            "asset_type",
        )

        normalized_hostname = _normalize_optional_text(
            hostname
        )

        normalized_ip_address = _normalize_optional_text(
            ip_address
        )

        normalized_mac_address = _normalize_optional_text(
            mac_address
        )

        if normalized_mac_address is not None:
            normalized_mac_address = (
                normalized_mac_address.upper()
            )

        normalized_operating_system = (
            _normalize_upper_optional(
                operating_system,
                "operating_system",
            )
        )

        normalized_environment = (
            _normalize_upper_optional(
                environment,
                "environment",
            )
        )

        normalized_risk = _validate_risk(
            risk
        )

        normalized_owner = _normalize_optional_text(
            owner
        )

        normalized_location = _normalize_optional_text(
            location
        )

        normalized_tags = _normalize_tags(
            tags
        )

        normalized_description = _normalize_optional_text(
            description
        )

        normalized_metadata = _normalize_metadata(
            metadata
        )

        asset_id = uuid4()

        try:
            return await self.repository.create(
                asset_id=asset_id,
                name=normalized_name,
                asset_type=normalized_asset_type,
                hostname=normalized_hostname,
                ip_address=normalized_ip_address,
                mac_address=normalized_mac_address,
                operating_system=normalized_operating_system,
                environment=normalized_environment,
                risk=normalized_risk,
                lifecycle_status=DEFAULT_LIFECYCLE_STATUS,
                operational_status=DEFAULT_OPERATIONAL_STATUS,
                owner=normalized_owner,
                location=normalized_location,
                tags=normalized_tags,
                description=normalized_description,
                metadata=normalized_metadata,
            )

        except AssetAlreadyExistsError as exc:
            raise AssetAlreadyExistsServiceError(
                "Asset already exists."
            ) from exc

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to create asset."
            ) from exc

    # ========================================================================
    # Get
    # ========================================================================

    async def get_asset(
        self,
        *,
        asset_id: UUID,
    ) -> dict[str, Any]:
        """
        Retrieve one asset.
        """

        _validate_asset_id(asset_id)

        try:
            asset = await self.repository.get_by_id(
                asset_id
            )

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to retrieve asset."
            ) from exc

        if asset is None:
            raise AssetNotFoundServiceError(
                "Asset not found."
            )

        return asset

    # ========================================================================
    # List
    # ========================================================================

    async def list_assets(
        self,
        *,
        search: str | None = None,
        asset_type: str | None = None,
        status: str | None = None,
        risk: str | None = None,
        operating_system: str | None = None,
        environment: str | None = None,
        page: int = DEFAULT_PAGE,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> AssetListResult:
        """
        List assets with locked filters and pagination.

        Search:
            Asset Name
            Hostname
            IP Address
            MAC Address

        Filters:
            Asset Type
            Status
            Risk
            Operating System
            Environment

        Pagination:
            page
            page_size

        The repository performs the actual database filtering and
        pagination. The service validates and normalizes inputs.
        """

        _validate_pagination(
            page,
            page_size,
        )

        normalized_search = _normalize_optional_text(
            search
        )

        normalized_asset_type = (
            _normalize_asset_type_filter(
                asset_type
            )
        )

        normalized_status = _normalize_status_filter(
            status
        )

        normalized_risk = _normalize_risk_filter(
            risk
        )

        normalized_operating_system = (
            _normalize_upper_optional(
                operating_system,
                "operating_system",
            )
        )

        normalized_environment = (
            _normalize_upper_optional(
                environment,
                "environment",
            )
        )

        try:
            result = await self.repository.list_assets(
                search=normalized_search,
                asset_type=normalized_asset_type,
                status=normalized_status,
                risk=normalized_risk,
                operating_system=normalized_operating_system,
                environment=normalized_environment,
                page=page,
                page_size=page_size,
            )

        except ValueError as exc:
            raise AssetValidationError(
                str(exc)
            ) from exc

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to list assets."
            ) from exc

        return AssetListResult(
            assets=result["items"],
            total=int(result["total"]),
            page=int(result["page"]),
            page_size=int(result["page_size"]),
            total_pages=int(result["total_pages"]),
        )

    # ========================================================================
    # Update
    # ========================================================================

    async def update_asset(
        self,
        *,
        asset_id: UUID,
        name: str | None = None,
        hostname: str | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        asset_type: str | None = None,
        operating_system: str | None = None,
        environment: str | None = None,
        risk: str | None = None,
        owner: str | None = None,
        location: str | None = None,
        tags: list[str] | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Update asset information.

        Lifecycle status is intentionally NOT accepted here.

        Enable/Disable must be performed through
        update_lifecycle_status().

        NOTE:
            This method uses None as "not supplied".
            Explicit clearing of nullable fields must be handled by
            the API/schema field-presence layer if required.
        """

        _validate_asset_id(asset_id)

        normalized_name = None

        if name is not None:
            normalized_name = _normalize_required_text(
                name,
                "name",
            )

        normalized_hostname = _normalize_optional_text(
            hostname
        )

        normalized_ip_address = _normalize_optional_text(
            ip_address
        )

        normalized_mac_address = _normalize_optional_text(
            mac_address
        )

        if normalized_mac_address is not None:
            normalized_mac_address = (
                normalized_mac_address.upper()
            )

        normalized_asset_type = None

        if asset_type is not None:
            normalized_asset_type = _normalize_required_upper(
                asset_type,
                "asset_type",
            )

        normalized_operating_system = (
            _normalize_upper_optional(
                operating_system,
                "operating_system",
            )
        )

        normalized_environment = (
            _normalize_upper_optional(
                environment,
                "environment",
            )
        )

        normalized_risk = None

        if risk is not None:
            normalized_risk = _validate_risk(
                risk
            )

        normalized_owner = _normalize_optional_text(
            owner
        )

        normalized_location = _normalize_optional_text(
            location
        )

        normalized_tags = _normalize_tags(
            tags
        )

        normalized_description = _normalize_optional_text(
            description
        )

        normalized_metadata = _normalize_metadata(
            metadata
        )

        # --------------------------------------------------------------------
        # Ensure at least one field was provided.
        # --------------------------------------------------------------------

        if all(
            value is None
            for value in (
                normalized_name,
                normalized_hostname,
                normalized_ip_address,
                normalized_mac_address,
                normalized_asset_type,
                normalized_operating_system,
                normalized_environment,
                normalized_risk,
                normalized_owner,
                normalized_location,
                normalized_tags,
                normalized_description,
                normalized_metadata,
            )
        ):
            raise AssetValidationError(
                "At least one asset field must be provided."
            )

        try:
            asset = await self.repository.update(
                asset_id,
                name=normalized_name,
                hostname=normalized_hostname,
                ip_address=normalized_ip_address,
                mac_address=normalized_mac_address,
                asset_type=normalized_asset_type,
                operating_system=normalized_operating_system,
                environment=normalized_environment,
                risk=normalized_risk,
                owner=normalized_owner,
                location=normalized_location,
                tags=normalized_tags,
                description=normalized_description,
                metadata=normalized_metadata,
            )

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to update asset."
            ) from exc

        if asset is None:
            raise AssetNotFoundServiceError(
                "Asset not found."
            )

        return asset

    # ========================================================================
    # Enable / Disable
    # ========================================================================

    async def update_lifecycle_status(
        self,
        *,
        asset_id: UUID,
        lifecycle_status: str,
    ) -> dict[str, Any]:
        """
        Enable or disable an asset.

        Allowed:
            ENABLED
            DISABLED

        Operational status remains unchanged.
        """

        _validate_asset_id(asset_id)

        normalized_status = _validate_lifecycle_status(
            lifecycle_status
        )

        try:
            asset = await self.repository.update_lifecycle_status(
                asset_id,
                lifecycle_status=normalized_status,
            )

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to update asset lifecycle status."
            ) from exc

        if asset is None:
            raise AssetNotFoundServiceError(
                "Asset not found."
            )

        return asset

    async def enable_asset(
        self,
        *,
        asset_id: UUID,
    ) -> dict[str, Any]:
        """
        Enable an asset.
        """

        return await self.update_lifecycle_status(
            asset_id=asset_id,
            lifecycle_status="ENABLED",
        )

    async def disable_asset(
        self,
        *,
        asset_id: UUID,
    ) -> dict[str, Any]:
        """
        Disable an asset.
        """

        return await self.update_lifecycle_status(
            asset_id=asset_id,
            lifecycle_status="DISABLED",
        )

    # ========================================================================
    # Operational Status
    # ========================================================================

    async def update_operational_status(
        self,
        *,
        asset_id: UUID,
        operational_status: str,
    ) -> dict[str, Any]:
        """
        Update operational status.

        This is intended for internal discovery/monitoring workflows.

        It is intentionally separate from Enable/Disable.
        """

        _validate_asset_id(asset_id)

        normalized_status = _validate_operational_status(
            operational_status
        )

        try:
            asset = await self.repository.update_operational_status(
                asset_id,
                operational_status=normalized_status,
            )

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to update asset operational status."
            ) from exc

        if asset is None:
            raise AssetNotFoundServiceError(
                "Asset not found."
            )

        return asset

    # ========================================================================
    # Exists
    # ========================================================================

    async def asset_exists(
        self,
        *,
        asset_id: UUID,
    ) -> bool:
        """
        Check whether an asset exists.
        """

        _validate_asset_id(asset_id)

        try:
            return await self.repository.exists(
                asset_id
            )

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to check asset existence."
            ) from exc

    # ========================================================================
    # Statistics
    # ========================================================================

    async def statistics(
        self,
    ) -> AssetStatisticsResult:
        """
        Return aggregate Asset Inventory statistics.

        Summary cards:
            Total Assets
            Enabled
            Disabled
            Critical Risk
        """

        try:
            result = await self.repository.get_statistics()

        except AssetRepositoryError as exc:
            raise AssetServiceError(
                "Unable to calculate asset statistics."
            ) from exc

        return AssetStatisticsResult(
            total=int(result["total"]),
            enabled=int(result["enabled"]),
            disabled=int(result["disabled"]),
            critical=int(result["critical"]),
            by_type=dict(
                result.get("by_type", {})
            ),
            by_risk=dict(
                result.get("by_risk", {})
            ),
            by_lifecycle_status=dict(
                result.get(
                    "by_lifecycle_status",
                    {},
                )
            ),
            by_operational_status=dict(
                result.get(
                    "by_operational_status",
                    {},
                )
            ),
        )

    async def get_statistics(
        self,
    ) -> AssetStatisticsResult:
        """
        Backward-compatible alias for statistics().
        """

        return await self.statistics()


# ============================================================================
# Public exports
# ============================================================================


__all__ = [
    "AssetAlreadyExistsServiceError",
    "AssetListResult",
    "AssetNotFoundServiceError",
    "AssetService",
    "AssetServiceError",
    "AssetStatisticsResult",
    "AssetValidationError",
    "DEFAULT_LIFECYCLE_STATUS",
    "DEFAULT_OPERATIONAL_STATUS",
    "DEFAULT_PAGE",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_RISK",
    "LIFECYCLE_STATUSES",
    "MAX_PAGE_SIZE",
    "OPERATIONAL_STATUSES",
    "RISK_LEVELS",
]