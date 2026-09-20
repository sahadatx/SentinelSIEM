from __future__ import annotations

from datetime import UTC, datetime
from math import ceil
from typing import Any
from uuid import UUID

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.postgres.models import Asset


# ============================================================================
# Constants
# ============================================================================

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 30
MAX_PAGE_SIZE = 30

LIFECYCLE_ENABLED = "ENABLED"
LIFECYCLE_DISABLED = "DISABLED"

OPERATIONAL_ONLINE = "ONLINE"
OPERATIONAL_OFFLINE = "OFFLINE"
OPERATIONAL_UNKNOWN = "UNKNOWN"
OPERATIONAL_MAINTENANCE = "MAINTENANCE"

RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFORMATIONAL = "INFORMATIONAL"

LIFECYCLE_STATUSES = {
    LIFECYCLE_ENABLED,
    LIFECYCLE_DISABLED,
}

OPERATIONAL_STATUSES = {
    OPERATIONAL_ONLINE,
    OPERATIONAL_OFFLINE,
    OPERATIONAL_UNKNOWN,
    OPERATIONAL_MAINTENANCE,
}

RISK_LEVELS = {
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_MEDIUM,
    RISK_LOW,
    RISK_INFORMATIONAL,
}


# ============================================================================
# Exceptions
# ============================================================================


class AssetRepositoryError(Exception):
    """
    Base exception for asset repository failures.
    """

    pass


class AssetNotFoundError(AssetRepositoryError):
    """
    Raised when a requested asset does not exist.
    """

    pass


class AssetAlreadyExistsError(AssetRepositoryError):
    """
    Raised when an asset cannot be created because of a uniqueness
    or primary-key constraint violation.
    """

    pass


# ============================================================================
# Helpers
# ============================================================================


def _utc_now() -> datetime:
    """
    Return the current timezone-aware UTC timestamp.
    """

    return datetime.now(UTC)


def _validate_asset_id(asset_id: UUID) -> UUID:
    """
    Validate an asset identifier.
    """

    if not isinstance(asset_id, UUID):
        raise ValueError("asset_id must be a UUID")

    return asset_id


def _normalize_text(value: str | None) -> str | None:
    """
    Normalize optional text.

    Empty or whitespace-only strings become None.
    """

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("value must be a string")

    normalized = value.strip()

    return normalized or None


def _normalize_required_text(
    value: str,
    field_name: str,
) -> str:
    """
    Normalize a required text value.
    """

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    normalized = value.strip()

    if not normalized:
        raise ValueError(f"{field_name} must not be empty")

    return normalized


def _normalize_enum(
    value: str | None,
    field_name: str,
    allowed: set[str],
) -> str | None:
    """
    Normalize and validate an enum-like value.

    Values are normalized to uppercase.
    """

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    normalized = value.strip().upper()

    if normalized not in allowed:
        raise ValueError(
            f"Invalid {field_name}: {value!r}"
        )

    return normalized


def _normalize_metadata(
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Normalize asset metadata.

    Metadata is always represented as a dictionary.
    """

    if metadata is None:
        return {}

    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a dictionary")

    return dict(metadata)


def _normalize_tags(
    tags: list[str] | None,
) -> list[str]:
    """
    Normalize asset tags.

    - None -> []
    - whitespace is stripped
    - empty tags are removed
    - duplicates are removed
    - original order is preserved
    """

    if tags is None:
        return []

    if not isinstance(tags, list):
        raise ValueError("tags must be a list")

    normalized: list[str] = []
    seen: set[str] = set()

    for tag in tags:
        if not isinstance(tag, str):
            raise ValueError("each tag must be a string")

        value = tag.strip()

        if not value:
            continue

        key = value.lower()

        if key in seen:
            continue

        seen.add(key)
        normalized.append(value)

    return normalized


def _normalize_ip(
    value: str | None,
) -> str | None:
    """
    Normalize an IP address string.

    PostgreSQL INET performs the actual database-level validation.
    """

    return _normalize_text(value)


def _normalize_mac(
    value: str | None,
) -> str | None:
    """
    Normalize a MAC address.

    The repository stores MAC addresses in uppercase.
    Separators are preserved.
    """

    normalized = _normalize_text(value)

    if normalized is None:
        return None

    return normalized.upper()


def _asset_to_dict(
    asset: Asset,
) -> dict[str, Any]:
    """
    Convert an ORM Asset instance into an API/domain-friendly dictionary.

    Important:
        ORM uses `asset_metadata` for the Python attribute while the
        PostgreSQL column is named `metadata`.
    """

    return {
        "asset_id": asset.asset_id,
        "name": asset.name,
        "hostname": asset.hostname,
        "ip_address": (
            str(asset.ip_address)
            if asset.ip_address is not None
            else None
        ),
        "mac_address": asset.mac_address,
        "asset_type": asset.asset_type,
        "operating_system": asset.operating_system,
        "environment": asset.environment,
        "risk": asset.risk,
        "lifecycle_status": asset.lifecycle_status,
        "operational_status": asset.operational_status,
        "owner": asset.owner,
        "location": asset.location,
        "tags": list(asset.tags or []),
        "description": asset.description,
        "metadata": dict(asset.asset_metadata or {}),
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


def _apply_filters(
    statement,
    *,
    search: str | None = None,
    asset_type: str | None = None,
    status: str | None = None,
    risk: str | None = None,
    operating_system: str | None = None,
    environment: str | None = None,
):
    """
    Apply the locked Asset Inventory filters.

    Search fields ONLY:
        - Asset Name
        - Hostname
        - IP Address
        - MAC Address

    Filters:
        - Asset Type
        - Status
        - Risk
        - Operating System
        - Environment

    Status behavior:
        ENABLED / DISABLED
            -> lifecycle_status

        ONLINE / OFFLINE / UNKNOWN / MAINTENANCE
            -> operational_status
    """

    normalized_search = _normalize_text(search)

    normalized_asset_type = (
        asset_type.strip().upper()
        if isinstance(asset_type, str) and asset_type.strip()
        else None
    )

    normalized_status = (
        status.strip().upper()
        if isinstance(status, str) and status.strip()
        else None
    )

    normalized_risk = (
        risk.strip().upper()
        if isinstance(risk, str) and risk.strip()
        else None
    )

    normalized_os = (
        operating_system.strip().upper()
        if isinstance(operating_system, str)
        and operating_system.strip()
        else None
    )

    normalized_environment = (
        environment.strip().upper()
        if isinstance(environment, str)
        and environment.strip()
        else None
    )

    # ------------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------------

    if normalized_search is not None:
        pattern = f"%{normalized_search.lower()}%"

        statement = statement.where(
            or_(
                func.lower(Asset.name).like(pattern),
                func.lower(Asset.hostname).like(pattern),
                func.lower(
                    cast(Asset.ip_address, String)
                ).like(pattern),
                func.lower(Asset.mac_address).like(pattern),
            )
        )

    # ------------------------------------------------------------------------
    # Asset Type
    # ------------------------------------------------------------------------

    if normalized_asset_type is not None:
        statement = statement.where(
            Asset.asset_type == normalized_asset_type
        )

    # ------------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------------

    if normalized_status is not None:

        if normalized_status in LIFECYCLE_STATUSES:
            statement = statement.where(
                Asset.lifecycle_status == normalized_status
            )

        elif normalized_status in OPERATIONAL_STATUSES:
            statement = statement.where(
                Asset.operational_status == normalized_status
            )

        else:
            raise ValueError(
                f"Invalid status filter: {status!r}"
            )

    # ------------------------------------------------------------------------
    # Risk
    # ------------------------------------------------------------------------

    if normalized_risk is not None:
        if normalized_risk not in RISK_LEVELS:
            raise ValueError(
                f"Invalid risk filter: {risk!r}"
            )

        statement = statement.where(
            Asset.risk == normalized_risk
        )

    # ------------------------------------------------------------------------
    # Operating System
    # ------------------------------------------------------------------------

    if normalized_os is not None:
        statement = statement.where(
            Asset.operating_system == normalized_os
        )

    # ------------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------------

    if normalized_environment is not None:
        statement = statement.where(
            Asset.environment == normalized_environment
        )

    return statement


# ============================================================================
# Repository
# ============================================================================


class AssetRepository:
    """
    PostgreSQL repository for SentinelSIEM Asset Management.

    Responsibilities:
        - Create assets.
        - Retrieve assets.
        - Update asset information.
        - Update lifecycle status.
        - Search/filter assets.
        - Paginate assets.
        - Calculate asset statistics.
        - Check asset existence.

    Non-responsibilities:
        - Authentication.
        - Authorization.
        - RBAC decisions.
        - HTTP concerns.
        - Audit policy.
        - Audit event creation.
        - Transaction commit/rollback.

    Transaction ownership belongs to the caller.
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # ========================================================================
    # Internal lookup
    # ========================================================================

    async def _get_asset(
        self,
        asset_id: UUID,
        *,
        for_update: bool = False,
    ) -> Asset | None:
        """
        Retrieve an asset ORM object by UUID.

        When for_update=True, a PostgreSQL row-level lock is requested.
        """

        _validate_asset_id(asset_id)

        statement = select(Asset).where(
            Asset.asset_id == asset_id
        )

        if for_update:
            statement = statement.with_for_update()

        try:
            result = await self.session.execute(statement)

            return result.scalar_one_or_none()

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to retrieve asset."
            ) from exc

    # ========================================================================
    # Create
    # ========================================================================

    async def create(
        self,
        *,
        asset_id: UUID,
        name: str,
        asset_type: str,
        hostname: str | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        operating_system: str | None = None,
        environment: str | None = None,
        risk: str = RISK_INFORMATIONAL,
        lifecycle_status: str = LIFECYCLE_ENABLED,
        operational_status: str = OPERATIONAL_UNKNOWN,
        owner: str | None = None,
        location: str | None = None,
        tags: list[str] | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Create and persist a new asset.

        The repository does not commit the transaction.
        """

        _validate_asset_id(asset_id)

        normalized_name = _normalize_required_text(
            name,
            "name",
        )

        normalized_asset_type = _normalize_required_text(
            asset_type,
            "asset_type",
        ).upper()

        normalized_risk = _normalize_enum(
            risk,
            "risk",
            RISK_LEVELS,
        )

        normalized_lifecycle = _normalize_enum(
            lifecycle_status,
            "lifecycle_status",
            LIFECYCLE_STATUSES,
        )

        normalized_operational = _normalize_enum(
            operational_status,
            "operational_status",
            OPERATIONAL_STATUSES,
        )

        now = _utc_now()

        record = Asset(
            asset_id=asset_id,
            name=normalized_name,
            hostname=_normalize_text(hostname),
            ip_address=_normalize_ip(ip_address),
            mac_address=_normalize_mac(mac_address),
            asset_type=normalized_asset_type,
            operating_system=(
                _normalize_text(operating_system).upper()
                if _normalize_text(operating_system)
                else None
            ),
            environment=(
                _normalize_text(environment).upper()
                if _normalize_text(environment)
                else None
            ),
            risk=normalized_risk,
            lifecycle_status=normalized_lifecycle,
            operational_status=normalized_operational,
            owner=_normalize_text(owner),
            location=_normalize_text(location),
            tags=_normalize_tags(tags),
            description=_normalize_text(description),
            asset_metadata=_normalize_metadata(metadata),
            first_seen=first_seen or now,
            last_seen=last_seen,
            created_at=now,
            updated_at=now,
        )

        self.session.add(record)

        try:
            await self.session.flush()

        except IntegrityError as exc:
            raise AssetAlreadyExistsError(
                "Unable to create asset because the asset already exists "
                "or a database uniqueness constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to create asset."
            ) from exc

        return _asset_to_dict(record)

    # ========================================================================
    # Get by ID
    # ========================================================================

    async def get_by_id(
        self,
        asset_id: UUID,
    ) -> dict[str, Any] | None:
        """
        Retrieve one asset by UUID.

        Returns:
            Asset dictionary when found.
            None when the asset does not exist.
        """

        record = await self._get_asset(asset_id)

        if record is None:
            return None

        return _asset_to_dict(record)

    # ========================================================================
    # Get required
    # ========================================================================

    async def get_required(
        self,
        asset_id: UUID,
    ) -> dict[str, Any]:
        """
        Retrieve an asset or raise AssetNotFoundError.
        """

        record = await self._get_asset(asset_id)

        if record is None:
            raise AssetNotFoundError(
                "Asset not found."
            )

        return _asset_to_dict(record)

    # ========================================================================
    # List with pagination
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
    ) -> dict[str, Any]:
        """
        List assets using the locked page/page_size pagination model.

        Default:
            page = 1
            page_size = 30

        Returns:
            {
                "items": [...],
                "total": int,
                "page": int,
                "page_size": int,
                "total_pages": int,
            }
        """

        if page < 1:
            raise ValueError(
                "page must be greater than or equal to 1"
            )

        if page_size < 1:
            raise ValueError(
                "page_size must be greater than zero"
            )

        if page_size > MAX_PAGE_SIZE:
            raise ValueError(
                f"page_size must not exceed {MAX_PAGE_SIZE}"
            )

        base_statement = select(Asset)

        base_statement = _apply_filters(
            base_statement,
            search=search,
            asset_type=asset_type,
            status=status,
            risk=risk,
            operating_system=operating_system,
            environment=environment,
        )

        # --------------------------------------------------------------------
        # Total count
        # --------------------------------------------------------------------

        count_statement = select(
            func.count(Asset.asset_id)
        ).select_from(Asset)

        count_statement = _apply_filters(
            count_statement,
            search=search,
            asset_type=asset_type,
            status=status,
            risk=risk,
            operating_system=operating_system,
            environment=environment,
        )

        try:
            count_result = await self.session.execute(
                count_statement
            )

            total = int(count_result.scalar_one())

            # ---------------------------------------------------------------
            # Total pages
            # ---------------------------------------------------------------

            total_pages = (
                ceil(total / page_size)
                if total > 0
                else 0
            )

            # ---------------------------------------------------------------
            # If requested page is beyond the available range, return empty
            # items rather than silently changing the requested page.
            #
            # The service/frontend can then perform its required fallback
            # to page 1 after refresh/filter changes.
            # ---------------------------------------------------------------

            if total == 0 or page > total_pages:
                return {
                    "items": [],
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": total_pages,
                }

            offset = (page - 1) * page_size

            statement = (
                base_statement
                .order_by(
                    Asset.created_at.desc(),
                    Asset.asset_id.desc(),
                )
                .limit(page_size)
                .offset(offset)
            )

            result = await self.session.execute(statement)

            records = result.scalars().all()

            return {
                "items": [
                    _asset_to_dict(record)
                    for record in records
                ],
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
            }

        except ValueError:
            raise

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to list assets."
            ) from exc

    # ========================================================================
    # Count
    # ========================================================================

    async def count_assets(
        self,
        *,
        search: str | None = None,
        asset_type: str | None = None,
        status: str | None = None,
        risk: str | None = None,
        operating_system: str | None = None,
        environment: str | None = None,
    ) -> int:
        """
        Count assets matching the supplied filters.
        """

        statement = (
            select(func.count(Asset.asset_id))
            .select_from(Asset)
        )

        statement = _apply_filters(
            statement,
            search=search,
            asset_type=asset_type,
            status=status,
            risk=risk,
            operating_system=operating_system,
            environment=environment,
        )

        try:
            result = await self.session.execute(statement)

            return int(result.scalar_one())

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to count assets."
            ) from exc

    # ========================================================================
    # Update asset information
    # ========================================================================

    async def update(
        self,
        asset_id: UUID,
        *,
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
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> dict[str, Any] | None:
        """
        Update asset information.

        Lifecycle status is intentionally NOT accepted here.

        Enable/Disable must use update_lifecycle_status().
        """

        record = await self._get_asset(
            asset_id,
            for_update=True,
        )

        if record is None:
            return None

        # --------------------------------------------------------------------
        # Required fields
        # --------------------------------------------------------------------

        if name is not None:
            record.name = _normalize_required_text(
                name,
                "name",
            )

        if asset_type is not None:
            record.asset_type = _normalize_required_text(
                asset_type,
                "asset_type",
            ).upper()

        # --------------------------------------------------------------------
        # Nullable fields
        # --------------------------------------------------------------------

        if hostname is not None:
            record.hostname = _normalize_text(hostname)

        if ip_address is not None:
            record.ip_address = _normalize_ip(ip_address)

        if mac_address is not None:
            record.mac_address = _normalize_mac(mac_address)

        if operating_system is not None:
            normalized_os = _normalize_text(
                operating_system
            )

            record.operating_system = (
                normalized_os.upper()
                if normalized_os
                else None
            )

        if environment is not None:
            normalized_environment = _normalize_text(
                environment
            )

            record.environment = (
                normalized_environment.upper()
                if normalized_environment
                else None
            )

        if owner is not None:
            record.owner = _normalize_text(owner)

        if location is not None:
            record.location = _normalize_text(location)

        if description is not None:
            record.description = _normalize_text(description)

        # --------------------------------------------------------------------
        # Risk
        # --------------------------------------------------------------------

        if risk is not None:
            record.risk = _normalize_enum(
                risk,
                "risk",
                RISK_LEVELS,
            )

        # --------------------------------------------------------------------
        # Tags
        # --------------------------------------------------------------------

        if tags is not None:
            record.tags = _normalize_tags(tags)

        # --------------------------------------------------------------------
        # Metadata
        # --------------------------------------------------------------------

        if metadata is not None:
            record.asset_metadata = _normalize_metadata(
                metadata
            )

        # --------------------------------------------------------------------
        # Discovery timestamps
        # --------------------------------------------------------------------

        if first_seen is not None:
            record.first_seen = first_seen

        if last_seen is not None:
            record.last_seen = last_seen

        record.updated_at = _utc_now()

        try:
            await self.session.flush()

        except IntegrityError as exc:
            raise AssetRepositoryError(
                "Unable to update asset because a database "
                "constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to update asset."
            ) from exc

        return _asset_to_dict(record)

    # ========================================================================
    # Update lifecycle status
    # ========================================================================

    async def update_lifecycle_status(
        self,
        asset_id: UUID,
        *,
        lifecycle_status: str,
    ) -> dict[str, Any] | None:
        """
        Enable or disable an asset.

        Allowed values:
            ENABLED
            DISABLED

        Operational status is intentionally not changed here.

        This preserves the locked distinction:

            lifecycle_status
                ENABLED / DISABLED

            operational_status
                ONLINE / OFFLINE / UNKNOWN / MAINTENANCE
        """

        normalized_status = _normalize_enum(
            lifecycle_status,
            "lifecycle_status",
            LIFECYCLE_STATUSES,
        )

        record = await self._get_asset(
            asset_id,
            for_update=True,
        )

        if record is None:
            return None

        record.lifecycle_status = normalized_status
        record.updated_at = _utc_now()

        try:
            await self.session.flush()

        except IntegrityError as exc:
            raise AssetRepositoryError(
                "Unable to update asset lifecycle status "
                "because a database constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to update asset lifecycle status."
            ) from exc

        return _asset_to_dict(record)

    # ========================================================================
    # Update operational status
    # ========================================================================

    async def update_operational_status(
        self,
        asset_id: UUID,
        *,
        operational_status: str,
    ) -> dict[str, Any] | None:
        """
        Update operational status.

        This method is available for internal/system discovery workflows.

        UI lifecycle Enable/Disable actions must use
        update_lifecycle_status().
        """

        normalized_status = _normalize_enum(
            operational_status,
            "operational_status",
            OPERATIONAL_STATUSES,
        )

        record = await self._get_asset(
            asset_id,
            for_update=True,
        )

        if record is None:
            return None

        record.operational_status = normalized_status
        record.updated_at = _utc_now()

        try:
            await self.session.flush()

        except IntegrityError as exc:
            raise AssetRepositoryError(
                "Unable to update asset operational status "
                "because a database constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to update asset operational status."
            ) from exc

        return _asset_to_dict(record)

    # ========================================================================
    # Exists
    # ========================================================================

    async def exists(
        self,
        asset_id: UUID,
    ) -> bool:
        """
        Check whether an asset exists.
        """

        _validate_asset_id(asset_id)

        statement = (
            select(func.count(Asset.asset_id))
            .select_from(Asset)
            .where(
                Asset.asset_id == asset_id
            )
        )

        try:
            result = await self.session.execute(statement)

            return bool(result.scalar_one())

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to check asset existence."
            ) from exc

    # ========================================================================
    # Statistics
    # ========================================================================

    async def get_statistics(
        self,
    ) -> dict[str, Any]:
        """
        Return complete Asset Inventory statistics.

        Summary cards:
            - Total Assets
            - Enabled
            - Disabled
            - Critical Risk

        Additional grouped statistics:
            - by_type
            - by_risk
            - by_lifecycle_status
            - by_operational_status
        """

        try:
            # ----------------------------------------------------------------
            # Total
            # ----------------------------------------------------------------

            total_statement = select(
                func.count(Asset.asset_id)
            )

            total_result = await self.session.execute(
                total_statement
            )

            total = int(total_result.scalar_one())

            # ----------------------------------------------------------------
            # Enabled
            # ----------------------------------------------------------------

            enabled_statement = select(
                func.count(Asset.asset_id)
            ).where(
                Asset.lifecycle_status == LIFECYCLE_ENABLED
            )

            enabled_result = await self.session.execute(
                enabled_statement
            )

            enabled = int(enabled_result.scalar_one())

            # ----------------------------------------------------------------
            # Disabled
            # ----------------------------------------------------------------

            disabled_statement = select(
                func.count(Asset.asset_id)
            ).where(
                Asset.lifecycle_status == LIFECYCLE_DISABLED
            )

            disabled_result = await self.session.execute(
                disabled_statement
            )

            disabled = int(disabled_result.scalar_one())

            # ----------------------------------------------------------------
            # Critical
            # ----------------------------------------------------------------

            critical_statement = select(
                func.count(Asset.asset_id)
            ).where(
                Asset.risk == RISK_CRITICAL
            )

            critical_result = await self.session.execute(
                critical_statement
            )

            critical = int(critical_result.scalar_one())

            # ----------------------------------------------------------------
            # By asset type
            # ----------------------------------------------------------------

            type_statement = (
                select(
                    Asset.asset_type,
                    func.count(Asset.asset_id),
                )
                .group_by(Asset.asset_type)
                .order_by(Asset.asset_type)
            )

            type_result = await self.session.execute(
                type_statement
            )

            by_type = {
                str(asset_type): int(count)
                for asset_type, count in type_result.all()
            }

            # ----------------------------------------------------------------
            # By risk
            # ----------------------------------------------------------------

            risk_statement = (
                select(
                    Asset.risk,
                    func.count(Asset.asset_id),
                )
                .group_by(Asset.risk)
                .order_by(Asset.risk)
            )

            risk_result = await self.session.execute(
                risk_statement
            )

            by_risk = {
                str(risk): int(count)
                for risk, count in risk_result.all()
            }

            # ----------------------------------------------------------------
            # By lifecycle status
            # ----------------------------------------------------------------

            lifecycle_statement = (
                select(
                    Asset.lifecycle_status,
                    func.count(Asset.asset_id),
                )
                .group_by(Asset.lifecycle_status)
                .order_by(Asset.lifecycle_status)
            )

            lifecycle_result = await self.session.execute(
                lifecycle_statement
            )

            by_lifecycle_status = {
                str(status): int(count)
                for status, count in lifecycle_result.all()
            }

            # ----------------------------------------------------------------
            # By operational status
            # ----------------------------------------------------------------

            operational_statement = (
                select(
                    Asset.operational_status,
                    func.count(Asset.asset_id),
                )
                .group_by(Asset.operational_status)
                .order_by(Asset.operational_status)
            )

            operational_result = await self.session.execute(
                operational_statement
            )

            by_operational_status = {
                str(status): int(count)
                for status, count in operational_result.all()
            }

            return {
                "total": total,
                "enabled": enabled,
                "disabled": disabled,
                "critical": critical,
                "by_type": by_type,
                "by_risk": by_risk,
                "by_lifecycle_status": by_lifecycle_status,
                "by_operational_status": by_operational_status,
            }

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to calculate asset statistics."
            ) from exc

    # ========================================================================
    # Backward-friendly statistics helpers
    # ========================================================================

    async def count_by_lifecycle_status(
        self,
    ) -> dict[str, int]:
        """
        Return asset counts grouped by lifecycle status.
        """

        statement = (
            select(
                Asset.lifecycle_status,
                func.count(Asset.asset_id),
            )
            .group_by(Asset.lifecycle_status)
            .order_by(Asset.lifecycle_status)
        )

        try:
            result = await self.session.execute(statement)

            return {
                str(status): int(count)
                for status, count in result.all()
            }

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to calculate asset lifecycle statistics."
            ) from exc

    async def count_by_operational_status(
        self,
    ) -> dict[str, int]:
        """
        Return asset counts grouped by operational status.
        """

        statement = (
            select(
                Asset.operational_status,
                func.count(Asset.asset_id),
            )
            .group_by(Asset.operational_status)
            .order_by(Asset.operational_status)
        )

        try:
            result = await self.session.execute(statement)

            return {
                str(status): int(count)
                for status, count in result.all()
            }

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to calculate asset operational statistics."
            ) from exc

    async def count_by_risk(
        self,
    ) -> dict[str, int]:
        """
        Return asset counts grouped by risk.
        """

        statement = (
            select(
                Asset.risk,
                func.count(Asset.asset_id),
            )
            .group_by(Asset.risk)
            .order_by(Asset.risk)
        )

        try:
            result = await self.session.execute(statement)

            return {
                str(risk): int(count)
                for risk, count in result.all()
            }

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to calculate asset risk statistics."
            ) from exc

    async def count_by_type(
        self,
    ) -> dict[str, int]:
        """
        Return asset counts grouped by asset type.
        """

        statement = (
            select(
                Asset.asset_type,
                func.count(Asset.asset_id),
            )
            .group_by(Asset.asset_type)
            .order_by(Asset.asset_type)
        )

        try:
            result = await self.session.execute(statement)

            return {
                str(asset_type): int(count)
                for asset_type, count in result.all()
            }

        except SQLAlchemyError as exc:
            raise AssetRepositoryError(
                "Unable to calculate asset type statistics."
            ) from exc


# ============================================================================
# Public exports
# ============================================================================


__all__ = [
    "AssetAlreadyExistsError",
    "AssetNotFoundError",
    "AssetRepository",
    "AssetRepositoryError",
]