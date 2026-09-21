from __future__ import annotations

from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from app.api.schemas.assets import (
    AssetCreate,
    AssetListResponse,
    AssetResponse,
    AssetStatisticsResponse,
    AssetStatusUpdate,
    AssetUpdate,
)
from app.assets.service import (
    AssetAlreadyExistsServiceError,
    AssetNotFoundServiceError,
    AssetService,
    AssetServiceError,
    AssetValidationError,
)
from app.dependencies import get_asset_service


# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/assets",
    tags=["Assets"],
)


# ============================================================================
# Constants
# ============================================================================

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 30
MAX_PAGE_SIZE = 30


# ============================================================================
# Exception Helpers
# ============================================================================


def _asset_not_found(
    asset_id: UUID,
) -> HTTPException:
    """
    Build the standardized 404 response for a missing asset.
    """

    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Asset '{asset_id}' not found.",
    )


def _service_error(
    exc: AssetServiceError,
) -> HTTPException:
    """
    Convert a generic asset-service failure into HTTP 500.
    """

    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=str(exc),
    )


def _validation_error(
    exc: AssetValidationError,
) -> HTTPException:
    """
    Convert an asset validation failure into HTTP 422.
    """

    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=str(exc),
    )


def _conflict_error(
    exc: AssetAlreadyExistsServiceError,
) -> HTTPException:
    """
    Convert a duplicate/conflict service error into HTTP 409.
    """

    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=str(exc),
    )


# ============================================================================
# Create Asset
# ============================================================================


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create asset",
)
async def create_asset(
    payload: AssetCreate,
    service: AssetService = Depends(get_asset_service),
) -> AssetResponse:
    """
    Create a new SentinelSIEM asset.

    Lifecycle status:
        ENABLED

    Operational status:
        UNKNOWN

    Both are initialized by the service.
    """

    try:
        asset = await service.create_asset(
            name=payload.name,
            asset_type=payload.asset_type,
            hostname=payload.hostname,
            ip_address=(
                str(payload.ip_address)
                if payload.ip_address is not None
                else None
            ),
            mac_address=payload.mac_address,
            operating_system=payload.operating_system,
            environment=payload.environment,
            risk=payload.risk,
            owner=payload.owner,
            location=payload.location,
            tags=payload.tags,
            description=payload.description,
            metadata=payload.metadata,
        )

    except AssetAlreadyExistsServiceError as exc:
        raise _conflict_error(exc) from exc

    except AssetValidationError as exc:
        raise _validation_error(exc) from exc

    except AssetServiceError as exc:
        raise _service_error(exc) from exc

    return AssetResponse.model_validate(asset)


# ============================================================================
# List Assets
# ============================================================================


@router.get(
    "",
    response_model=AssetListResponse,
    status_code=status.HTTP_200_OK,
    summary="List assets",
)
async def list_assets(
    search: str | None = Query(
        default=None,
        max_length=255,
        description=(
            "Search by asset name, hostname, "
            "IP address, or MAC address."
        ),
    ),
    asset_type: str | None = Query(
        default=None,
        max_length=100,
        description="Filter by asset type.",
    ),
    asset_status: str | None = Query(
        default=None,
        alias="status",
        max_length=50,
        description=(
            "Filter by lifecycle or operational status."
        ),
    ),
    risk: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by risk level.",
    ),
    operating_system: str | None = Query(
        default=None,
        alias="os",
        max_length=100,
        description="Filter by operating system.",
    ),
    environment: str | None = Query(
        default=None,
        max_length=100,
        description="Filter by environment.",
    ),
    page: int = Query(
        default=DEFAULT_PAGE,
        ge=1,
        description="Page number.",
    ),
    page_size: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Number of assets per page.",
    ),
    service: AssetService = Depends(get_asset_service),
) -> AssetListResponse:
    """
    Return a paginated list of assets.

    Locked search fields:
        - Asset Name
        - Hostname
        - IP Address
        - MAC Address

    Locked filters:
        - Asset Type
        - Status
        - Risk
        - Operating System
        - Environment

    Pagination:
        - Default page size: 30
        - Maximum page size: 30
    """

    try:
        result = await service.list_assets(
            search=search,
            asset_type=asset_type,
            status=asset_status,
            risk=risk,
            operating_system=operating_system,
            environment=environment,
            page=page,
            page_size=page_size,
        )

    except AssetValidationError as exc:
        raise _validation_error(exc) from exc

    except AssetServiceError as exc:
        raise _service_error(exc) from exc

    return AssetListResponse(
        items=result.assets,
        total=result.total,
        page=result.page,
        page_size=result.page_size,
        total_pages=result.total_pages,
    )


# ============================================================================
# Asset Statistics
# ============================================================================


@router.get(
    "/statistics",
    response_model=AssetStatisticsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset statistics",
)
async def get_asset_statistics(
    service: AssetService = Depends(get_asset_service),
) -> AssetStatisticsResponse:
    """
    Return aggregate Asset Inventory statistics.

    Summary cards:
        - Total Assets
        - Enabled
        - Disabled
        - Critical Risk
    """

    try:
        result = await service.get_statistics()

    except AssetValidationError as exc:
        raise _validation_error(exc) from exc

    except AssetServiceError as exc:
        raise _service_error(exc) from exc

    return AssetStatisticsResponse(
        total=result.total,
        enabled=result.enabled,
        disabled=result.disabled,
        critical=result.critical,
        by_type=result.by_type,
        by_risk=result.by_risk,
        by_lifecycle_status=result.by_lifecycle_status,
        by_operational_status=result.by_operational_status,
    )


# ============================================================================
# Get Single Asset
# ============================================================================


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset",
)
async def get_asset(
    asset_id: UUID,
    service: AssetService = Depends(get_asset_service),
) -> AssetResponse:
    """
    Return a single asset by UUID.
    """

    try:
        asset = await service.get_asset(
            asset_id=asset_id,
        )

    except AssetNotFoundServiceError as exc:
        raise _asset_not_found(asset_id) from exc

    except AssetValidationError as exc:
        raise _validation_error(exc) from exc

    except AssetServiceError as exc:
        raise _service_error(exc) from exc

    return AssetResponse.model_validate(asset)


# ============================================================================
# Update Asset
# ============================================================================


@router.patch(
    "/{asset_id}",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Update asset",
)
async def update_asset(
    asset_id: UUID,
    payload: AssetUpdate,
    service: AssetService = Depends(get_asset_service),
) -> AssetResponse:
    """
    Update asset information.

    Lifecycle status is intentionally excluded.

    Enable/Disable must use:
        PATCH /assets/{asset_id}/status
    """

    changes = payload.model_dump(
        exclude_unset=True,
    )

    if not changes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one field must be provided.",
        )

    # ------------------------------------------------------------------------
    # Convert Pydantic IP object into a string for the service layer.
    # ------------------------------------------------------------------------

    if "ip_address" in changes:
        changes["ip_address"] = (
            str(changes["ip_address"])
            if changes["ip_address"] is not None
            else None
        )

    try:
        asset = await service.update_asset(
            asset_id=asset_id,
            **changes,
        )

    except AssetNotFoundServiceError as exc:
        raise _asset_not_found(asset_id) from exc

    except AssetAlreadyExistsServiceError as exc:
        raise _conflict_error(exc) from exc

    except AssetValidationError as exc:
        raise _validation_error(exc) from exc

    except AssetServiceError as exc:
        raise _service_error(exc) from exc

    return AssetResponse.model_validate(asset)


# ============================================================================
# Enable / Disable Asset
# ============================================================================


@router.patch(
    "/{asset_id}/status",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Enable or disable asset",
)
async def update_asset_status(
    asset_id: UUID,
    payload: AssetStatusUpdate,
    service: AssetService = Depends(get_asset_service),
) -> AssetResponse:
    """
    Enable or disable an asset.

    Allowed lifecycle statuses:
        ENABLED
        DISABLED

    Important:
        Lifecycle status and operational status are separate.

    This endpoint changes only lifecycle_status.
    """

    try:
        asset = await service.update_lifecycle_status(
            asset_id=asset_id,
            lifecycle_status=payload.lifecycle_status,
        )

    except AssetNotFoundServiceError as exc:
        raise _asset_not_found(asset_id) from exc

    except AssetValidationError as exc:
        raise _validation_error(exc) from exc

    except AssetServiceError as exc:
        raise _service_error(exc) from exc

    return AssetResponse.model_validate(asset)


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "router",
    "create_asset",
    "list_assets",
    "get_asset_statistics",
    "get_asset",
    "update_asset",
    "update_asset_status",
]