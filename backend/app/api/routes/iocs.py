from __future__ import annotations

from datetime import datetime
from math import ceil
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from app.api.dependencies import (
    get_threat_intelligence,
    require_permission,
)
from app.api.schemas.iocs import (
    IOCCreateRequest,
    IOCDetailResponse,
    IOCFilterOptionsResponse,
    IOCListResponse,
    IOCMatchResponse,
    IOCRelationshipQuery,
    IOCRelationshipResponse,
    IOCResponse,
    IOCSummaryResponse,
    IOCUpdateRequest,
    ioc_reputation_values,
    ioc_severity_values,
    ioc_status_values,
    ioc_type_values,
)
from app.threat_intelligence.models import (
    IOCCreate,
    IOCRelationships,
    IOCSeverity,
    IOCStatus,
    IOCType,
    Reputation,
)
from app.threat_intelligence.service import (
    ThreatIntelligenceService,
)


# =============================================================================
# Router
# =============================================================================

router = APIRouter(
    prefix="/iocs",
    tags=["threat-intelligence"],
)


# =============================================================================
# Permission Dependencies
# =============================================================================

iocs_read_permission = require_permission(
    "iocs:read",
)

iocs_manage_permission = require_permission(
    "iocs:manage",
)


# =============================================================================
# Constants
# =============================================================================

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 30
MAX_PAGE_SIZE = 200

MAX_QUERY_LENGTH = 200
MAX_SOURCE_LENGTH = 255
MAX_FEED_LENGTH = 255
MAX_OBSERVABLE_LENGTH = 2048
MAX_DESCRIPTION_LENGTH = 5000
MAX_TAG_LENGTH = 100
MAX_TAGS = 50


# =============================================================================
# Enum Parsers
# =============================================================================


def _parse_ioc_type(
    value: str | None,
) -> IOCType | None:
    """
    Parse and validate IOC type.

    Backend domain enum remains authoritative.
    """

    if value is None:
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    try:
        return IOCType(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Unsupported IOC type: {value}. "
                f"Supported values: {ioc_type_values()}"
            ),
        ) from exc


def _parse_severity(
    value: str | None,
) -> IOCSeverity | None:
    """
    Parse and validate IOC severity.

    Backend domain enum remains authoritative.
    """

    if value is None:
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    try:
        return IOCSeverity(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Invalid IOC severity: {value}. "
                f"Supported values: {ioc_severity_values()}"
            ),
        ) from exc


def _parse_status(
    value: str | None,
) -> IOCStatus | None:
    """
    Parse and validate IOC lifecycle status.

    This parser is used only for inventory filtering.

    Lifecycle mutation is intentionally handled through the
    dedicated activate/revoke endpoints.
    """

    if value is None:
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    try:
        return IOCStatus(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Invalid IOC status: {value}. "
                f"Supported values: {ioc_status_values()}"
            ),
        ) from exc


def _parse_reputation(
    value: str | None,
) -> Reputation | None:
    """
    Parse and validate IOC reputation.

    Backend domain enum remains authoritative.
    """

    if value is None:
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    try:
        return Reputation(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Invalid IOC reputation: {value}. "
                f"Supported values: {ioc_reputation_values()}"
            ),
        ) from exc


# =============================================================================
# Relationship Helpers
# =============================================================================


def _build_relationships(
    relationships: IOCRelationshipResponse | None,
) -> IOCRelationships:
    """
    Convert API relationship representation into the domain model.

    IOC identity itself is not part of the relationship payload.
    """

    if relationships is None:
        return IOCRelationships()

    return IOCRelationships(
        event_ids=tuple(
            relationships.event_ids,
        ),
        alert_ids=tuple(
            relationships.alert_ids,
        ),
        incident_ids=tuple(
            relationships.incident_ids,
        ),
        asset_ids=tuple(
            relationships.asset_ids,
        ),
        mitre_technique_ids=tuple(
            relationships.mitre_technique_ids,
        ),
    )


# =============================================================================
# Tag Helpers
# =============================================================================


def _normalise_tags(
    tags: list[str] | tuple[str, ...] | None,
) -> tuple[str, ...]:
    """
    Normalize IOC tags.

    Rules:

        - trim whitespace
        - discard empty tags
        - preserve insertion order
        - remove duplicates case-insensitively
        - enforce maximum tag length
        - enforce maximum tag count
    """

    if not tags:
        return ()

    result: list[str] = []
    seen: set[str] = set()

    for raw_tag in tags:
        tag = str(raw_tag).strip()

        if not tag:
            continue

        if len(tag) > MAX_TAG_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "IOC tag exceeds maximum length "
                    f"of {MAX_TAG_LENGTH} characters."
                ),
            )

        key = tag.lower()

        if key in seen:
            continue

        seen.add(key)
        result.append(tag)

        if len(result) >= MAX_TAGS:
            break

    return tuple(result)


# =============================================================================
# Description Validation
# =============================================================================


def _normalise_description(
    description: str | None,
) -> str | None:
    """
    Normalize and validate IOC description.
    """

    if description is None:
        return None

    value = description.strip()

    if len(value) > MAX_DESCRIPTION_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "IOC description exceeds maximum "
                f"length of {MAX_DESCRIPTION_LENGTH} characters."
            ),
        )

    return value or None


# =============================================================================
# Create Model Builder
# =============================================================================


def _build_create_model(
    payload: IOCCreateRequest,
) -> IOCCreate:
    """
    Convert API Add IOC request into the domain IOCCreate model.

    New IOC lifecycle state is always ACTIVE.

    Clients cannot create an IOC directly as REVOKED or EXPIRED.
    """

    domain_type = _parse_ioc_type(
        payload.type,
    )

    if domain_type is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="IOC type is required.",
        )

    severity = _parse_severity(
        payload.severity,
    )

    if severity is None:
        severity = IOCSeverity.MEDIUM

    reputation = _parse_reputation(
        payload.reputation,
    )

    if reputation is None:
        reputation = Reputation.UNKNOWN

    description = _normalise_description(
        payload.description,
    )

    tags = _normalise_tags(
        payload.tags,
    )

    confidence = payload.confidence / 100.0

    return IOCCreate(
        ioc_type=domain_type,
        value=payload.value.strip(),
        confidence=confidence,
        severity=severity,
        reputation=reputation,
        status=IOCStatus.ACTIVE,
        source=payload.source.strip(),
        feed=(
            payload.feed.strip()
            if payload.feed is not None
            else None
        ),
        description=description,
        tags=tags,
        expiration=payload.expiration,
        metadata=dict(payload.metadata),
        relationships=_build_relationships(
            None,
        ),
    )


# =============================================================================
# Detail Builder
# =============================================================================


async def _build_detail(
    service: ThreatIntelligenceService,
    ioc,
) -> IOCDetailResponse:
    """
    Build complete IOC detail response.

    Relationship data is loaded separately from the Threat Intelligence
    service and validated against IOCRelationshipResponse.

    The relationship object does not contain ioc_id.
    """

    detail = IOCDetailResponse.from_model(
        ioc,
    )

    relationships = await service.get_relationships(
        ioc.ioc_id,
    )

    normalized_relationships = (
        IOCRelationshipResponse.model_validate(
            relationships,
        )
    )

    return detail.model_copy(
        update={
            "relationships": normalized_relationships,
        },
    )


# =============================================================================
# IOC Inventory
# =============================================================================


@router.get(
    "",
    response_model=IOCListResponse,
    summary="List and search threat indicators",
    dependencies=[
        Depends(
            iocs_read_permission,
        ),
    ],
)
async def list_iocs(
    query: str | None = Query(
        default=None,
        max_length=MAX_QUERY_LENGTH,
        description=(
            "Search IOC value, normalized value, source, "
            "feed, description, tags, or IOC identifier."
        ),
    ),
    ioc_type: str | None = Query(
        default=None,
        alias="type",
        description="Filter by IOC type.",
    ),
    severity: str | None = Query(
        default=None,
        description="Filter by IOC severity.",
    ),
    ioc_status: str | None = Query(
        default=None,
        alias="status",
        description="Filter by IOC lifecycle status.",
    ),
    source: str | None = Query(
        default=None,
        max_length=MAX_SOURCE_LENGTH,
        description="Filter by IOC source.",
    ),
    reputation: str | None = Query(
        default=None,
        description="Filter by IOC reputation.",
    ),
    feed: str | None = Query(
        default=None,
        max_length=MAX_FEED_LENGTH,
        description="Filter by threat intelligence feed.",
    ),
    active: bool | None = Query(
        default=None,
        description="Filter by active lifecycle state.",
    ),
    start_time: datetime | None = Query(
        default=None,
        description="Filter IOCs last seen after this timestamp.",
    ),
    end_time: datetime | None = Query(
        default=None,
        description="Filter IOCs last seen before this timestamp.",
    ),
    page: int = Query(
        default=DEFAULT_PAGE,
        ge=1,
    ),
    page_size: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
    ),
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCListResponse:
    """
    List, search and filter IOC inventory.

    Filtering, total count and pagination are backend authoritative.

    Response contract:

        {
            "items": [...],
            "total": 252,
            "page": 1,
            "page_size": 30,
            "total_pages": 9
        }

    Frontend must not calculate total_pages.
    """

    parsed_type = _parse_ioc_type(
        ioc_type,
    )

    parsed_severity = _parse_severity(
        severity,
    )

    parsed_status = _parse_status(
        ioc_status,
    )

    parsed_reputation = _parse_reputation(
        reputation,
    )

    records, total = await service.list_iocs(
        query=query,
        ioc_type=(
            parsed_type.value
            if parsed_type is not None
            else None
        ),
        severity=(
            parsed_severity.value
            if parsed_severity is not None
            else None
        ),
        status=(
            parsed_status.value
            if parsed_status is not None
            else None
        ),
        source=(
            source.strip()
            if source
            else None
        ),
        reputation=(
            parsed_reputation.value
            if parsed_reputation is not None
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

    items = [
        IOCResponse.from_model(
            item,
        )
        for item in records
    ]

    total_pages = (
        ceil(total / page_size)
        if total > 0
        else 0
    )

    return IOCListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# =============================================================================
# IOC Summary / KPI
# =============================================================================


@router.get(
    "/summary",
    response_model=IOCSummaryResponse,
    summary="Get threat intelligence dashboard summary",
    dependencies=[
        Depends(
            iocs_read_permission,
        ),
    ],
)
async def get_ioc_summary(
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCSummaryResponse:
    """
    Return backend-authoritative Threat Intelligence dashboard statistics.

    Canonical UI KPI:

        Total IOCs
        Active IOCs
        High Risk
        Expired
    """

    summary = await service.summary()

    normalized = dict(
        summary,
    )

    # Existing repository implementations may expose total_iocs.
    # Public API contract uses total.
    if "total" not in normalized:
        normalized["total"] = normalized.get(
            "total_iocs",
            0,
        )

    return IOCSummaryResponse.model_validate(
        normalized,
    )


# =============================================================================
# IOC Filter Options
# =============================================================================


@router.get(
    "/filter-options",
    response_model=IOCFilterOptionsResponse,
    summary="Get IOC filter options",
    dependencies=[
        Depends(
            iocs_read_permission,
        ),
    ],
)
async def get_ioc_filter_options(
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCFilterOptionsResponse:
    """
    Return backend-authoritative IOC filter catalogues.

    Type, severity, status and reputation come from canonical
    Threat Intelligence domain enums.

    Source values are derived from persisted IOC intelligence.
    """

    # -------------------------------------------------------------------------
    # Canonical catalogues
    # -------------------------------------------------------------------------

    types = ioc_type_values()
    severities = ioc_severity_values()
    statuses = ioc_status_values()
    reputations = ioc_reputation_values()

    # -------------------------------------------------------------------------
    # Source catalogue
    #
    # Source is data-derived because it represents actual persisted
    # intelligence sources.
    # -------------------------------------------------------------------------

    source_values: set[str] = set()

    page = 1

    while True:
        records, total = await service.list_iocs(
            page=page,
            page_size=MAX_PAGE_SIZE,
        )

        for ioc in records:
            source_value = getattr(
                ioc,
                "source",
                None,
            )

            if source_value is None:
                continue

            value = str(
                source_value,
            ).strip()

            if value:
                source_values.add(value)

        if not records:
            break

        if (
            page * MAX_PAGE_SIZE
            >= total
        ):
            break

        page += 1

    sources = sorted(
        source_values,
        key=str.casefold,
    )

    return IOCFilterOptionsResponse(
        types=types,
        severities=severities,
        statuses=statuses,
        sources=sources,
        reputations=reputations,
    )


# =============================================================================
# IOC Match / Enrichment
# =============================================================================


@router.get(
    "/match",
    response_model=list[IOCMatchResponse],
    summary="Match observable against threat intelligence",
    dependencies=[
        Depends(
            iocs_read_permission,
        ),
    ],
)
async def match_ioc(
    observable: str = Query(
        ...,
        min_length=1,
        max_length=MAX_OBSERVABLE_LENGTH,
        description=(
            "IP, domain, URL, hash, email, hostname, "
            "or another supported observable."
        ),
    ),
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> list[IOCMatchResponse]:
    """
    Match an observable against active IOC intelligence.
    """

    normalized_observable = observable.strip()

    if not normalized_observable:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Observable is required.",
        )

    matches = await service.match(
        normalized_observable,
    )

    return [
        IOCMatchResponse.from_model(
            match,
        )
        for match in matches
    ]


# =============================================================================
# IOC Relationships
# =============================================================================


@router.get(
    "/{ioc_id}/relationships",
    response_model=IOCRelationshipResponse,
    summary="Get IOC cross-module relationships",
    dependencies=[
        Depends(
            iocs_read_permission,
        ),
    ],
)
async def get_ioc_relationships(
    ioc_id: UUID,
    relationship_query: IOCRelationshipQuery = Depends(),
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCRelationshipResponse:
    """
    Return lightweight relationships to:

        Events
        Alerts
        Incidents
        Assets
        MITRE techniques
    """

    try:
        relationships = await service.get_relationships(
            ioc_id,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found.",
        ) from exc

    # -------------------------------------------------------------------------
    # Inclusion controls
    # -------------------------------------------------------------------------

    if not relationship_query.include_events:
        relationships["event_ids"] = []
        relationships["event_count"] = 0

    if not relationship_query.include_alerts:
        relationships["alert_ids"] = []
        relationships["alert_count"] = 0

    if not relationship_query.include_incidents:
        relationships["incident_ids"] = []
        relationships["incident_count"] = 0

    if not relationship_query.include_assets:
        relationships["asset_ids"] = []
        relationships["asset_count"] = 0

    if not relationship_query.include_mitre:
        relationships["mitre_technique_ids"] = []
        relationships["mitre_technique_count"] = 0

    # -------------------------------------------------------------------------
    # Global relationship result limit
    # -------------------------------------------------------------------------

    limit = relationship_query.limit

    for field in (
        "event_ids",
        "alert_ids",
        "incident_ids",
        "asset_ids",
        "mitre_technique_ids",
    ):
        values = relationships.get(
            field,
            [],
        )

        relationships[field] = values[:limit]

        count_field = field.replace(
            "_ids",
            "_count",
        )

        relationships[count_field] = len(
            relationships[field],
        )

    return IOCRelationshipResponse.model_validate(
        relationships,
    )


# =============================================================================
# IOC Details
# =============================================================================


@router.get(
    "/{ioc_id}",
    response_model=IOCDetailResponse,
    summary="Get IOC details",
    dependencies=[
        Depends(
            iocs_read_permission,
        ),
    ],
)
async def get_ioc(
    ioc_id: UUID,
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCDetailResponse:
    """
    Return full IOC details for the View IOC drawer.
    """

    try:
        ioc = await service.get_ioc(
            ioc_id,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found.",
        ) from exc

    return await _build_detail(
        service,
        ioc,
    )


# =============================================================================
# Create IOC
# =============================================================================


@router.post(
    "",
    response_model=IOCResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create threat indicator",
    dependencies=[
        Depends(
            iocs_manage_permission,
        ),
    ],
)
async def create_ioc(
    payload: IOCCreateRequest,
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCResponse:
    """
    Create or merge an IOC.

    New IOCs always start as ACTIVE.
    """

    data = _build_create_model(
        payload,
    )

    try:
        ioc = await service.add_ioc(
            data,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return IOCResponse.from_model(
        ioc,
    )


# =============================================================================
# Update IOC
# =============================================================================


@router.patch(
    "/{ioc_id}",
    response_model=IOCDetailResponse,
    summary="Edit threat indicator",
    dependencies=[
        Depends(
            iocs_manage_permission,
        ),
    ],
)
async def update_ioc(
    ioc_id: UUID,
    payload: IOCUpdateRequest,
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCDetailResponse:
    """
    Edit IOC intelligence.

    Editable intelligence fields are handled here.

    Lifecycle Enable/Disable operations are intentionally separated
    into the dedicated activate/revoke endpoints.
    """

    severity = _parse_severity(
        payload.severity,
    )

    reputation = _parse_reputation(
        payload.reputation,
    )

    relationships = None

    if payload.relationships is not None:
        relationships = _build_relationships(
            payload.relationships,
        )

    description = _normalise_description(
        payload.description,
    )

    tags = None

    if payload.tags is not None:
        tags = _normalise_tags(
            payload.tags,
        )

    try:
        ioc = await service.update_ioc(
            ioc_id,
            value=(
                payload.value.strip()
                if payload.value is not None
                else None
            ),
            confidence=(
                payload.confidence / 100.0
                if payload.confidence is not None
                else None
            ),
            severity=severity,
            source=(
                payload.source.strip()
                if payload.source is not None
                else None
            ),
            expiration=payload.expiration,
            reputation=reputation,
            feed=(
                payload.feed.strip()
                if payload.feed is not None
                else None
            ),
            description=description,
            tags=tags,
            metadata=(
                dict(payload.metadata)
                if payload.metadata is not None
                else None
            ),
            relationships=relationships,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found.",
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return await _build_detail(
        service,
        ioc,
    )


# =============================================================================
# Disable / Revoke IOC
# =============================================================================


@router.post(
    "/{ioc_id}/revoke",
    response_model=IOCResponse,
    summary="Disable threat indicator",
    dependencies=[
        Depends(
            iocs_manage_permission,
        ),
    ],
)
async def revoke_ioc(
    ioc_id: UUID,
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCResponse:
    """
    Disable an IOC by moving it to REVOKED state.

    This is the supported replacement for permanent deletion.
    """

    try:
        ioc = await service.revoke_ioc(
            ioc_id,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found.",
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return IOCResponse.from_model(
        ioc,
    )


# =============================================================================
# Enable / Activate IOC
# =============================================================================


@router.post(
    "/{ioc_id}/activate",
    response_model=IOCResponse,
    summary="Enable threat indicator",
    dependencies=[
        Depends(
            iocs_manage_permission,
        ),
    ],
)
async def activate_ioc(
    ioc_id: UUID,
    service: ThreatIntelligenceService = Depends(
        get_threat_intelligence,
    ),
) -> IOCResponse:
    """
    Enable an IOC by moving it to ACTIVE state.

    Expired IOCs cannot be activated until their expiration
    is updated.
    """

    try:
        ioc = await service.activate_ioc(
            ioc_id,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found.",
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return IOCResponse.from_model(
        ioc,
    )


# =============================================================================
# Public Exports
# =============================================================================

__all__ = [
    "router",
]