from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.threat_intelligence.models import (
    IOCSeverity,
    IOCStatus,
    IOCType,
    Reputation,
)


# ============================================================================
# Shared Constants
# ============================================================================

IOC_MIN_CONFIDENCE = 0
IOC_MAX_CONFIDENCE = 100

IOC_DEFAULT_PAGE = 1
IOC_DEFAULT_PAGE_SIZE = 30
IOC_MAX_PAGE_SIZE = 200

IOC_DEFAULT_SEVERITY = IOCSeverity.MEDIUM.value
IOC_DEFAULT_STATUS = IOCStatus.ACTIVE.value
IOC_DEFAULT_REPUTATION = Reputation.UNKNOWN.value


# ============================================================================
# Canonical Catalogue Helpers
# ============================================================================


def ioc_type_values() -> list[str]:
    """
    Return the complete backend-authoritative IOC type catalogue.
    """

    return [
        item.value
        for item in IOCType
    ]


def ioc_severity_values() -> list[str]:
    """
    Return the complete backend-authoritative IOC severity catalogue.
    """

    return [
        item.value
        for item in IOCSeverity
    ]


def ioc_status_values() -> list[str]:
    """
    Return the complete backend-authoritative IOC status catalogue.
    """

    return [
        item.value
        for item in IOCStatus
    ]


def ioc_reputation_values() -> list[str]:
    """
    Return the complete backend-authoritative IOC reputation catalogue.
    """

    return [
        item.value
        for item in Reputation
    ]


# ============================================================================
# Shared / Common Response
# ============================================================================


class IOCBaseResponse(BaseModel):
    """
    Canonical public representation of an IOC.

    Used by inventory/list and detail responses.

    Backend/domain values remain authoritative. The API layer only converts
    confidence from the domain 0..1 representation into the public 0..100
    representation.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    id: UUID

    # ------------------------------------------------------------------------
    # Indicator
    # ------------------------------------------------------------------------

    indicator: str

    type: str

    value: str

    # ------------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------------

    confidence: int | None = Field(
        default=None,
        ge=IOC_MIN_CONFIDENCE,
        le=IOC_MAX_CONFIDENCE,
    )

    severity: str | None = None

    status: str | None = None

    reputation: str | None = None

    # ------------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------------

    source: str | None = None

    feed: str | None = None

    # ------------------------------------------------------------------------
    # Analyst Context
    # ------------------------------------------------------------------------

    description: str | None = None

    tags: list[str] = Field(
        default_factory=list,
    )

    # ------------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------------

    active: bool = True

    first_seen: datetime | None = None

    last_seen: datetime | None = None

    expiration: datetime | None = None

    created_at: datetime | None = None

    updated_at: datetime | None = None

    # ------------------------------------------------------------------------
    # Additional Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )


# ============================================================================
# IOC Response
# ============================================================================


class IOCResponse(IOCBaseResponse):
    """
    Public IOC representation used by inventory/table views.
    """

    pass


# ============================================================================
# IOC Relationship Response
# ============================================================================


class IOCRelationshipResponse(BaseModel):
    """
    Lightweight cross-module IOC relationships.

    Related resource details remain owned by their respective modules.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )

    event_ids: list[str] = Field(
        default_factory=list,
    )

    alert_ids: list[UUID] = Field(
        default_factory=list,
    )

    incident_ids: list[UUID] = Field(
        default_factory=list,
    )

    asset_ids: list[str] = Field(
        default_factory=list,
    )

    mitre_technique_ids: list[str] = Field(
        default_factory=list,
    )

    event_count: int = Field(
        default=0,
        ge=0,
    )

    alert_count: int = Field(
        default=0,
        ge=0,
    )

    incident_count: int = Field(
        default=0,
        ge=0,
    )

    asset_count: int = Field(
        default=0,
        ge=0,
    )

    mitre_technique_count: int = Field(
        default=0,
        ge=0,
    )


# ============================================================================
# IOC Detail Response
# ============================================================================


class IOCDetailResponse(IOCResponse):
    """
    Full IOC representation used by View IOC drawer.
    """

    relationships: IOCRelationshipResponse = Field(
        default_factory=IOCRelationshipResponse,
    )


# ============================================================================
# Pagination
# ============================================================================


class IOCPagination(BaseModel):
    """
    Backend-authoritative IOC pagination metadata.

    Frontend must use total_pages directly and must not calculate it.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    page: int = Field(
        default=IOC_DEFAULT_PAGE,
        ge=1,
    )

    page_size: int = Field(
        default=IOC_DEFAULT_PAGE_SIZE,
        ge=1,
        le=IOC_MAX_PAGE_SIZE,
    )

    total: int = Field(
        default=0,
        ge=0,
    )

    total_pages: int = Field(
        default=0,
        ge=0,
    )


# ============================================================================
# IOC List Response
# ============================================================================


class IOCListResponse(BaseModel):
    """
    Canonical paginated IOC inventory response.

    Example:

        {
            "items": [...],
            "total": 252,
            "page": 1,
            "page_size": 30,
            "total_pages": 9
        }

    Pagination is backend authoritative.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )

    items: list[IOCResponse] = Field(
        default_factory=list,
    )

    total: int = Field(
        default=0,
        ge=0,
    )

    page: int = Field(
        default=IOC_DEFAULT_PAGE,
        ge=1,
    )

    page_size: int = Field(
        default=IOC_DEFAULT_PAGE_SIZE,
        ge=1,
        le=IOC_MAX_PAGE_SIZE,
    )

    total_pages: int = Field(
        default=0,
        ge=0,
    )


# ============================================================================
# IOC Summary / KPI Response
# ============================================================================


class IOCSummaryResponse(BaseModel):
    """
    Threat Intelligence dashboard KPI response.

    Canonical UI KPI:

        Total IOCs
        Active IOCs
        High Risk
        Expired

    Additional backend analytics remain available for existing consumers.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )

    # ------------------------------------------------------------------------
    # Canonical dashboard KPI
    # ------------------------------------------------------------------------

    total: int = Field(
        default=0,
        ge=0,
    )

    active: int = Field(
        default=0,
        ge=0,
    )

    high_risk: int = Field(
        default=0,
        ge=0,
    )

    expired: int = Field(
        default=0,
        ge=0,
    )

    # ------------------------------------------------------------------------
    # Additional analytics
    # ------------------------------------------------------------------------

    malicious: int = Field(
        default=0,
        ge=0,
    )

    recently_updated: int = Field(
        default=0,
        ge=0,
    )

    revoked: int = Field(
        default=0,
        ge=0,
    )

    by_type: dict[str, int] = Field(
        default_factory=dict,
    )

    by_source: dict[str, int] = Field(
        default_factory=dict,
    )

    by_severity: dict[str, int] = Field(
        default_factory=dict,
    )

    by_status: dict[str, int] = Field(
        default_factory=dict,
    )

    by_reputation: dict[str, int] = Field(
        default_factory=dict,
    )


# ============================================================================
# IOC Filter Options
# ============================================================================


class IOCFilterOptionsResponse(BaseModel):
    """
    Backend-authoritative filter catalogue.

    The frontend must not hardcode these values.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )

    types: list[str] = Field(
        default_factory=list,
    )

    severities: list[str] = Field(
        default_factory=list,
    )

    statuses: list[str] = Field(
        default_factory=list,
    )

    sources: list[str] = Field(
        default_factory=list,
    )

    reputations: list[str] = Field(
        default_factory=list,
    )


# ============================================================================
# IOC Create Request
# ============================================================================


class IOCCreateRequest(BaseModel):
    """
    API request for Add IOC.

    Required:

        value
        type
        source

    Optional:

        confidence
        severity
        reputation
        feed
        description
        tags
        expiration
        metadata

    IOC status is intentionally NOT client-controlled during creation.

    The backend creates new IOCs as ACTIVE.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    # ------------------------------------------------------------------------
    # Indicator
    # ------------------------------------------------------------------------

    value: str = Field(
        min_length=1,
        max_length=4096,
    )

    type: str = Field(
        min_length=1,
        max_length=64,
    )

    # ------------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------------

    confidence: int = Field(
        default=50,
        ge=IOC_MIN_CONFIDENCE,
        le=IOC_MAX_CONFIDENCE,
    )

    severity: str = Field(
        default=IOC_DEFAULT_SEVERITY,
        min_length=1,
        max_length=32,
    )

    reputation: str = Field(
        default=IOC_DEFAULT_REPUTATION,
        min_length=1,
        max_length=32,
    )

    # ------------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------------

    source: str = Field(
        min_length=1,
        max_length=255,
    )

    feed: str | None = Field(
        default=None,
        max_length=255,
    )

    # ------------------------------------------------------------------------
    # Analyst Context
    # ------------------------------------------------------------------------

    description: str | None = Field(
        default=None,
        max_length=8192,
    )

    tags: list[str] = Field(
        default_factory=list,
    )

    # ------------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------------

    expiration: datetime | None = None

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )


# ============================================================================
# IOC Update Request
# ============================================================================


class IOCUpdateRequest(BaseModel):
    """
    API request for Edit IOC.

    All fields are optional to preserve PATCH semantics.

    Status changes are supported for lifecycle operations, although the
    preferred application-level Enable / Disable actions should use the
    dedicated revoke/activate service workflow.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    # ------------------------------------------------------------------------
    # Indicator
    # ------------------------------------------------------------------------

    value: str | None = Field(
        default=None,
        min_length=1,
        max_length=4096,
    )

    # ------------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------------

    confidence: int | None = Field(
        default=None,
        ge=IOC_MIN_CONFIDENCE,
        le=IOC_MAX_CONFIDENCE,
    )

    severity: str | None = Field(
        default=None,
        min_length=1,
        max_length=32,
    )

    reputation: str | None = Field(
        default=None,
        min_length=1,
        max_length=32,
    )

    # ------------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------------

    source: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )

    feed: str | None = Field(
        default=None,
        max_length=255,
    )

    # ------------------------------------------------------------------------
    # Analyst Context
    # ------------------------------------------------------------------------

    description: str | None = Field(
        default=None,
        max_length=8192,
    )

    tags: list[str] | None = None

    # ------------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------------

    expiration: datetime | None = None

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] | None = None

    # ------------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------------

    relationships: IOCRelationshipResponse | None = None


# ============================================================================
# IOC Lifecycle Requests
# ============================================================================


class IOCStatusChangeRequest(BaseModel):
    """
    Explicit IOC lifecycle transition request.

    Used by application endpoints that expose Enable / Disable behavior.

    The backend remains responsible for validating whether the requested
    transition is allowed.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    status: str = Field(
        min_length=1,
        max_length=32,
    )


# ============================================================================
# IOC Match / Enrichment Response
# ============================================================================


class IOCMatchResponse(BaseModel):
    """
    Public API representation of an IOC matching/enrichment result.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )

    id: UUID | None = None

    indicator: str | None = None

    type: str | None = None

    value: str | None = None

    matched: bool = True

    confidence: int | None = Field(
        default=None,
        ge=IOC_MIN_CONFIDENCE,
        le=IOC_MAX_CONFIDENCE,
    )

    severity: str | None = None

    status: str | None = None

    reputation: str | None = None

    source: str | None = None

    feed: str | None = None

    tags: list[str] = Field(
        default_factory=list,
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )


# ============================================================================
# IOC List / Filter Query
# ============================================================================


class IOCListFilters(BaseModel):
    """
    Canonical IOC inventory query contract.

    UI filters:

        Search
        Type
        Severity
        Status
        Source
        Reputation

    Additional backend-compatible query controls remain supported.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    # ------------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------------

    query: str | None = None

    # ------------------------------------------------------------------------
    # UI Filters
    # ------------------------------------------------------------------------

    ioc_type: str | None = None

    severity: str | None = None

    status: str | None = None

    source: str | None = None

    reputation: str | None = None

    # ------------------------------------------------------------------------
    # Additional backend filtering
    # ------------------------------------------------------------------------

    feed: str | None = None

    active: bool | None = None

    start_time: datetime | None = None

    end_time: datetime | None = None

    # ------------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------------

    page: int = Field(
        default=IOC_DEFAULT_PAGE,
        ge=1,
    )

    page_size: int = Field(
        default=IOC_DEFAULT_PAGE_SIZE,
        ge=1,
        le=IOC_MAX_PAGE_SIZE,
    )


# ============================================================================
# IOC Relationship Query
# ============================================================================


class IOCRelationshipQuery(BaseModel):
    """
    Optional controls for IOC relationship lookup.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    include_events: bool = True

    include_alerts: bool = True

    include_incidents: bool = True

    include_assets: bool = True

    include_mitre: bool = True

    limit: int = Field(
        default=100,
        ge=1,
        le=500,
    )


# ============================================================================
# Conversion Helpers
# ============================================================================


def _model_to_dict(
    model: Any,
) -> dict[str, Any]:
    """
    Convert supported Pydantic/domain/ORM representations to a dictionary.
    """

    if isinstance(
        model,
        BaseModel,
    ):
        return model.model_dump(
            mode="python",
        )

    if hasattr(
        model,
        "model_dump",
    ):
        return model.model_dump(
            mode="python",
        )

    if hasattr(
        model,
        "__dict__",
    ):
        return {
            key: value
            for key, value in vars(model).items()
            if not key.startswith("_")
        }

    raise TypeError(
        "Unsupported IOC model type: "
        f"{type(model).__name__}",
    )


def _normalise_confidence(
    value: Any,
) -> int | None:
    """
    Normalize confidence into the public 0..100 representation.

    Domain representation:

        0.0 .. 1.0

    API representation:

        0 .. 100
    """

    if value is None:
        return None

    numeric = float(
        value,
    )

    if 0.0 <= numeric <= 1.0:
        return round(
            numeric * 100,
        )

    return max(
        IOC_MIN_CONFIDENCE,
        min(
            IOC_MAX_CONFIDENCE,
            round(numeric),
        ),
    )


def _enum_value(
    value: Any,
) -> str | None:
    """
    Return the string value of a StrEnum or regular value.
    """

    if value is None:
        return None

    if isinstance(
        value,
        str,
    ):
        return value

    enum_value = getattr(
        value,
        "value",
        None,
    )

    if enum_value is not None:
        return str(
            enum_value,
        )

    return str(
        value,
    )


def _normalise_relationships(
    model: Any,
) -> dict[str, Any]:
    """
    Convert domain relationship fields into API relationship fields.
    """

    raw = getattr(
        model,
        "relationships",
        None,
    )

    if raw is None:
        return {
            "event_ids": [],
            "alert_ids": [],
            "incident_ids": [],
            "asset_ids": [],
            "mitre_technique_ids": [],
            "event_count": 0,
            "alert_count": 0,
            "incident_count": 0,
            "asset_count": 0,
            "mitre_technique_count": 0,
        }

    data = _model_to_dict(
        raw,
    )

    event_ids = list(
        data.get(
            "event_ids",
            [],
        )
    )

    alert_ids = list(
        data.get(
            "alert_ids",
            [],
        )
    )

    incident_ids = list(
        data.get(
            "incident_ids",
            [],
        )
    )

    asset_ids = list(
        data.get(
            "asset_ids",
            [],
        )
    )

    mitre_technique_ids = list(
        data.get(
            "mitre_technique_ids",
            [],
        )
    )

    return {
        "event_ids": event_ids,
        "alert_ids": alert_ids,
        "incident_ids": incident_ids,
        "asset_ids": asset_ids,
        "mitre_technique_ids": mitre_technique_ids,
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


# ============================================================================
# IOC Response Conversion
# ============================================================================


def _ioc_response_from_model(
    cls: type[IOCResponse],
    model: Any,
) -> IOCResponse:
    """
    Convert a domain IOC model into IOCResponse.
    """

    if isinstance(
        model,
        cls,
    ):
        return model

    data = _model_to_dict(
        model,
    )

    ioc_id = data.get(
        "ioc_id",
        data.get("id"),
    )

    if ioc_id is None:
        raise ValueError(
            "IOC response conversion requires an IOC ID.",
        )

    ioc_type = data.get(
        "ioc_type",
        data.get("type"),
    )

    value = data.get(
        "value",
        "",
    )

    indicator = data.get(
        "indicator",
        value,
    )

    status = _enum_value(
        data.get("status"),
    )

    active = data.get(
        "active",
        status == IOCStatus.ACTIVE.value,
    )

    return cls(
        id=ioc_id,
        indicator=str(
            indicator,
        ),
        type=_enum_value(
            ioc_type,
        ) or "",
        value=str(
            value,
        ),
        confidence=_normalise_confidence(
            data.get("confidence"),
        ),
        severity=_enum_value(
            data.get("severity"),
        ),
        status=status,
        source=data.get(
            "source",
        ),
        feed=data.get(
            "feed",
        ),
        reputation=_enum_value(
            data.get("reputation"),
        ),
        description=data.get(
            "description",
        ),
        tags=list(
            data.get(
                "tags",
                [],
            )
        ),
        active=bool(
            active,
        ),
        first_seen=data.get(
            "first_seen",
        ),
        last_seen=data.get(
            "last_seen",
        ),
        expiration=data.get(
            "expiration",
        ),
        created_at=data.get(
            "created_at",
        ),
        updated_at=data.get(
            "updated_at",
        ),
        metadata=dict(
            data.get(
                "metadata",
                {},
            )
        ),
    )


def _ioc_detail_from_model(
    cls: type[IOCDetailResponse],
    model: Any,
) -> IOCDetailResponse:
    """
    Convert a domain IOC model into IOCDetailResponse.
    """

    base = _ioc_response_from_model(
        IOCResponse,
        model,
    )

    relationships = IOCRelationshipResponse(
        **_normalise_relationships(
            model,
        ),
    )

    return cls(
        **base.model_dump(),
        relationships=relationships,
    )


# ============================================================================
# IOC Match Conversion
# ============================================================================


def _ioc_match_from_model(
    cls: type[IOCMatchResponse],
    model: Any,
) -> IOCMatchResponse:
    """
    Convert an IOC match domain model into IOCMatchResponse.
    """

    if isinstance(
        model,
        cls,
    ):
        return model

    data = _model_to_dict(
        model,
    )

    ioc_id = data.get(
        "ioc_id",
        data.get("id"),
    )

    ioc_type = data.get(
        "ioc_type",
        data.get("type"),
    )

    return cls(
        id=ioc_id,
        indicator=data.get(
            "indicator",
            data.get(
                "value",
            ),
        ),
        type=_enum_value(
            ioc_type,
        ),
        value=data.get(
            "value",
        ),
        matched=data.get(
            "matched",
            True,
        ),
        confidence=_normalise_confidence(
            data.get(
                "confidence",
            ),
        ),
        severity=_enum_value(
            data.get(
                "severity",
            ),
        ),
        status=_enum_value(
            data.get(
                "status",
            ),
        ),
        reputation=_enum_value(
            data.get(
                "reputation",
            ),
        ),
        source=data.get(
            "source",
        ),
        feed=data.get(
            "feed",
        ),
        tags=list(
            data.get(
                "tags",
                [],
            )
        ),
        metadata=dict(
            data.get(
                "metadata",
                {},
            )
        ),
    )


# ============================================================================
# Attach Conversion Helpers
# ============================================================================


IOCResponse.from_model = classmethod(
    _ioc_response_from_model,
)

IOCDetailResponse.from_model = classmethod(
    _ioc_detail_from_model,
)

IOCMatchResponse.from_model = classmethod(
    _ioc_match_from_model,
)


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "IOC_MIN_CONFIDENCE",
    "IOC_MAX_CONFIDENCE",
    "IOC_DEFAULT_PAGE",
    "IOC_DEFAULT_PAGE_SIZE",
    "IOC_MAX_PAGE_SIZE",
    "IOC_DEFAULT_SEVERITY",
    "IOC_DEFAULT_STATUS",
    "IOC_DEFAULT_REPUTATION",
    "IOCResponse",
    "IOCDetailResponse",
    "IOCRelationshipResponse",
    "IOCListResponse",
    "IOCPagination",
    "IOCSummaryResponse",
    "IOCFilterOptionsResponse",
    "IOCCreateRequest",
    "IOCUpdateRequest",
    "IOCStatusChangeRequest",
    "IOCListFilters",
    "IOCRelationshipQuery",
    "IOCMatchResponse",
    "ioc_type_values",
    "ioc_severity_values",
    "ioc_status_values",
    "ioc_reputation_values",
]