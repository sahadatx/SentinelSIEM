"""
SentinelSIEM — Global Audit API Schemas
=======================================

Public API schemas for the centralized audit subsystem.

Canonical persistence source
----------------------------

    siem_auth_audit

These schemas are presentation/API contracts only.

Architecture
------------

    API Route
       |
       v
    API Schemas
       |
       v
    AuditService
       |
       v
    AuditRepository
       |
       v
    siem_auth_audit


Security
--------

These schemas MUST NOT expose:

    - passwords
    - password hashes
    - access tokens
    - refresh tokens
    - session tokens
    - API keys
    - secrets
    - private keys
    - authorization headers
    - cookies
    - raw credential material

Identity enrichment
-------------------

Global Audit responses expose safe actor/target information.

Actor:

    user_id
    username
    role

Target:

    user_id
    username
    role

The API schema contains only presentation-safe identity information.

Raw ORM objects MUST NOT be returned directly from API routes.
"""


from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Base
# ============================================================================


class AuditSchemaBase(BaseModel):
    """
    Base configuration for Global Audit API schemas.

    Unknown fields are rejected to prevent accidental expansion
    of the public API contract.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


# ============================================================================
# Audit Identity Reference
# ============================================================================


class AuditUserReference(AuditSchemaBase):
    """
    Safe user identity reference used by Global Audit responses.

    This is intentionally limited to non-sensitive identity information.

    Exposed fields:

        user_id
        username
        role

    Security
    --------

    This schema MUST NOT contain:

        - password
        - password_hash
        - tokens
        - session secrets
        - API keys
        - authentication headers
        - private keys
        - credential material
    """

    user_id: UUID

    username: str = Field(
        min_length=1,
        max_length=150,
    )

    role: str = Field(
        min_length=1,
        max_length=100,
    )


# ============================================================================
# Audit Event Response
# ============================================================================


class AuditEventResponse(AuditSchemaBase):
    """
    Public-safe representation of one audit event.

    Actor and target are enriched identity references.

    Actor
    -----

        user_id
        username
        role

    Target
    ------

        user_id
        username
        role

    Security
    --------

    Only explicitly approved audit fields are exposed.

    Credential material must never be returned through this schema.
    """

    # ------------------------------------------------------------------------
    # Event Identity
    # ------------------------------------------------------------------------

    audit_id: UUID

    # ------------------------------------------------------------------------
    # Enriched Actor
    # ------------------------------------------------------------------------

    actor: AuditUserReference | None = None

    # ------------------------------------------------------------------------
    # Enriched Target
    # ------------------------------------------------------------------------

    target: AuditUserReference | None = None

    # ------------------------------------------------------------------------
    # Canonical Correlation References
    # ------------------------------------------------------------------------

    session_id: UUID | None = None

    request_id: str | None = Field(
        default=None,
        max_length=100,
    )

    # ------------------------------------------------------------------------
    # Event Classification
    # ------------------------------------------------------------------------

    action: str = Field(
        min_length=1,
        max_length=150,
    )

    outcome: str = Field(
        min_length=1,
        max_length=50,
    )

    category: str = Field(
        min_length=1,
        max_length=100,
    )

    # ------------------------------------------------------------------------
    # Source Context
    # ------------------------------------------------------------------------

    source: str | None = Field(
        default=None,
        max_length=100,
    )

    source_ip: str | None = Field(
        default=None,
        max_length=45,
    )

    user_agent: str | None = Field(
        default=None,
        max_length=1000,
    )

    # ------------------------------------------------------------------------
    # Safe Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )

    # ------------------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------------------

    timestamp: datetime


# ============================================================================
# Related Audit Event Response
# ============================================================================


class AuditRelatedEventResponse(
    AuditEventResponse,
):
    """
    Public-safe representation of an audit event returned
    as a related event.

    Uses the same enriched actor/target contract as
    AuditEventResponse.
    """

    relation: str | None = Field(
        default=None,
        max_length=100,
    )


# ============================================================================
# Audit List Response
# ============================================================================


class AuditListResponse(AuditSchemaBase):
    """
    Paginated Global Audit response.

    Used by:

        GET /audit
    """

    events: list[AuditEventResponse] = Field(
        default_factory=list,
    )

    page: int = Field(
        ge=1,
    )

    page_size: int = Field(
        ge=1,
        le=200,
    )

    total: int = Field(
        ge=0,
    )

    pages: int = Field(
        ge=0,
    )


# ============================================================================
# Related Events Response
# ============================================================================


class AuditRelatedEventListResponse(
    AuditSchemaBase,
):
    """
    Related audit events response.

    Used by:

        GET /audit/{audit_id}/related
    """

    audit_id: UUID

    events: list[AuditRelatedEventResponse] = Field(
        default_factory=list,
    )

    total: int = Field(
        ge=0,
    )


# ============================================================================
# Audit Statistics Response
# ============================================================================


class AuditStatisticsResponse(
    AuditSchemaBase,
):
    """
    Global Audit dashboard statistics.

    Statistics represent the currently selected filter scope.
    """

    total: int = Field(
        ge=0,
    )

    success: int = Field(
        ge=0,
    )

    failure: int = Field(
        ge=0,
    )

    denied: int = Field(
        ge=0,
    )


# ============================================================================
# Audit Filter
# ============================================================================


class AuditFilter(
    AuditSchemaBase,
):
    """
    Global Audit investigation filters.

    Supported filters
    -----------------

        actor
        target
        action
        category
        result
        source
        date_from
        date_to
        search
        session_id
        request_id
    """

    actor: UUID | None = None

    target: UUID | None = None

    action: str | None = Field(
        default=None,
        max_length=150,
    )

    category: str | None = Field(
        default=None,
        max_length=100,
    )

    result: str | None = Field(
        default=None,
        max_length=50,
    )

    source: str | None = Field(
        default=None,
        max_length=100,
    )

    date_from: datetime | None = None

    date_to: datetime | None = None

    search: str | None = Field(
        default=None,
        max_length=500,
    )

    session_id: UUID | None = None

    request_id: str | None = Field(
        default=None,
        max_length=100,
    )


# ============================================================================
# Audit List Query
# ============================================================================


class AuditListQuery(
    AuditSchemaBase,
):
    """
    Query contract for Global Audit listing.

    Used internally by the API route when query parameters
    need to be normalized before calling AuditService.
    """

    page: int = Field(
        default=1,
        ge=1,
    )

    page_size: int = Field(
        default=50,
        ge=1,
        le=200,
    )

    actor: UUID | None = None

    target: UUID | None = None

    action: str | None = Field(
        default=None,
        max_length=150,
    )

    category: str | None = Field(
        default=None,
        max_length=100,
    )

    result: str | None = Field(
        default=None,
        max_length=50,
    )

    source: str | None = Field(
        default=None,
        max_length=100,
    )

    date_from: datetime | None = None

    date_to: datetime | None = None

    search: str | None = Field(
        default=None,
        max_length=500,
    )

    session_id: UUID | None = None

    request_id: str | None = Field(
        default=None,
        max_length=100,
    )


# ============================================================================
# Audit Related Query
# ============================================================================


class AuditRelatedQuery(
    AuditSchemaBase,
):
    """
    Query contract for related-event lookup.

    Used by:

        GET /audit/{audit_id}/related
    """

    limit: int = Field(
        default=100,
        ge=1,
        le=200,
    )


# ============================================================================
# Audit Export Query
# ============================================================================


class AuditExportQuery(
    AuditSchemaBase,
):
    """
    Query contract for audit export.

    Used by:

        GET /audit/export

    Export remains read-only.

    The service/repository layer remains responsible for
    enforcing the maximum export size.
    """

    actor: UUID | None = None

    target: UUID | None = None

    action: str | None = Field(
        default=None,
        max_length=150,
    )

    category: str | None = Field(
        default=None,
        max_length=100,
    )

    result: str | None = Field(
        default=None,
        max_length=50,
    )

    source: str | None = Field(
        default=None,
        max_length=100,
    )

    date_from: datetime | None = None

    date_to: datetime | None = None

    search: str | None = Field(
        default=None,
        max_length=500,
    )

    session_id: UUID | None = None

    request_id: str | None = Field(
        default=None,
        max_length=100,
    )

    limit: int = Field(
        default=10_000,
        ge=1,
        le=10_000,
    )

    format: str = Field(
        default="json",
        min_length=1,
        max_length=20,
        pattern="^(json|csv)$",
    )


# ============================================================================
# Audit Export Response
# ============================================================================


class AuditExportResponse(
    AuditSchemaBase,
):
    """
    Structured JSON export response.

    Actor and target identities remain enriched using:

        user_id
        username
        role

    For CSV downloads, the route may return a Response
    or StreamingResponse directly.
    """

    format: str = Field(
        min_length=1,
        max_length=20,
    )

    total: int = Field(
        ge=0,
    )

    events: list[AuditEventResponse] = Field(
        default_factory=list,
    )


# ============================================================================
# Generic Audit Mutation Response
# ============================================================================


class AuditMutationResponse(
    AuditSchemaBase,
):
    """
    Generic response for future audit-related state operations.

    Audit records themselves remain immutable.
    """

    success: bool = True

    message: str


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "AuditSchemaBase",
    "AuditUserReference",
    "AuditEventResponse",
    "AuditRelatedEventResponse",
    "AuditListResponse",
    "AuditRelatedEventListResponse",
    "AuditStatisticsResponse",
    "AuditFilter",
    "AuditListQuery",
    "AuditRelatedQuery",
    "AuditExportQuery",
    "AuditExportResponse",
    "AuditMutationResponse",
]