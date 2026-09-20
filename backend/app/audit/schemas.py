"""
SentinelSIEM — Central Audit API Schemas
========================================

Canonical Pydantic contracts for the centralized audit subsystem.

Canonical persistence
---------------------

    siem_auth_audit

Canonical ORM model
-------------------

    app.audit.models.AuditEvent


Architecture
------------

    Authentication / User Management
                    |
                    v
              AuditCreate
                    |
                    v
             AuditRepository
                    |
                    v
             siem_auth_audit
                    |
                    v
               AuditEvent
                    |
                    v
             AuditService
                    |
          +---------+---------+
          |                   |
          v                   v
     User Resolver       Audit Mapper
          |                   |
          +---------+---------+
                    |
                    v
              AuditResponse
                    |
                    v
                   API


FINAL GLOBAL AUDIT CONTRACT
---------------------------

Canonical database references:

    actor_user_id
    target_user_id

Resolved API identities:

    actor
    target

Resolved identity:

    user_id
    username
    role

The UUID fields remain the canonical technical references.

The resolved ``actor`` and ``target`` objects are presentation-layer
identity information.

IMPORTANT:

    actor_user_id == None
        -> actor may be None
        -> presentation layer may render:
               🛡 System
               System

    target_user_id == None
        -> target MUST remain None
        -> presentation layer MUST render:
               —
               No target

The backend MUST NEVER create a fake target such as:

    —
    User

A missing target is semantically different from an unknown user.

Table vs Details
----------------

Audit table:

    Human-readable actor/target identity.

Audit details:

    Human-readable identity
    +
    technical UUIDs.

Therefore ``actor_user_id`` and ``target_user_id`` remain available
in the API response for the technical details view.

Security
--------

These schemas MUST NEVER expose:

    - plaintext passwords
    - password hashes
    - JWTs
    - access tokens
    - refresh tokens
    - session tokens
    - API keys
    - client secrets
    - private keys
    - authorization headers
    - cookies
    - credential material

Unknown fields are rejected.

AuditCreate
-----------

AuditCreate is an internal trusted creation contract.

It MUST NOT be exposed directly as a public HTTP request model.

Canonical metadata field:

    metadata_json

The legacy ``metadata`` field is intentionally unsupported.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


# =============================================================================
# Constants
# =============================================================================

MAX_ACTION_LENGTH = 150
MAX_OUTCOME_LENGTH = 50

MAX_REQUEST_ID_LENGTH = 100
MAX_SOURCE_IP_LENGTH = 45

MAX_USERNAME_LENGTH = 150
MAX_ROLE_LENGTH = 100

MAX_METADATA_DEPTH = 10

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

DEFAULT_RELATED_LIMIT = 100
MAX_RELATED_LIMIT = 200

DEFAULT_RECENT_LIMIT = 50
MAX_RECENT_LIMIT = 200

DEFAULT_EXPORT_LIMIT = 10_000
MAX_EXPORT_LIMIT = 50_000


# =============================================================================
# Canonical Outcomes
# =============================================================================

CANONICAL_OUTCOMES = frozenset(
    {
        "success",
        "failure",
        "denied",
    }
)


# =============================================================================
# Sensitive Metadata Protection
# =============================================================================

_FORBIDDEN_METADATA_KEYS: frozenset[str] = frozenset(
    {
        # ---------------------------------------------------------------------
        # Passwords
        # ---------------------------------------------------------------------
        "password",
        "passwd",
        "pass",
        "pwd",
        "passphrase",
        "password_hash",
        "passwordhash",
        "hashed_password",
        "hashedpassword",
        "hash_password",
        "hashpassword",
        "new_password",
        "newpassword",
        "current_password",
        "currentpassword",
        "old_password",
        "oldpassword",
        "plaintext_password",
        "plaintextpassword",
        "plain_password",
        "plainpassword",
        "password_value",
        "passwordvalue",

        # ---------------------------------------------------------------------
        # Tokens
        # ---------------------------------------------------------------------
        "token",
        "token_id",
        "tokenid",
        "token_value",
        "tokenvalue",
        "access_token",
        "accesstoken",
        "refresh_token",
        "refreshtoken",
        "id_token",
        "idtoken",
        "session_token",
        "sessiontoken",
        "bearer_token",
        "bearertoken",
        "jwt",
        "jwt_token",
        "jwttoken",
        "jwt_value",
        "jwtvalue",

        # ---------------------------------------------------------------------
        # API credentials
        # ---------------------------------------------------------------------
        "api_key",
        "apikey",
        "api_key_value",
        "apikeyvalue",
        "client_secret",
        "clientsecret",
        "client_secret_value",
        "clientsecretvalue",

        # ---------------------------------------------------------------------
        # Secrets
        # ---------------------------------------------------------------------
        "secret",
        "secret_key",
        "secretkey",
        "secret_value",
        "secretvalue",

        # ---------------------------------------------------------------------
        # Cryptographic material
        # ---------------------------------------------------------------------
        "private_key",
        "privatekey",
        "private_key_value",
        "privatekeyvalue",
        "encryption_key",
        "encryptionkey",
        "encryption_key_value",
        "encryptionkeyvalue",
        "signing_key",
        "signingkey",
        "signing_key_value",
        "signingkeyvalue",

        # ---------------------------------------------------------------------
        # HTTP credential material
        # ---------------------------------------------------------------------
        "authorization",
        "authorization_header",
        "authorizationheader",
        "auth_header",
        "authheader",
        "cookie",
        "cookies",
        "set_cookie",
        "setcookie",

        # ---------------------------------------------------------------------
        # Generic credentials
        # ---------------------------------------------------------------------
        "credential",
        "credentials",
        "credential_material",
        "credentialmaterial",
        "credential_value",
        "credentialvalue",

        # ---------------------------------------------------------------------
        # Session secrets
        # ---------------------------------------------------------------------
        "session_secret",
        "sessionsecret",
        "session_secret_value",
        "sessionsecretvalue",
    }
)


_FORBIDDEN_METADATA_FRAGMENTS: tuple[str, ...] = (
    "passwordhash",
    "hashedpassword",
    "hashpassword",
    "plaintextpassword",
    "plainpassword",
    "passwordvalue",
    "accesstoken",
    "refreshtoken",
    "sessiontoken",
    "bearertoken",
    "jwttoken",
    "jwtvalue",
    "idtoken",
    "tokenid",
    "tokenvalue",
    "apikey",
    "apikeyvalue",
    "clientsecret",
    "clientsecretvalue",
    "secretvalue",
    "privatekey",
    "privatekeyvalue",
    "encryptionkey",
    "encryptionkeyvalue",
    "signingkey",
    "signingkeyvalue",
    "authorizationheader",
    "authheader",
    "credentialmaterial",
    "credentialvalue",
    "sessionsecret",
    "sessionsecretvalue",
)


def _normalize_metadata_key(
    key: object,
) -> str:
    """
    Normalize metadata keys before security comparison.

    Examples:

        Access-Token
            -> access_token

        " PASSWORD "
            -> password

        authorization.header
            -> authorization_header
    """

    normalized = str(key).strip().lower()

    for separator in (
        "-",
        " ",
        ".",
        "/",
        "\\",
    ):
        normalized = normalized.replace(
            separator,
            "_",
        )

    while "__" in normalized:
        normalized = normalized.replace(
            "__",
            "_",
        )

    return normalized


def _is_forbidden_metadata_key(
    key: object,
) -> bool:
    """
    Determine whether a metadata key contains
    sensitive credential material.
    """

    normalized = _normalize_metadata_key(
        key,
    )

    if normalized in _FORBIDDEN_METADATA_KEYS:
        return True

    compact = normalized.replace(
        "_",
        "",
    )

    return any(
        fragment in compact
        for fragment in _FORBIDDEN_METADATA_FRAGMENTS
    )


def _validate_metadata_value(
    value: object,
    *,
    path: str = "metadata_json",
    depth: int = 0,
) -> None:
    """
    Recursively validate metadata.

    Sensitive fields are rejected regardless
    of nesting depth.

    A depth limit prevents pathological structures.
    """

    if depth > MAX_METADATA_DEPTH:
        raise ValueError(
            "Audit metadata exceeds the maximum "
            f"supported nesting depth of {MAX_METADATA_DEPTH}."
        )

    if isinstance(
        value,
        dict,
    ):
        for key, nested_value in value.items():
            if _is_forbidden_metadata_key(
                key,
            ):
                raise ValueError(
                    "Sensitive credential field "
                    f"'{path}.{key}' is not permitted "
                    "in audit metadata."
                )

            _validate_metadata_value(
                nested_value,
                path=f"{path}.{key}",
                depth=depth + 1,
            )

        return

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
            frozenset,
        ),
    ):
        for index, nested_value in enumerate(
            value,
        ):
            _validate_metadata_value(
                nested_value,
                path=f"{path}[{index}]",
                depth=depth + 1,
            )


# =============================================================================
# Common Schema Configuration
# =============================================================================


class AuditSchemaBase(BaseModel):
    """
    Common configuration for all audit schemas.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


# =============================================================================
# Canonical Audit Classification
# =============================================================================


class AuditBase(AuditSchemaBase):
    """
    Canonical audit classification fields.
    """

    action: str = Field(
        ...,
        min_length=1,
        max_length=MAX_ACTION_LENGTH,
        description="Canonical namespaced audit action.",
        examples=[
            "authentication.login_success",
            "authentication.login_failure",
            "authentication.logout",
            "authentication.session_created",
            "authentication.session_revoked",
            "authorization.permission_denied",
            "authorization.role_denied",
            "users.created",
            "users.updated",
            "users.role_changed",
            "users.enabled",
            "users.disabled",
            "users.locked",
            "users.unlocked",
            "users.password_reset",
            "users.force_password_change",
            "users.sessions_revoked",
            "users.deleted",
        ],
    )

    outcome: str = Field(
        ...,
        min_length=1,
        max_length=MAX_OUTCOME_LENGTH,
        description="Canonical audit outcome.",
        examples=[
            "success",
            "failure",
            "denied",
        ],
    )

    @field_validator("action")
    @classmethod
    def validate_action(
        cls,
        value: str,
    ) -> str:
        """
        Normalize and validate action.
        """

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "action must be a string."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "action must not be empty."
            )

        return normalized

    @field_validator("outcome")
    @classmethod
    def validate_outcome(
        cls,
        value: str,
    ) -> str:
        """
        Normalize and validate outcome.
        """

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "outcome must be a string."
            )

        normalized = value.strip().lower()

        if not normalized:
            raise ValueError(
                "outcome must not be empty."
            )

        if normalized not in CANONICAL_OUTCOMES:
            raise ValueError(
                "outcome must be one of: "
                "success, failure, denied."
            )

        return normalized


# =============================================================================
# Internal Audit Creation Contract
# =============================================================================


class AuditCreate(AuditBase):
    """
    Trusted internal schema for creating an audit event.

    This schema is NOT a public HTTP request model.
    """

    audit_id: UUID = Field(
        default_factory=uuid4,
        description="Unique audit event identifier.",
    )

    actor_user_id: UUID | None = Field(
        default=None,
        description="Canonical actor user UUID.",
    )

    target_user_id: UUID | None = Field(
        default=None,
        description=(
            "Canonical target user UUID. "
            "NULL means the event has no target."
        ),
    )

    session_id: UUID | None = Field(
        default=None,
        description="Authentication/session correlation UUID.",
    )

    request_id: str | None = Field(
        default=None,
        max_length=MAX_REQUEST_ID_LENGTH,
        description="Application request correlation identifier.",
    )

    source_ip: str | None = Field(
        default=None,
        max_length=MAX_SOURCE_IP_LENGTH,
        description="Source/client IP address.",
    )

    metadata_json: dict[str, Any] | None = Field(
        default=None,
        description="Safe non-sensitive audit metadata.",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the audit event was created.",
    )

    @field_validator(
        "request_id",
        "source_ip",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize optional string values.
        """

        if value is None:
            return None

        normalized = value.strip()

        return normalized or None

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(
        cls,
        value: datetime,
    ) -> datetime:
        """
        Require timezone-aware timestamps and normalize to UTC.
        """

        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                "created_at must be timezone-aware."
            )

        return value.astimezone(UTC)

    @field_validator("metadata_json")
    @classmethod
    def validate_metadata(
        cls,
        value: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """
        Validate audit metadata recursively.
        """

        if value is None:
            return None

        _validate_metadata_value(
            value,
        )

        return value


# =============================================================================
# Resolved Actor Identity
# =============================================================================


class AuditActorResponse(AuditSchemaBase):
    """
    Resolved actor identity.

    The UUID is the canonical identity reference.

    Username and role are presentation-layer values.

    Example:

        {
            "user_id": "...",
            "username": "Sahadat Hossain",
            "role": "Admin"
        }

    System-generated events may have:

        actor = None

    The presentation layer can then render:

        🛡 System
           System
    """

    user_id: UUID = Field(
        ...,
        description="Canonical actor user UUID.",
    )

    username: str = Field(
        ...,
        min_length=1,
        max_length=MAX_USERNAME_LENGTH,
        description="Resolved actor username.",
    )

    role: str = Field(
        ...,
        min_length=1,
        max_length=MAX_ROLE_LENGTH,
        description="Resolved actor role.",
    )


# =============================================================================
# Resolved Target Identity
# =============================================================================


class AuditTargetResponse(AuditSchemaBase):
    """
    Resolved target identity.

    The UUID is the canonical identity reference.

    Username and role are presentation-layer values.

    IMPORTANT:

        This object exists ONLY when target_user_id exists.

    When target_user_id is NULL:

        target == None

    The presentation layer MUST render:

        —
        No target

    It MUST NOT render:

        —
        User
    """

    user_id: UUID = Field(
        ...,
        description="Canonical target user UUID.",
    )

    username: str = Field(
        ...,
        min_length=1,
        max_length=MAX_USERNAME_LENGTH,
        description="Resolved target username.",
    )

    role: str = Field(
        ...,
        min_length=1,
        max_length=MAX_ROLE_LENGTH,
        description="Resolved target role.",
    )


# =============================================================================
# Public Audit Event Response
# =============================================================================


class AuditResponse(AuditSchemaBase):
    """
    Public-safe representation of one audit event.

    Canonical references:

        actor_user_id
        target_user_id

    Resolved presentation objects:

        actor
        target

    Final identity semantics
    ------------------------

    Actor:

        actor_user_id != None
            -> actor should normally contain resolved identity

        actor_user_id == None
            -> actor may be None
            -> UI may render System/System

    Target:

        target_user_id != None
            -> target should normally contain resolved identity

        target_user_id == None
            -> target MUST be None

            -> UI:
                   —
                   No target

    The API does not invent fallback target identities.

    Example successful login:

        {
            "actor_user_id": "...",
            "actor": {
                "user_id": "...",
                "username": "Sahadat Hossain",
                "role": "Admin"
            },

            "target_user_id": "...",
            "target": {
                "user_id": "...",
                "username": "Sahadat Hossain",
                "role": "Admin"
            },

            "action": "authentication.login_success",
            "outcome": "success"
        }

    Example failed login:

        {
            "actor_user_id": null,
            "actor": null,

            "target_user_id": null,
            "target": null,

            "action": "authentication.login_failure",
            "outcome": "failure"
        }
    """

    # -------------------------------------------------------------------------
    # Audit identity
    # -------------------------------------------------------------------------

    audit_id: UUID = Field(
        ...,
        description="Unique audit event UUID.",
    )

    # -------------------------------------------------------------------------
    # Canonical actor
    # -------------------------------------------------------------------------

    actor_user_id: UUID | None = Field(
        default=None,
        description="Canonical actor user UUID.",
    )

    # -------------------------------------------------------------------------
    # Canonical target
    # -------------------------------------------------------------------------

    target_user_id: UUID | None = Field(
        default=None,
        description=(
            "Canonical target user UUID. "
            "NULL means no target."
        ),
    )

    # -------------------------------------------------------------------------
    # Session correlation
    # -------------------------------------------------------------------------

    session_id: UUID | None = Field(
        default=None,
        description="Authentication/session correlation UUID.",
    )

    # -------------------------------------------------------------------------
    # Resolved actor identity
    # -------------------------------------------------------------------------

    actor: AuditActorResponse | None = Field(
        default=None,
        description=(
            "Resolved actor identity. "
            "NULL may represent a system-generated event."
        ),
    )

    # -------------------------------------------------------------------------
    # Resolved target identity
    # -------------------------------------------------------------------------

    target: AuditTargetResponse | None = Field(
        default=None,
        description=(
            "Resolved target identity. "
            "MUST be NULL when target_user_id is NULL."
        ),
    )

    # -------------------------------------------------------------------------
    # Request correlation
    # -------------------------------------------------------------------------

    request_id: str | None = Field(
        default=None,
        max_length=MAX_REQUEST_ID_LENGTH,
    )

    # -------------------------------------------------------------------------
    # Network information
    # -------------------------------------------------------------------------

    source_ip: str | None = Field(
        default=None,
        max_length=MAX_SOURCE_IP_LENGTH,
    )

    # -------------------------------------------------------------------------
    # Classification
    # -------------------------------------------------------------------------

    action: str = Field(
        ...,
        min_length=1,
        max_length=MAX_ACTION_LENGTH,
    )

    outcome: str = Field(
        ...,
        min_length=1,
        max_length=MAX_OUTCOME_LENGTH,
    )

    # -------------------------------------------------------------------------
    # Safe metadata
    # -------------------------------------------------------------------------

    metadata_json: dict[str, Any] | None = Field(
        default=None,
    )

    # -------------------------------------------------------------------------
    # Timestamp
    # -------------------------------------------------------------------------

    created_at: datetime = Field(
        ...,
        description="UTC audit creation timestamp.",
    )

    # -------------------------------------------------------------------------
    # Action validation
    # -------------------------------------------------------------------------

    @field_validator("action")
    @classmethod
    def validate_response_action(
        cls,
        value: str,
    ) -> str:
        """
        Validate response action.
        """

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "action must not be empty."
            )

        return normalized

    # -------------------------------------------------------------------------
    # Outcome validation
    # -------------------------------------------------------------------------

    @field_validator("outcome")
    @classmethod
    def validate_response_outcome(
        cls,
        value: str,
    ) -> str:
        """
        Validate response outcome.
        """

        normalized = value.strip().lower()

        if normalized not in CANONICAL_OUTCOMES:
            raise ValueError(
                "outcome must be one of: "
                "success, failure, denied."
            )

        return normalized

    # -------------------------------------------------------------------------
    # Optional text normalization
    # -------------------------------------------------------------------------

    @field_validator(
        "request_id",
        "source_ip",
    )
    @classmethod
    def normalize_response_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize optional response strings.
        """

        if value is None:
            return None

        normalized = value.strip()

        return normalized or None

    # -------------------------------------------------------------------------
    # Timestamp validation
    # -------------------------------------------------------------------------

    @field_validator("created_at")
    @classmethod
    def normalize_response_timestamp(
        cls,
        value: datetime,
    ) -> datetime:
        """
        Require timezone-aware timestamps and normalize to UTC.
        """

        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                "created_at must be timezone-aware."
            )

        return value.astimezone(UTC)

    # -------------------------------------------------------------------------
    # Metadata validation
    # -------------------------------------------------------------------------

    @field_validator("metadata_json")
    @classmethod
    def validate_response_metadata(
        cls,
        value: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """
        Re-validate metadata before public serialization.
        """

        if value is None:
            return None

        _validate_metadata_value(
            value,
        )

        return value

    # -------------------------------------------------------------------------
    # Actor / Target consistency
    # -------------------------------------------------------------------------

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
    ) -> "AuditResponse":
        """
        Validate the response and enforce identity consistency.

        In particular:

            target_user_id is NULL
                ->
            target MUST be NULL.

        This prevents accidental creation of a misleading target
        fallback such as:

            —
            User
        """

        model = super().model_validate(
            obj,
            strict=strict,
            from_attributes=from_attributes,
            context=context,
        )

        if (
            model.target_user_id is None
            and model.target is not None
        ):
            raise ValueError(
                "target must be null when target_user_id is null."
            )

        if (
            model.target_user_id is not None
            and model.target is not None
            and model.target.user_id != model.target_user_id
        ):
            raise ValueError(
                "target.user_id must match target_user_id."
            )

        if (
            model.actor_user_id is not None
            and model.actor is not None
            and model.actor.user_id != model.actor_user_id
        ):
            raise ValueError(
                "actor.user_id must match actor_user_id."
            )

        return model


# =============================================================================
# Pagination
# =============================================================================


class AuditPagination(AuditSchemaBase):
    """
    Common pagination response contract.
    """

    total: int = Field(
        ...,
        ge=0,
        description="Total matching audit events.",
    )

    page: int = Field(
        ...,
        ge=1,
        description="One-based page number.",
    )

    page_size: int = Field(
        ...,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Number of events requested per page.",
    )

    pages: int = Field(
        ...,
        ge=0,
        description="Total available pages.",
    )


# =============================================================================
# Global Audit List
# =============================================================================


class AuditListResponse(AuditPagination):
    """
    Paginated global audit response.

    Endpoint:

        GET /api/v1/audit
    """

    events: list[AuditResponse] = Field(
        default_factory=list,
        description="Audit events for the requested page.",
    )


# =============================================================================
# Single Audit Event
# =============================================================================


class AuditDetailResponse(AuditSchemaBase):
    """
    Explicit single-event response contract.

    Details view receives:

        - human-readable actor
        - human-readable target
        - actor UUID
        - target UUID
        - session UUID
        - request ID
        - source IP
        - metadata
        - timestamp
    """

    event: AuditResponse


# =============================================================================
# Related Audit Events
# =============================================================================


class AuditRelatedEventListResponse(AuditSchemaBase):
    """
    Related audit events response.

    Endpoint:

        GET /api/v1/audit/{audit_id}/related
    """

    audit_id: UUID = Field(
        ...,
        description="Source audit event UUID.",
    )

    events: list[AuditResponse] = Field(
        default_factory=list,
        description="Related audit events.",
    )

    total: int = Field(
        ...,
        ge=0,
        description="Number of returned related events.",
    )


# =============================================================================
# User Audit History
# =============================================================================


class UserAuditHistoryResponse(AuditPagination):
    """
    Paginated audit history for one user.

    An event belongs to a user's history when the user is
    either the actor or the target.

    Endpoint:

        GET /api/v1/users/{user_id}/audit
    """

    user_id: UUID = Field(
        ...,
        description="User whose audit history is being returned.",
    )

    events: list[AuditResponse] = Field(
        default_factory=list,
        description="User audit history.",
    )


# =============================================================================
# User Activity Compatibility Contract
# =============================================================================


class UserActivityResponse(
    UserAuditHistoryResponse,
):
    """
    Backward-compatible user activity response.

    New code should prefer UserAuditHistoryResponse.
    """

    pass


# =============================================================================
# Statistics
# =============================================================================


class AuditStatisticsResponse(
    AuditSchemaBase,
):
    """
    Canonical audit statistics.

    All counters MUST describe the same filtered dataset.
    """

    total: int = Field(
        ...,
        ge=0,
        description="Total matching events.",
    )

    success: int = Field(
        ...,
        ge=0,
        description="Successful events.",
    )

    failure: int = Field(
        ...,
        ge=0,
        description="Failed events.",
    )

    denied: int = Field(
        ...,
        ge=0,
        description="Denied events.",
    )

    unique_actors: int = Field(
        ...,
        ge=0,
        description="Unique actor users.",
    )

    unique_targets: int = Field(
        ...,
        ge=0,
        description="Unique target users.",
    )


# =============================================================================
# Export
# =============================================================================


class AuditExportResponse(
    AuditSchemaBase,
):
    """
    Read-only audit export response.
    """

    format: str = Field(
        ...,
        min_length=1,
        max_length=20,
        description="Export format.",
    )

    total: int = Field(
        ...,
        ge=0,
        description="Number of exported events.",
    )

    events: list[AuditResponse] = Field(
        default_factory=list,
        description="Exported audit events.",
    )


# =============================================================================
# Security Event Responses
# =============================================================================


class SecurityEventListResponse(
    AuditPagination,
):
    """
    Paginated security-event response.
    """

    events: list[AuditResponse] = Field(
        default_factory=list,
    )


class SecurityEventRecentResponse(
    AuditSchemaBase,
):
    """
    Bounded response for recent security events.
    """

    events: list[AuditResponse] = Field(
        default_factory=list,
    )

    limit: int = Field(
        ...,
        ge=1,
        le=MAX_RECENT_LIMIT,
    )

    total: int = Field(
        ...,
        ge=0,
    )


# =============================================================================
# Public Exports
# =============================================================================

__all__ = [
    # Base
    "AuditSchemaBase",
    "AuditBase",

    # Internal creation
    "AuditCreate",

    # Identity
    "AuditActorResponse",
    "AuditTargetResponse",

    # Event
    "AuditResponse",
    "AuditDetailResponse",

    # Pagination
    "AuditPagination",
    "AuditListResponse",

    # Related events
    "AuditRelatedEventListResponse",

    # User history
    "UserAuditHistoryResponse",
    "UserActivityResponse",

    # Statistics
    "AuditStatisticsResponse",

    # Export
    "AuditExportResponse",

    # Security events
    "SecurityEventListResponse",
    "SecurityEventRecentResponse",

    # Constants
    "MAX_ACTION_LENGTH",
    "MAX_OUTCOME_LENGTH",
    "MAX_REQUEST_ID_LENGTH",
    "MAX_SOURCE_IP_LENGTH",
    "MAX_USERNAME_LENGTH",
    "MAX_ROLE_LENGTH",
    "MAX_METADATA_DEPTH",
    "DEFAULT_PAGE",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "DEFAULT_RELATED_LIMIT",
    "MAX_RELATED_LIMIT",
    "DEFAULT_RECENT_LIMIT",
    "MAX_RECENT_LIMIT",
    "DEFAULT_EXPORT_LIMIT",
    "MAX_EXPORT_LIMIT",
    "CANONICAL_OUTCOMES",
]