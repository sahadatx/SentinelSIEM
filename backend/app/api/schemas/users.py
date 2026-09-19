"""
SentinelSIEM User Management API Schemas.

===============================================================================
PURPOSE
===============================================================================

Pydantic v2 request/response schemas for the SentinelSIEM User Management API.

The API schema layer owns:

    - request validation
    - response serialization
    - type validation
    - string normalization
    - pagination bounds
    - API contract boundaries

The API schema layer does NOT own:

    - RBAC authorization
    - permission decisions
    - last-active-ADMIN protection
    - account-state business rules
    - session-revocation orchestration
    - password hashing
    - database persistence
    - transaction management

Those responsibilities belong to the appropriate service/repository layers.

===============================================================================
SECURITY
===============================================================================

Plaintext passwords are accepted only by explicit password request schemas.

Passwords MUST NEVER appear in response schemas.

The following MUST NEVER appear in API response schemas:

    - password
    - password_hash
    - access_token
    - refresh_token
    - session_token
    - JWT
    - JWT JTI
    - token_id
    - API keys
    - client secrets
    - private keys
    - authorization headers
    - cookies
    - credential material

Internal repository/domain fields MUST NOT accidentally leak into API
responses.

===============================================================================
UNKNOWN FIELDS
===============================================================================

All request and response models use:

    extra="forbid"

Unexpected fields are rejected.

===============================================================================
NORMALIZATION
===============================================================================

Where appropriate:

    username -> lowercase
    email    -> lowercase
    role     -> uppercase

User-controlled textual values are stripped and checked for control
characters.

===============================================================================
PAGINATION
===============================================================================

User Management pagination:

    default page size = 30

Maximum API page size:

    200

Offset pagination:

    limit >= 1
    offset >= 0

User list response:

    users
    total
    total_pages
    limit
    offset

The backend is authoritative for total and total_pages.

Example:

    total = 67
    limit = 30

    total_pages = 3


Individual User Audit pagination:

    default page = 1
    default page size = 30
    maximum page size = 200

Individual User Audit response:

    activities
    total
    limit
    offset
    statistics

Audit statistics are calculated against the COMPLETE filtered
Individual Audit dataset.

They are NOT calculated from the current page.

===============================================================================
DATETIME
===============================================================================

UUID and datetime fields use native Pydantic types.

Timezone-aware datetimes are required where explicitly validated by these
schemas.

===============================================================================
AUDIT
===============================================================================

Audit metadata is untrusted data.

The API response exposes only approved audit fields.

Credential-bearing audit fields must never be serialized into the API
contract.

Individual User Audit filters are intentionally limited to:

    action
    outcome
    target_user_id
    source_ip
    date_from
    date_to
    page
    page_size

There is intentionally NO actor filter.

The requested user is already the audit subject.

There are intentionally NO category/search filters in the Individual
User Audit contract.

Global Audit remains a separate API surface.

===============================================================================
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


# =============================================================================
# Constants
# =============================================================================


MAX_PAGE_SIZE = 200

# Canonical User Management page size.
DEFAULT_USER_PAGE_SIZE = 30

# Canonical Individual User Audit pagination.
DEFAULT_AUDIT_PAGE = 1
DEFAULT_AUDIT_PAGE_SIZE = 30

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 100

MAX_EMAIL_LENGTH = 320

MAX_DISPLAY_NAME_LENGTH = 200

MAX_ROLE_LENGTH = 64

MAX_PASSWORD_LENGTH = 256

MAX_MESSAGE_LENGTH = 500

MAX_SEARCH_LENGTH = 200

MAX_REQUEST_ID_LENGTH = 200

MAX_USER_AGENT_LENGTH = 1000

MAX_IP_ADDRESS_LENGTH = 45

MAX_AUDIT_ACTION_LENGTH = 200

MAX_AUDIT_OUTCOME_LENGTH = 100

MAX_AUDIT_CATEGORY_LENGTH = 100


# =============================================================================
# Base Schema
# =============================================================================


class UserSchemaBase(BaseModel):
    """
    Common configuration for User Management API schemas.

    Security:

        - unknown fields are rejected
        - surrounding whitespace is removed from normal string fields

    Password schemas explicitly validate their own values so password
    whitespace is preserved.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


# =============================================================================
# Validation Helpers
# =============================================================================


def _reject_control_characters(
    value: str,
    *,
    field_name: str,
) -> str:
    """
    Reject ASCII control characters.
    """

    if any(
        ord(char) < 32
        for char in value
    ):
        raise ValueError(
            f"{field_name} contains invalid control characters."
        )

    return value


def _reject_null_character(
    value: str,
    *,
    field_name: str,
) -> str:
    """
    Explicitly reject NULL characters.
    """

    if "\x00" in value:
        raise ValueError(
            f"{field_name} contains an invalid NULL character."
        )

    return value


def _validate_non_empty_string(
    value: str,
    *,
    field_name: str,
) -> str:
    """
    Validate that a string contains meaningful content.
    """

    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            f"{field_name} must be a string."
        )

    value = value.strip()

    if not value:
        raise ValueError(
            f"{field_name} cannot be empty."
        )

    _reject_control_characters(
        value,
        field_name=field_name,
    )

    _reject_null_character(
        value,
        field_name=field_name,
    )

    return value


def _validate_optional_text(
    value: str | None,
    *,
    field_name: str,
    max_length: int,
) -> str | None:
    """
    Validate optional textual input.

    Empty strings are normalized to None.
    """

    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    if len(value) > max_length:
        raise ValueError(
            f"{field_name} is too long."
        )

    _reject_control_characters(
        value,
        field_name=field_name,
    )

    _reject_null_character(
        value,
        field_name=field_name,
    )

    return value


def _normalize_username(
    value: str,
) -> str:
    """
    Normalize username to lowercase.
    """

    value = _validate_non_empty_string(
        value,
        field_name="Username",
    )

    value = value.lower()

    if not (
        MIN_USERNAME_LENGTH
        <= len(value)
        <= MAX_USERNAME_LENGTH
    ):
        raise ValueError(
            "Username must be between "
            f"{MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters."
        )

    return value


def _normalize_role(
    value: str,
) -> str:
    """
    Normalize role to canonical uppercase form.

    Role existence and authorization remain service-layer responsibilities.
    """

    value = _validate_non_empty_string(
        value,
        field_name="Role",
    )

    value = value.upper()

    if len(value) > MAX_ROLE_LENGTH:
        raise ValueError(
            "Role value is too long."
        )

    return value


def _normalize_email(
    value: str,
) -> str:
    """
    Normalize an email address.

    EmailStr performs structural email validation.
    """

    value = _validate_non_empty_string(
        value,
        field_name="Email",
    )

    return value.lower()


def _validate_password(
    value: str,
    *,
    field_name: str,
) -> str:
    """
    Perform API-level password sanity validation.

    The authoritative password policy remains in the password/security
    service.

    Password whitespace is preserved intentionally.
    """

    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            f"{field_name} must be a string."
        )

    if not value:
        raise ValueError(
            f"{field_name} cannot be empty."
        )

    if len(value) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"{field_name} is too long."
        )

    if any(
        ord(char) < 32
        for char in value
    ):
        raise ValueError(
            f"{field_name} contains invalid control characters."
        )

    if "\x00" in value:
        raise ValueError(
            f"{field_name} contains an invalid NULL character."
        )

    return value


def _validate_timezone_aware_datetime(
    value: datetime | None,
    *,
    field_name: str,
) -> datetime | None:
    """
    Require timezone-aware datetime values.

    UTC normalization remains a service/repository responsibility.
    """

    if value is None:
        return None

    if value.tzinfo is None:
        raise ValueError(
            f"{field_name} must be timezone-aware."
        )

    return value


# =============================================================================
# User Response
# =============================================================================


class UserResponse(UserSchemaBase):
    """
    Public-safe user representation.

    NEVER includes:

        - password
        - password_hash
        - token
        - JWT
        - JTI
        - API key
        - secret
        - private key
    """

    user_id: UUID

    username: str = Field(
        min_length=MIN_USERNAME_LENGTH,
        max_length=MAX_USERNAME_LENGTH,
    )

    email: EmailStr = Field(
        max_length=MAX_EMAIL_LENGTH,
    )

    roles: list[str] = Field(
        default_factory=list,
    )

    is_active: bool

    is_locked: bool

    failed_login_count: int = Field(
        ge=0,
    )

    display_name: str | None = Field(
        default=None,
        max_length=MAX_DISPLAY_NAME_LENGTH,
    )

    force_password_change: bool

    password_changed_at: datetime | None = None

    last_login_at: datetime | None = None

    created_at: datetime

    updated_at: datetime

    @field_validator("username")
    @classmethod
    def validate_username(
        cls,
        value: str,
    ) -> str:
        return _normalize_username(
            value,
        )

    @field_validator("email")
    @classmethod
    def normalize_email(
        cls,
        value: EmailStr,
    ) -> EmailStr:
        return _normalize_email(
            str(value),
        )

    @field_validator("roles")
    @classmethod
    def normalize_roles(
        cls,
        value: list[str],
    ) -> list[str]:
        """
        Normalize role names and reject duplicates.
        """

        normalized: list[str] = []
        seen: set[str] = set()

        for role in value:
            normalized_role = _normalize_role(
                role,
            )

            if normalized_role in seen:
                raise ValueError(
                    "Duplicate roles are not allowed."
                )

            seen.add(
                normalized_role,
            )
            normalized.append(
                normalized_role,
            )

        return normalized

    @field_validator("display_name")
    @classmethod
    def validate_display_name(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Display name",
            max_length=MAX_DISPLAY_NAME_LENGTH,
        )


# =============================================================================
# User Detail Response
# =============================================================================


class UserDetailResponse(UserResponse):
    """
    Detailed safe user representation.

    Additional sensitive operational information such as active sessions and
    audit history must be retrieved through dedicated endpoints.
    """

    pass


# =============================================================================
# User List Response
# =============================================================================


class UserListResponse(UserSchemaBase):
    """
    Backend-authoritative paginated user listing response.

    Contract:

        users
        total
        total_pages
        limit
        offset

    The frontend MUST NOT calculate total_pages independently.
    """

    users: list[UserResponse] = Field(
        default_factory=list,
    )

    total: int = Field(
        ge=0,
    )

    total_pages: int = Field(
        ge=0,
    )

    limit: int = Field(
        ge=1,
        le=MAX_PAGE_SIZE,
    )

    offset: int = Field(
        ge=0,
    )

    @model_validator(mode="after")
    def validate_pagination_consistency(
        self,
    ) -> "UserListResponse":
        """
        Validate that backend-provided total_pages matches total/limit.

        The offset is intentionally not constrained against total because
        requesting a page beyond the last page is a valid client request.
        """

        expected_total_pages = (
            (
                self.total
                + self.limit
                - 1
            )
            // self.limit
            if self.total > 0
            else 0
        )

        if self.total_pages != expected_total_pages:
            raise ValueError(
                "total_pages is inconsistent with total and limit."
            )

        return self


# =============================================================================
# User Statistics Response
# =============================================================================


class UserStatisticsResponse(UserSchemaBase):
    """
    User Management dashboard statistics.
    """

    total: int = Field(
        ge=0,
    )

    active: int = Field(
        ge=0,
    )

    disabled: int = Field(
        ge=0,
    )

    locked: int = Field(
        ge=0,
    )

    @model_validator(mode="after")
    def validate_statistics(
        self,
    ) -> "UserStatisticsResponse":
        """
        Validate basic account-state counter consistency.
        """

        if (
            self.active
            + self.disabled
            > self.total
        ):
            raise ValueError(
                "Active and disabled user counts cannot exceed total users."
            )

        if self.locked > self.total:
            raise ValueError(
                "Locked user count cannot exceed total users."
            )

        return self


# =============================================================================
# Create User Request
# =============================================================================


class CreateUserRequest(UserSchemaBase):
    """
    Administrator-provisioned user creation request.

    Plaintext password is transient request data only.

    It must never be:

        - logged
        - audited
        - persisted directly
        - returned
        - included in exception messages
    """

    username: str = Field(
        min_length=MIN_USERNAME_LENGTH,
        max_length=MAX_USERNAME_LENGTH,
    )

    email: EmailStr = Field(
        max_length=MAX_EMAIL_LENGTH,
    )

    password: str = Field(
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
    )

    role: str = Field(
        min_length=1,
        max_length=MAX_ROLE_LENGTH,
    )

    is_active: bool = True

    display_name: str | None = Field(
        default=None,
        max_length=MAX_DISPLAY_NAME_LENGTH,
    )

    @field_validator("username")
    @classmethod
    def normalize_username(
        cls,
        value: str,
    ) -> str:
        return _normalize_username(
            value,
        )

    @field_validator("email")
    @classmethod
    def normalize_email(
        cls,
        value: EmailStr,
    ) -> EmailStr:
        return _normalize_email(
            str(value),
        )

    @field_validator("role")
    @classmethod
    def normalize_role(
        cls,
        value: str,
    ) -> str:
        return _normalize_role(
            value,
        )

    @field_validator("password")
    @classmethod
    def validate_password(
        cls,
        value: str,
    ) -> str:
        return _validate_password(
            value,
            field_name="Password",
        )

    @field_validator("display_name")
    @classmethod
    def validate_display_name(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Display name",
            max_length=MAX_DISPLAY_NAME_LENGTH,
        )


# =============================================================================
# Update User Request
# =============================================================================


class UpdateUserRequest(UserSchemaBase):
    """
    Editable user-profile request.

    Supported fields:

        username
        email
        display_name

    Dedicated schemas must be used for:

        - role changes
        - password changes
        - active-state changes
        - lock-state changes
        - force-password-change state
        - session revocation
    """

    username: str = Field(
        min_length=MIN_USERNAME_LENGTH,
        max_length=MAX_USERNAME_LENGTH,
    )

    email: EmailStr = Field(
        max_length=MAX_EMAIL_LENGTH,
    )

    display_name: str | None = Field(
        default=None,
        max_length=MAX_DISPLAY_NAME_LENGTH,
    )

    @field_validator("username")
    @classmethod
    def normalize_username(
        cls,
        value: str,
    ) -> str:
        return _normalize_username(
            value,
        )

    @field_validator("email")
    @classmethod
    def normalize_email(
        cls,
        value: EmailStr,
    ) -> EmailStr:
        return _normalize_email(
            str(value),
        )

    @field_validator("display_name")
    @classmethod
    def validate_display_name(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Display name",
            max_length=MAX_DISPLAY_NAME_LENGTH,
        )


# =============================================================================
# Change Role Request
# =============================================================================


class ChangeRoleRequest(UserSchemaBase):
    """
    Replace the target user's role.
    """

    role: str = Field(
        min_length=1,
        max_length=MAX_ROLE_LENGTH,
    )

    @field_validator("role")
    @classmethod
    def normalize_role(
        cls,
        value: str,
    ) -> str:
        return _normalize_role(
            value,
        )


# =============================================================================
# Set Active Request
# =============================================================================


class SetActiveRequest(UserSchemaBase):
    """
    Enable or disable an account.
    """

    is_active: bool


# =============================================================================
# Set Locked Request
# =============================================================================


class SetLockedRequest(UserSchemaBase):
    """
    Lock or unlock an account.
    """

    is_locked: bool


# =============================================================================
# Force Password Change Request
# =============================================================================


class SetForcePasswordChangeRequest(UserSchemaBase):
    """
    Set or clear forced-password-change state.
    """

    force_password_change: bool


# =============================================================================
# Reset Password Request
# =============================================================================


class ResetPasswordRequest(UserSchemaBase):
    """
    Password reset/change request.

    Plaintext password is accepted only here and must be passed directly to
    the password hashing service.

    It must never be copied into:

        - audit metadata
        - logs
        - responses
        - repository objects
    """

    new_password: str = Field(
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
    )

    @field_validator("new_password")
    @classmethod
    def validate_new_password(
        cls,
        value: str,
    ) -> str:
        return _validate_password(
            value,
            field_name="New password",
        )


# =============================================================================
# User List Query Parameters
# =============================================================================


class UserListQuery(UserSchemaBase):
    """
    Query parameters for administrative user listing.

    Canonical default:

        30 users per page
    """

    search: str | None = Field(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
    )

    role: str | None = Field(
        default=None,
        max_length=MAX_ROLE_LENGTH,
    )

    is_active: bool | None = None

    is_locked: bool | None = None

    force_password_change: bool | None = None

    created_from: datetime | None = None

    created_to: datetime | None = None

    last_login_from: datetime | None = None

    last_login_to: datetime | None = None

    limit: int = Field(
        default=DEFAULT_USER_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
    )

    offset: int = Field(
        default=0,
        ge=0,
    )

    @field_validator("search")
    @classmethod
    def validate_search(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Search",
            max_length=MAX_SEARCH_LENGTH,
        )

    @field_validator("role")
    @classmethod
    def normalize_role(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return _normalize_role(
            value,
        )

    @field_validator(
        "created_from",
        "created_to",
        "last_login_from",
        "last_login_to",
    )
    @classmethod
    def validate_timestamps(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        return _validate_timezone_aware_datetime(
            value,
            field_name="Date filter",
        )

    @model_validator(mode="after")
    def validate_date_ranges(
        self,
    ) -> "UserListQuery":
        if (
            self.created_from is not None
            and self.created_to is not None
            and self.created_from > self.created_to
        ):
            raise ValueError(
                "created_from must not be later than created_to."
            )

        if (
            self.last_login_from is not None
            and self.last_login_to is not None
            and self.last_login_from > self.last_login_to
        ):
            raise ValueError(
                "last_login_from must not be later than last_login_to."
            )

        return self


# =============================================================================
# Session Response
# =============================================================================


class SessionResponse(UserSchemaBase):
    """
    Safe authentication-session representation.

    SECURITY:

    The following are intentionally excluded:

        - token_id
        - JWT JTI
        - access token
        - refresh token
        - session token
        - JWT
        - secret
        - credential material
    """

    session_id: UUID

    user_id: UUID

    created_at: datetime

    expires_at: datetime

    revoked_at: datetime | None = None

    ip_address: str | None = Field(
        default=None,
        max_length=MAX_IP_ADDRESS_LENGTH,
    )

    user_agent: str | None = Field(
        default=None,
        max_length=MAX_USER_AGENT_LENGTH,
    )

    is_active: bool

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="IP address",
            max_length=MAX_IP_ADDRESS_LENGTH,
        )

    @field_validator("user_agent")
    @classmethod
    def validate_user_agent(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="User agent",
            max_length=MAX_USER_AGENT_LENGTH,
        )

    @model_validator(mode="after")
    def validate_session_dates(
        self,
    ) -> "SessionResponse":
        if self.expires_at <= self.created_at:
            raise ValueError(
                "Session expiration must be later than creation time."
            )

        if (
            self.revoked_at is not None
            and self.revoked_at < self.created_at
        ):
            raise ValueError(
                "Session revocation time cannot precede creation time."
            )

        return self


# =============================================================================
# Session List Response
# =============================================================================


class SessionListResponse(UserSchemaBase):
    """
    Collection of safe active-session representations.
    """

    sessions: list[SessionResponse] = Field(
        default_factory=list,
    )


# =============================================================================
# User Activity Response
# =============================================================================


class UserActivityResponse(UserSchemaBase):
    """
    Safe representation of one audit event associated with a user.

    SECURITY:

    This schema intentionally exposes only approved investigation fields.

    It does NOT expose:

        - password
        - password_hash
        - access token
        - refresh token
        - session token
        - JWT
        - JTI
        - API keys
        - secrets
        - private keys
        - authorization headers
        - cookies
    """

    audit_id: UUID | None = None

    action: str = Field(
        min_length=1,
        max_length=MAX_AUDIT_ACTION_LENGTH,
    )

    outcome: str = Field(
        min_length=1,
        max_length=MAX_AUDIT_OUTCOME_LENGTH,
    )

    category: str | None = Field(
        default=None,
        max_length=MAX_AUDIT_CATEGORY_LENGTH,
    )

    actor_user_id: UUID | None = None

    target_user_id: UUID | None = None

    session_id: UUID | None = None

    request_id: str | None = Field(
        default=None,
        max_length=MAX_REQUEST_ID_LENGTH,
    )

    source_ip: str | None = Field(
        default=None,
        max_length=MAX_IP_ADDRESS_LENGTH,
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )

    timestamp: datetime

    @field_validator("action")
    @classmethod
    def validate_action(
        cls,
        value: str,
    ) -> str:
        return _validate_non_empty_string(
            value,
            field_name="Audit action",
        )

    @field_validator("outcome")
    @classmethod
    def validate_outcome(
        cls,
        value: str,
    ) -> str:
        return _validate_non_empty_string(
            value,
            field_name="Audit outcome",
        )

    @field_validator("category")
    @classmethod
    def validate_category(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Audit category",
            max_length=MAX_AUDIT_CATEGORY_LENGTH,
        )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Request ID",
            max_length=MAX_REQUEST_ID_LENGTH,
        )

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Source IP",
            max_length=MAX_IP_ADDRESS_LENGTH,
        )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Reject obvious credential-bearing metadata.

        AuditService remains the authoritative audit sanitization layer.
        """

        forbidden = {
            "password",
            "password_hash",
            "new_password",
            "current_password",
            "old_password",
            "plaintext_password",
            "passwd",
            "pass",
            "token",
            "access_token",
            "refresh_token",
            "session_token",
            "jwt",
            "jwt_token",
            "jti",
            "token_id",
            "api_key",
            "apikey",
            "secret",
            "client_secret",
            "private_key",
            "authorization",
            "cookie",
            "set_cookie",
            "credential",
            "credentials",
        }

        def normalize_key(
            key: Any,
        ) -> str:
            return (
                str(key)
                .strip()
                .lower()
                .replace("-", "_")
                .replace(" ", "_")
                .replace(".", "_")
                .replace("/", "_")
            )

        def validate_value(
            current: Any,
        ) -> Any:
            if isinstance(
                current,
                dict,
            ):
                result: dict[str, Any] = {}

                for key, nested in current.items():
                    normalized_key = normalize_key(
                        key,
                    )

                    if normalized_key in forbidden:
                        raise ValueError(
                            "Sensitive credential material cannot be "
                            "exposed through audit metadata."
                        )

                    result[str(key)] = validate_value(
                        nested,
                    )

                return result

            if isinstance(
                current,
                list,
            ):
                return [
                    validate_value(item)
                    for item in current
                ]

            if isinstance(
                current,
                tuple,
            ):
                return [
                    validate_value(item)
                    for item in current
                ]

            return current

        result = validate_value(
            value,
        )

        if not isinstance(
            result,
            dict,
        ):
            raise ValueError(
                "Audit metadata must be an object."
            )

        return result


# =============================================================================
# Individual User Audit Statistics
# =============================================================================


class UserAuditStatistics(UserSchemaBase):
    """
    Backend-authoritative statistics for Individual User Audit.

    IMPORTANT:

    These counters represent the COMPLETE filtered audit dataset.

    They are NOT calculated from the current paginated page.

    Example:

        total = 143
        success = 30
        failure = 113
        denied = 0

    When the user moves from page 1 to page 2, these statistics remain
    identical as long as the filters remain identical.

    When an audit filter changes, these statistics change accordingly.
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

    @model_validator(mode="after")
    def validate_statistics(
        self,
    ) -> "UserAuditStatistics":
        """
        Validate basic outcome-counter consistency.

        All returned outcome counters must be non-negative and their
        sum cannot exceed the total.

        The inequality is intentional because the audit system may contain
        outcomes outside the three dashboard categories.
        """

        counted = (
            self.success
            + self.failure
            + self.denied
        )

        if counted > self.total:
            raise ValueError(
                "Audit outcome statistics cannot exceed total audit events."
            )

        return self


# =============================================================================
# User Activity List Response
# =============================================================================


class UserActivityListResponse(UserSchemaBase):
    """
    Paginated Individual User Audit response.

    Contract:

        activities
        total
        limit
        offset
        statistics

    Statistics are backend-authoritative and represent the COMPLETE
    filtered dataset rather than the current page.

    Example:

        {
            "activities": [...],
            "total": 143,
            "limit": 30,
            "offset": 0,
            "statistics": {
                "total": 143,
                "success": 30,
                "failure": 113,
                "denied": 0
            }
        }

    The frontend must NOT calculate Successful/Failed/Denied counts
    from activities.

    The frontend may calculate pagination pages from:

        total
        limit
    """

    activities: list[UserActivityResponse] = Field(
        default_factory=list,
    )

    total: int = Field(
        ge=0,
    )

    limit: int = Field(
        ge=1,
        le=MAX_PAGE_SIZE,
    )

    offset: int = Field(
        ge=0,
    )

    statistics: UserAuditStatistics = Field(
        default_factory=UserAuditStatistics,
    )

    @model_validator(mode="after")
    def validate_statistics_total(
        self,
    ) -> "UserActivityListResponse":
        """
        Ensure the response-level total agrees with statistics.total.

        Both values refer to the same complete filtered dataset.
        """

        if self.statistics.total != self.total:
            raise ValueError(
                "Audit statistics.total must match response total."
            )

        return self


# =============================================================================
# Individual User Audit Query
# =============================================================================


class UserAuditQuery(UserSchemaBase):
    """
    Query parameters for Individual User Audit history.

    LOCKED CONTRACT:

        action
        outcome
        target_user_id
        source_ip
        date_from
        date_to
        page
        page_size

    Intentionally NOT supported here:

        actor_user_id
        category
        search

    Reason:

        The requested user is already the audit subject.

    Global Audit remains responsible for broader actor/category/search
    filtering.
    """

    action: str | None = Field(
        default=None,
        max_length=MAX_AUDIT_ACTION_LENGTH,
    )

    outcome: str | None = Field(
        default=None,
        max_length=MAX_AUDIT_OUTCOME_LENGTH,
    )

    target_user_id: UUID | None = None

    source_ip: str | None = Field(
        default=None,
        max_length=MAX_IP_ADDRESS_LENGTH,
    )

    date_from: datetime | None = None

    date_to: datetime | None = None

    page: int = Field(
        default=DEFAULT_AUDIT_PAGE,
        ge=1,
    )

    page_size: int = Field(
        default=DEFAULT_AUDIT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
    )

    @field_validator("action")
    @classmethod
    def validate_action(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Audit action",
            max_length=MAX_AUDIT_ACTION_LENGTH,
        )

    @field_validator("outcome")
    @classmethod
    def validate_outcome(
        cls,
        value: str | None,
    ) -> str | None:
        value = _validate_optional_text(
            value,
            field_name="Audit outcome",
            max_length=MAX_AUDIT_OUTCOME_LENGTH,
        )

        if value is None:
            return None

        return value.lower()

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(
        cls,
        value: str | None,
    ) -> str | None:
        return _validate_optional_text(
            value,
            field_name="Source IP",
            max_length=MAX_IP_ADDRESS_LENGTH,
        )

    @field_validator(
        "date_from",
        "date_to",
    )
    @classmethod
    def validate_dates(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        return _validate_timezone_aware_datetime(
            value,
            field_name="Audit date",
        )

    @model_validator(mode="after")
    def validate_date_range(
        self,
    ) -> "UserAuditQuery":
        if (
            self.date_from is not None
            and self.date_to is not None
            and self.date_from > self.date_to
        ):
            raise ValueError(
                "date_from must not be later than date_to."
            )

        return self


# =============================================================================
# Generic Mutation Response
# =============================================================================


class UserMutationResponse(UserSchemaBase):
    """
    Generic successful mutation response.
    """

    success: bool = True

    message: str = Field(
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
    )

    @field_validator("message")
    @classmethod
    def validate_message(
        cls,
        value: str,
    ) -> str:
        return _validate_non_empty_string(
            value,
            field_name="Message",
        )


# =============================================================================
# Revoke Sessions Response
# =============================================================================


class RevokeSessionsResponse(UserSchemaBase):
    """
    Result of revoking active sessions.
    """

    success: bool = True

    message: str = Field(
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
    )

    revoked_count: int = Field(
        ge=0,
    )

    @field_validator("message")
    @classmethod
    def validate_message(
        cls,
        value: str,
    ) -> str:
        return _validate_non_empty_string(
            value,
            field_name="Message",
        )


# =============================================================================
# Reset Password Response
# =============================================================================


class ResetPasswordResponse(UserSchemaBase):
    """
    Result of a password reset/change.

    No password or password hash is returned.
    """

    success: bool = True

    message: str = Field(
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
    )

    sessions_revoked: int = Field(
        ge=0,
    )

    @field_validator("message")
    @classmethod
    def validate_message(
        cls,
        value: str,
    ) -> str:
        return _validate_non_empty_string(
            value,
            field_name="Message",
        )


# =============================================================================
# Delete User Response
# =============================================================================


class DeleteUserResponse(UserSchemaBase):
    """
    Restricted user deletion response.

    Business/security decisions remain in UserManagementService.
    """

    success: bool = True

    message: str = Field(
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
    )

    @field_validator("message")
    @classmethod
    def validate_message(
        cls,
        value: str,
    ) -> str:
        return _validate_non_empty_string(
            value,
            field_name="Message",
        )


# =============================================================================
# Public Exports
# =============================================================================


__all__ = [
    # Base
    "UserSchemaBase",

    # Constants
    "MAX_PAGE_SIZE",
    "DEFAULT_USER_PAGE_SIZE",
    "DEFAULT_AUDIT_PAGE",
    "DEFAULT_AUDIT_PAGE_SIZE",

    # User responses
    "UserResponse",
    "UserDetailResponse",
    "UserListResponse",
    "UserStatisticsResponse",

    # User requests
    "CreateUserRequest",
    "UpdateUserRequest",
    "ChangeRoleRequest",
    "SetActiveRequest",
    "SetLockedRequest",
    "SetForcePasswordChangeRequest",
    "ResetPasswordRequest",

    # User queries
    "UserListQuery",
    "UserAuditQuery",

    # Session responses
    "SessionResponse",
    "SessionListResponse",

    # Audit responses
    "UserActivityResponse",
    "UserAuditStatistics",
    "UserActivityListResponse",

    # Mutation responses
    "UserMutationResponse",
    "RevokeSessionsResponse",
    "ResetPasswordResponse",
    "DeleteUserResponse",
]