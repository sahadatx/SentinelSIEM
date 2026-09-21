from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)


# ============================================================================
# Constants
# ============================================================================

# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 30
MAX_PAGE_SIZE = 30


# ---------------------------------------------------------------------------
# Asset Types
# ---------------------------------------------------------------------------

ASSET_TYPES = (
    "SERVER",
    "WORKSTATION",
    "LAPTOP",
    "DESKTOP",
    "NETWORK_DEVICE",
    "ROUTER",
    "SWITCH",
    "FIREWALL",
    "LOAD_BALANCER",
    "DATABASE",
    "WEB_SERVER",
    "APPLICATION_SERVER",
    "MAIL_SERVER",
    "DNS_SERVER",
    "PROXY_SERVER",
    "VIRTUAL_MACHINE",
    "CONTAINER",
    "CLOUD_RESOURCE",
    "STORAGE",
    "IOT_DEVICE",
    "SECURITY_APPLIANCE",
    "OTHER",
)


# ---------------------------------------------------------------------------
# Lifecycle Status
# ---------------------------------------------------------------------------

LIFECYCLE_STATUSES = (
    "ENABLED",
    "DISABLED",
)


# ---------------------------------------------------------------------------
# Operational Status
# ---------------------------------------------------------------------------

OPERATIONAL_STATUSES = (
    "ONLINE",
    "OFFLINE",
    "UNKNOWN",
    "MAINTENANCE",
)


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------

RISK_LEVELS = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
)


# ---------------------------------------------------------------------------
# Operating Systems
# ---------------------------------------------------------------------------

OPERATING_SYSTEMS = (
    "WINDOWS",
    "WINDOWS_SERVER",
    "LINUX",
    "UBUNTU",
    "DEBIAN",
    "CENTOS",
    "RHEL",
    "FEDORA",
    "ROCKY_LINUX",
    "ALMALINUX",
    "KALI_LINUX",
    "MACOS",
    "FREEBSD",
    "ANDROID",
    "IOS",
    "NETWORK_OS",
    "OTHER",
)


# ---------------------------------------------------------------------------
# Environments
# ---------------------------------------------------------------------------

ENVIRONMENTS = (
    "PRODUCTION",
    "STAGING",
    "DEVELOPMENT",
    "TESTING",
    "QA",
    "UAT",
    "DISASTER_RECOVERY",
    "OTHER",
)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_LIFECYCLE_STATUS = "ENABLED"
DEFAULT_OPERATIONAL_STATUS = "UNKNOWN"
DEFAULT_RISK = "INFORMATIONAL"


# ============================================================================
# Type Aliases
# ============================================================================

AssetLifecycleStatus = Literal[
    "ENABLED",
    "DISABLED",
]

AssetOperationalStatus = Literal[
    "ONLINE",
    "OFFLINE",
    "UNKNOWN",
    "MAINTENANCE",
]

AssetRisk = Literal[
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
]


# ============================================================================
# Base Schema
# ============================================================================


class AssetBase(BaseModel):
    """
    Shared asset fields.

    This schema represents fields that are common to asset creation
    and the general asset representation.

    Lifecycle status is intentionally excluded from this schema because
    ENABLE/DISABLE is a dedicated lifecycle operation.

    Operational status is also excluded from create/update payloads because
    it represents the observed operational state of the asset rather than
    an administrative lifecycle action.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable asset name.",
    )

    asset_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Asset category or type.",
    )

    # ------------------------------------------------------------------------
    # Network identity
    # ------------------------------------------------------------------------

    hostname: str | None = Field(
        default=None,
        max_length=255,
        description="Asset hostname.",
    )

    ip_address: IPvAnyAddress | None = Field(
        default=None,
        description="Primary IPv4 or IPv6 address.",
    )

    mac_address: str | None = Field(
        default=None,
        max_length=64,
        description="Asset MAC address.",
    )

    # ------------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------------

    operating_system: str | None = Field(
        default=None,
        max_length=128,
        description="Operating system.",
    )

    environment: str | None = Field(
        default=None,
        max_length=64,
        description="Deployment environment.",
    )

    # ------------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------------

    risk: AssetRisk = Field(
        default=DEFAULT_RISK,
        description="Current asset risk level.",
    )

    # ------------------------------------------------------------------------
    # Ownership
    # ------------------------------------------------------------------------

    owner: str | None = Field(
        default=None,
        max_length=255,
        description="Asset owner.",
    )

    # ------------------------------------------------------------------------
    # Location
    # ------------------------------------------------------------------------

    location: str | None = Field(
        default=None,
        max_length=255,
        description="Physical or logical asset location.",
    )

    # ------------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------------

    tags: list[str] = Field(
        default_factory=list,
        description="Asset classification and operational tags.",
    )

    # ------------------------------------------------------------------------
    # Description
    # ------------------------------------------------------------------------

    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Human-readable asset description.",
    )

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices(
            "metadata",
            "asset_metadata",
        ),
        serialization_alias="metadata",
        description="Additional structured asset metadata.",
    )

    # ------------------------------------------------------------------------
    # Name validation
    # ------------------------------------------------------------------------

    @field_validator(
        "name",
        "asset_type",
    )
    @classmethod
    def validate_required_text(
        cls,
        value: str,
    ) -> str:
        """
        Validate required textual fields.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Value must not be empty."
            )

        return value

    # ------------------------------------------------------------------------
    # Asset type
    # ------------------------------------------------------------------------

    @field_validator("asset_type")
    @classmethod
    def validate_asset_type(
        cls,
        value: str,
    ) -> str:
        """
        Normalize and validate the asset type.
        """

        value = value.strip().upper()

        if value not in ASSET_TYPES:
            allowed = ", ".join(ASSET_TYPES)

            raise ValueError(
                f"Invalid asset type. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Optional text
    # ------------------------------------------------------------------------

    @field_validator(
        "hostname",
        "operating_system",
        "environment",
        "owner",
        "location",
        "description",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize optional textual fields.

        Empty strings become None.
        """

        if value is None:
            return None

        value = value.strip()

        return value or None

    # ------------------------------------------------------------------------
    # Operating system
    # ------------------------------------------------------------------------

    @field_validator("operating_system")
    @classmethod
    def validate_operating_system(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate the operating system when supplied.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if value not in OPERATING_SYSTEMS:
            allowed = ", ".join(OPERATING_SYSTEMS)

            raise ValueError(
                f"Invalid operating system. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------------

    @field_validator("environment")
    @classmethod
    def validate_environment(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate environment when supplied.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if value not in ENVIRONMENTS:
            allowed = ", ".join(ENVIRONMENTS)

            raise ValueError(
                f"Invalid environment. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Risk
    # ------------------------------------------------------------------------

    @field_validator("risk")
    @classmethod
    def validate_risk(
        cls,
        value: str,
    ) -> str:
        """
        Normalize and validate risk.
        """

        value = value.strip().upper()

        if value not in RISK_LEVELS:
            allowed = ", ".join(RISK_LEVELS)

            raise ValueError(
                f"Invalid asset risk. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # MAC address
    # ------------------------------------------------------------------------

    @field_validator("mac_address")
    @classmethod
    def normalize_mac_address(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize MAC address formatting.

        The API accepts common MAC address representations while
        preserving a normalized colon-separated representation.
        """

        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        compact = (
            value
            .replace(":", "")
            .replace("-", "")
            .replace(".", "")
            .upper()
        )

        if len(compact) != 12:
            raise ValueError(
                "Invalid MAC address."
            )

        if not all(
            character in "0123456789ABCDEF"
            for character in compact
        ):
            raise ValueError(
                "Invalid MAC address."
            )

        return ":".join(
            compact[index:index + 2]
            for index in range(0, 12, 2)
        )

    # ------------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------------

    @field_validator("tags")
    @classmethod
    def validate_tags(
        cls,
        value: list[str],
    ) -> list[str]:
        """
        Normalize and validate asset tags.
        """

        normalized: list[str] = []

        for tag in value:
            tag = tag.strip()

            if not tag:
                continue

            if len(tag) > 100:
                raise ValueError(
                    "Each asset tag must not exceed 100 characters."
                )

            normalized.append(tag)

        # Preserve order while removing duplicates.
        return list(dict.fromkeys(normalized))

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    @field_validator("metadata")
    @classmethod
    def validate_metadata(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Ensure metadata is represented by a dictionary.
        """

        return dict(value)


# ============================================================================
# Create
# ============================================================================


class AssetCreate(AssetBase):
    """
    Request schema for creating an asset.

    New assets are created as:

        lifecycle_status = ENABLED
        operational_status = UNKNOWN

    Lifecycle changes are performed through the dedicated status endpoint.
    """

    pass


# ============================================================================
# Update
# ============================================================================


class AssetUpdate(BaseModel):
    """
    Partial asset update request.

    Lifecycle status is intentionally NOT accepted here.

    ENABLE/DISABLE must use the dedicated lifecycle endpoint:

        PATCH /assets/{asset_id}/status

    This keeps normal asset information updates separate from lifecycle
    state transitions.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Human-readable asset name.",
    )

    asset_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Asset category or type.",
    )

    # ------------------------------------------------------------------------
    # Network identity
    # ------------------------------------------------------------------------

    hostname: str | None = Field(
        default=None,
        max_length=255,
        description="Asset hostname.",
    )

    ip_address: IPvAnyAddress | None = Field(
        default=None,
        description="Primary IPv4 or IPv6 address.",
    )

    mac_address: str | None = Field(
        default=None,
        max_length=64,
        description="Asset MAC address.",
    )

    # ------------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------------

    operating_system: str | None = Field(
        default=None,
        max_length=128,
        description="Operating system.",
    )

    environment: str | None = Field(
        default=None,
        max_length=64,
        description="Deployment environment.",
    )

    # ------------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------------

    risk: AssetRisk | None = Field(
        default=None,
        description="Current asset risk level.",
    )

    # ------------------------------------------------------------------------
    # Ownership
    # ------------------------------------------------------------------------

    owner: str | None = Field(
        default=None,
        max_length=255,
        description="Asset owner.",
    )

    # ------------------------------------------------------------------------
    # Location
    # ------------------------------------------------------------------------

    location: str | None = Field(
        default=None,
        max_length=255,
        description="Physical or logical asset location.",
    )

    # ------------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------------

    tags: list[str] | None = Field(
        default=None,
        description="Asset classification and operational tags.",
    )

    # ------------------------------------------------------------------------
    # Description
    # ------------------------------------------------------------------------

    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Human-readable asset description.",
    )

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "metadata",
            "asset_metadata",
        ),
        serialization_alias="metadata",
        description="Additional structured asset metadata.",
    )

    # ------------------------------------------------------------------------
    # Name validation
    # ------------------------------------------------------------------------

    @field_validator(
        "name",
        "asset_type",
    )
    @classmethod
    def validate_required_update_text(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Validate required fields when supplied.
        """

        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError(
                "Value must not be empty."
            )

        return value

    # ------------------------------------------------------------------------
    # Asset type
    # ------------------------------------------------------------------------

    @field_validator("asset_type")
    @classmethod
    def validate_update_asset_type(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate asset type when supplied.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if value not in ASSET_TYPES:
            allowed = ", ".join(ASSET_TYPES)

            raise ValueError(
                f"Invalid asset type. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Optional text
    # ------------------------------------------------------------------------

    @field_validator(
        "hostname",
        "operating_system",
        "environment",
        "owner",
        "location",
        "description",
    )
    @classmethod
    def normalize_optional_update_text(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize optional update text.

        Empty strings become None.
        """

        if value is None:
            return None

        value = value.strip()

        return value or None

    # ------------------------------------------------------------------------
    # Operating system
    # ------------------------------------------------------------------------

    @field_validator("operating_system")
    @classmethod
    def validate_update_operating_system(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate operating system when supplied.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if value not in OPERATING_SYSTEMS:
            allowed = ", ".join(OPERATING_SYSTEMS)

            raise ValueError(
                f"Invalid operating system. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------------

    @field_validator("environment")
    @classmethod
    def validate_update_environment(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate environment when supplied.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if value not in ENVIRONMENTS:
            allowed = ", ".join(ENVIRONMENTS)

            raise ValueError(
                f"Invalid environment. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Risk
    # ------------------------------------------------------------------------

    @field_validator("risk")
    @classmethod
    def validate_update_risk(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate risk when supplied.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if value not in RISK_LEVELS:
            allowed = ", ".join(RISK_LEVELS)

            raise ValueError(
                f"Invalid asset risk. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # MAC address
    # ------------------------------------------------------------------------

    @field_validator("mac_address")
    @classmethod
    def normalize_update_mac_address(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize MAC address formatting when supplied.
        """

        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        compact = (
            value
            .replace(":", "")
            .replace("-", "")
            .replace(".", "")
            .upper()
        )

        if len(compact) != 12:
            raise ValueError(
                "Invalid MAC address."
            )

        if not all(
            character in "0123456789ABCDEF"
            for character in compact
        ):
            raise ValueError(
                "Invalid MAC address."
            )

        return ":".join(
            compact[index:index + 2]
            for index in range(0, 12, 2)
        )

    # ------------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------------

    @field_validator("tags")
    @classmethod
    def validate_update_tags(
        cls,
        value: list[str] | None,
    ) -> list[str] | None:
        """
        Normalize and validate tags when supplied.
        """

        if value is None:
            return None

        normalized: list[str] = []

        for tag in value:
            tag = tag.strip()

            if not tag:
                continue

            if len(tag) > 100:
                raise ValueError(
                    "Each asset tag must not exceed 100 characters."
                )

            normalized.append(tag)

        return list(dict.fromkeys(normalized))

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    @field_validator("metadata")
    @classmethod
    def validate_update_metadata(
        cls,
        value: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """
        Ensure metadata is a dictionary when supplied.
        """

        if value is None:
            return None

        return dict(value)

    # ------------------------------------------------------------------------
    # Empty PATCH protection
    # ------------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_at_least_one_field(
        self,
    ) -> "AssetUpdate":
        """
        Reject an empty PATCH body.

        Explicitly supplied null values count as supplied fields.
        """

        if not self.model_fields_set:
            raise ValueError(
                "At least one asset field must be provided."
            )

        return self

    # ------------------------------------------------------------------------
    # Field-presence helper
    # ------------------------------------------------------------------------

    def provided_fields(self) -> set[str]:
        """
        Return fields explicitly supplied by the caller.
        """

        return set(self.model_fields_set)


# ============================================================================
# Asset Status Update
# ============================================================================


class AssetStatusUpdate(BaseModel):
    """
    Dedicated lifecycle status update request.

    Only lifecycle status can be changed through this schema.

    Allowed values:

        ENABLED
        DISABLED
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    lifecycle_status: AssetLifecycleStatus = Field(
        ...,
        description="Target asset lifecycle status.",
    )

    @field_validator("lifecycle_status")
    @classmethod
    def validate_lifecycle_status(
        cls,
        value: str,
    ) -> str:
        """
        Normalize and validate lifecycle status.
        """

        value = value.strip().upper()

        if value not in LIFECYCLE_STATUSES:
            allowed = ", ".join(LIFECYCLE_STATUSES)

            raise ValueError(
                f"Invalid lifecycle status. "
                f"Allowed values: {allowed}."
            )

        return value


# ============================================================================
# Response
# ============================================================================


class AssetResponse(BaseModel):
    """
    Complete API representation of an asset.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    asset_id: UUID

    name: str

    asset_type: str

    # ------------------------------------------------------------------------
    # Network identity
    # ------------------------------------------------------------------------

    hostname: str | None = None

    ip_address: str | None = None

    mac_address: str | None = None

    # ------------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------------

    operating_system: str | None = None

    environment: str | None = None

    # ------------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------------

    risk: AssetRisk

    # ------------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------------

    lifecycle_status: AssetLifecycleStatus

    # ------------------------------------------------------------------------
    # Operational state
    # ------------------------------------------------------------------------

    operational_status: AssetOperationalStatus

    # ------------------------------------------------------------------------
    # Ownership / location
    # ------------------------------------------------------------------------

    owner: str | None = None

    location: str | None = None

    # ------------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------------

    tags: list[str] = Field(
        default_factory=list,
    )

    # ------------------------------------------------------------------------
    # Description
    # ------------------------------------------------------------------------

    description: str | None = None

    # ------------------------------------------------------------------------
    # Metadata
    #
    # SQLAlchemy attribute:
    #     asset_metadata
    #
    # Public API field:
    #     metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices(
            "metadata",
            "asset_metadata",
        ),
        serialization_alias="metadata",
    )

    # ------------------------------------------------------------------------
    # Discovery timestamps
    # ------------------------------------------------------------------------

    first_seen: datetime | None = None

    last_seen: datetime | None = None

    # ------------------------------------------------------------------------
    # Record timestamps
    # ------------------------------------------------------------------------

    created_at: datetime

    updated_at: datetime


# ============================================================================
# List Query
# ============================================================================


class AssetListQuery(BaseModel):
    """
    Query parameters for the Asset Inventory endpoint.

    The frontend uses five filters:

        Asset Type
        Status
        Risk
        OS
        Environment

    Search is limited to:

        Asset Name
        Hostname
        IP Address
        MAC Address
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    # ------------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------------

    search: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "Search asset name, hostname, IP address, "
            "or MAC address."
        ),
    )

    # ------------------------------------------------------------------------
    # Asset Type
    # ------------------------------------------------------------------------

    asset_type: str | None = Field(
        default=None,
        max_length=64,
        description="Filter by asset type.",
    )

    # ------------------------------------------------------------------------
    # Status
    #
    # This filter accepts either lifecycle or operational status.
    #
    # Lifecycle:
    #     ENABLED / DISABLED
    #
    # Operational:
    #     ONLINE / OFFLINE / UNKNOWN / MAINTENANCE
    # ------------------------------------------------------------------------

    status: str | None = Field(
        default=None,
        description=(
            "Filter by lifecycle or operational asset status."
        ),
    )

    # ------------------------------------------------------------------------
    # Risk
    # ------------------------------------------------------------------------

    risk: str | None = Field(
        default=None,
        description="Filter by asset risk.",
    )

    # ------------------------------------------------------------------------
    # Operating System
    # ------------------------------------------------------------------------

    os: str | None = Field(
        default=None,
        max_length=128,
        description="Filter by operating system.",
    )

    # ------------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------------

    environment: str | None = Field(
        default=None,
        max_length=64,
        description="Filter by deployment environment.",
    )

    # ------------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------------

    page: int = Field(
        default=DEFAULT_PAGE,
        ge=1,
        description="One-based page number.",
    )

    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Number of assets returned per page.",
    )

    # ------------------------------------------------------------------------
    # Search normalization
    # ------------------------------------------------------------------------

    @field_validator("search")
    @classmethod
    def normalize_search(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize search text.
        """

        if value is None:
            return None

        value = value.strip()

        return value or None

    # ------------------------------------------------------------------------
    # Asset type normalization
    # ------------------------------------------------------------------------

    @field_validator("asset_type")
    @classmethod
    def validate_filter_asset_type(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate asset type filter.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if not value:
            return None

        if value not in ASSET_TYPES:
            allowed = ", ".join(ASSET_TYPES)

            raise ValueError(
                f"Invalid asset type filter. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Status normalization
    # ------------------------------------------------------------------------

    @field_validator("status")
    @classmethod
    def validate_status_filter(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate lifecycle/operational status filter.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if not value:
            return None

        allowed_statuses = (
            *LIFECYCLE_STATUSES,
            *OPERATIONAL_STATUSES,
        )

        if value not in allowed_statuses:
            allowed = ", ".join(allowed_statuses)

            raise ValueError(
                f"Invalid asset status filter. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Risk normalization
    # ------------------------------------------------------------------------

    @field_validator("risk")
    @classmethod
    def validate_risk_filter(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate risk filter.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if not value:
            return None

        if value not in RISK_LEVELS:
            allowed = ", ".join(RISK_LEVELS)

            raise ValueError(
                f"Invalid risk filter. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Operating system normalization
    # ------------------------------------------------------------------------

    @field_validator("os")
    @classmethod
    def validate_os_filter(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate OS filter.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if not value:
            return None

        if value not in OPERATING_SYSTEMS:
            allowed = ", ".join(OPERATING_SYSTEMS)

            raise ValueError(
                f"Invalid operating system filter. "
                f"Allowed values: {allowed}."
            )

        return value

    # ------------------------------------------------------------------------
    # Environment normalization
    # ------------------------------------------------------------------------

    @field_validator("environment")
    @classmethod
    def validate_environment_filter(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate environment filter.
        """

        if value is None:
            return None

        value = value.strip().upper()

        if not value:
            return None

        if value not in ENVIRONMENTS:
            allowed = ", ".join(ENVIRONMENTS)

            raise ValueError(
                f"Invalid environment filter. "
                f"Allowed values: {allowed}."
            )

        return value


# ============================================================================
# List Response
# ============================================================================


class AssetListResponse(BaseModel):
    """
    Paginated Asset Inventory response.

    Pagination is intentionally page-based:

        page
        page_size
        total
        total_pages

    The frontend displays only Previous / Next controls.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    items: list[AssetResponse]

    total: int = Field(
        ge=0,
        description="Total number of matching assets.",
    )

    page: int = Field(
        ge=1,
        description="Current one-based page.",
    )

    page_size: int = Field(
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Number of assets per page.",
    )

    total_pages: int = Field(
        ge=0,
        description="Total number of available pages.",
    )

    # ------------------------------------------------------------------------
    # Consistency validation
    # ------------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_pagination_consistency(
        self,
    ) -> "AssetListResponse":
        """
        Ensure pagination metadata is internally consistent.
        """

        if self.total == 0:
            expected_total_pages = 0
        else:
            expected_total_pages = (
                self.total + self.page_size - 1
            ) // self.page_size

        if self.total_pages != expected_total_pages:
            raise ValueError(
                "Invalid pagination metadata: "
                "total_pages does not match total and page_size."
            )

        if self.total_pages > 0 and self.page > self.total_pages:
            raise ValueError(
                "Invalid pagination metadata: "
                "page exceeds total_pages."
            )

        if self.total == 0 and self.page != 1:
            raise ValueError(
                "Empty asset results must use page 1."
            )

        return self


# ============================================================================
# Statistics
# ============================================================================


class AssetStatisticsResponse(BaseModel):
    """
    Asset Inventory summary statistics.

    Dashboard cards:

        Total Assets
        Enabled
        Disabled
        Critical Risk
    """

    total: int = Field(
        ge=0,
        description="Total number of assets.",
    )

    enabled: int = Field(
        ge=0,
        description="Number of enabled assets.",
    )

    disabled: int = Field(
        ge=0,
        description="Number of disabled assets.",
    )

    critical: int = Field(
        ge=0,
        description="Number of critical-risk assets.",
    )

    # ------------------------------------------------------------------------
    # Optional detailed distributions
    # ------------------------------------------------------------------------

    by_type: dict[str, int] = Field(
        default_factory=dict,
        description="Asset counts grouped by type.",
    )

    by_risk: dict[str, int] = Field(
        default_factory=dict,
        description="Asset counts grouped by risk.",
    )

    by_lifecycle_status: dict[str, int] = Field(
        default_factory=dict,
        description="Asset counts grouped by lifecycle status.",
    )

    by_operational_status: dict[str, int] = Field(
        default_factory=dict,
        description="Asset counts grouped by operational status.",
    )

    # ------------------------------------------------------------------------
    # Consistency validation
    # ------------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_statistics(
        self,
    ) -> "AssetStatisticsResponse":
        """
        Validate the primary summary counters.
        """

        if self.enabled + self.disabled != self.total:
            raise ValueError(
                "Enabled and disabled asset counts "
                "must equal total assets."
            )

        if self.critical > self.total:
            raise ValueError(
                "Critical asset count cannot exceed total assets."
            )

        return self


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    # Constants
    "ASSET_TYPES",
    "LIFECYCLE_STATUSES",
    "OPERATIONAL_STATUSES",
    "RISK_LEVELS",
    "OPERATING_SYSTEMS",
    "ENVIRONMENTS",
    "DEFAULT_PAGE",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "DEFAULT_LIFECYCLE_STATUS",
    "DEFAULT_OPERATIONAL_STATUS",
    "DEFAULT_RISK",

    # Type aliases
    "AssetLifecycleStatus",
    "AssetOperationalStatus",
    "AssetRisk",

    # Schemas
    "AssetBase",
    "AssetCreate",
    "AssetUpdate",
    "AssetStatusUpdate",
    "AssetResponse",
    "AssetListQuery",
    "AssetListResponse",
    "AssetStatisticsResponse",
]