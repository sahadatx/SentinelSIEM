from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


# ============================================================================
# Base
# ============================================================================


class Base(DeclarativeBase):
    """
    Base class for all SentinelSIEM PostgreSQL ORM models.
    """

    pass


# ============================================================================
# Generic Storage
# ============================================================================


class StorageRecord(Base):
    """
    Generic structured storage boundary.
    """

    __tablename__ = "storage_records"

    entity_type: Mapped[str] = mapped_column(
        String(100),
        primary_key=True,
    )

    entity_id: Mapped[str] = mapped_column(
        String(255),
        primary_key=True,
    )

    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        onupdate=lambda: datetime.now(UTC),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )


Index(
    "idx_storage_records_entity_type",
    StorageRecord.entity_type,
)


# ============================================================================
# Users
# ============================================================================


class AuthUser(Base):
    """
    SentinelSIEM authenticated user.
    """

    __tablename__ = "siem_users"

    __table_args__ = (
        UniqueConstraint(
            "username",
            name="uq_siem_users_username",
        ),
        UniqueConstraint(
            "email",
            name="uq_siem_users_email",
        ),
    )

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
    )

    username: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("TRUE"),
        nullable=False,
    )

    is_locked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("FALSE"),
        nullable=False,
    )

    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    display_name: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )

    force_password_change: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("FALSE"),
        nullable=False,
    )

    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        onupdate=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )


Index(
    "ix_siem_users_active",
    AuthUser.is_active,
)

Index(
    "ix_siem_users_display_name",
    AuthUser.display_name,
)

Index(
    "ix_siem_users_locked",
    AuthUser.is_locked,
)

Index(
    "ix_siem_users_last_login",
    AuthUser.last_login_at.desc(),
)


# ============================================================================
# Roles
# ============================================================================


class AuthRole(Base):
    """
    SentinelSIEM RBAC role.
    """

    __tablename__ = "siem_roles"

    role_name: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    description: Mapped[str] = mapped_column(
        String(255),
        default="",
        server_default=text("''"),
        nullable=False,
    )


# ============================================================================
# Permissions
# ============================================================================


class AuthPermission(Base):
    """
    SentinelSIEM RBAC permission.
    """

    __tablename__ = "siem_permissions"

    permission_name: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
    )

    description: Mapped[str] = mapped_column(
        String(255),
        default="",
        server_default=text("''"),
        nullable=False,
    )


# ============================================================================
# User Roles
# ============================================================================


class AuthUserRole(Base):
    """
    User-to-role association.
    """

    __tablename__ = "siem_user_roles"

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    role_name: Mapped[str] = mapped_column(
        String(64),
        ForeignKey(
            "siem_roles.role_name",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )


# ============================================================================
# Role Permissions
# ============================================================================


class AuthRolePermission(Base):
    """
    Role-to-permission association.
    """

    __tablename__ = "siem_role_permissions"

    role_name: Mapped[str] = mapped_column(
        String(64),
        ForeignKey(
            "siem_roles.role_name",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    permission_name: Mapped[str] = mapped_column(
        String(128),
        ForeignKey(
            "siem_permissions.permission_name",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )


# ============================================================================
# Sessions
# ============================================================================


class AuthSession(Base):
    """
    Authenticated user session.
    """

    __tablename__ = "siem_sessions"

    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
    )

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    token_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )


# ============================================================================
# Authentication Audit
# ============================================================================


class AuthAudit(Base):
    """
    Authentication and user-management audit event.

    This remains the canonical audit storage boundary used by the
    existing SentinelSIEM audit architecture.
    """

    __tablename__ = "siem_auth_audit"

    audit_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    actor_user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    target_user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    session_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
    )

    request_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
    )

    audit_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )


Index(
    "ix_siem_auth_audit_created_at",
    AuthAudit.created_at.desc(),
)

Index(
    "ix_siem_auth_audit_action_created",
    AuthAudit.action,
    AuthAudit.created_at.desc(),
)

Index(
    "ix_siem_auth_audit_actor_created",
    AuthAudit.actor_user_id,
    AuthAudit.created_at.desc(),
)

Index(
    "ix_siem_auth_audit_target_created",
    AuthAudit.target_user_id,
    AuthAudit.created_at.desc(),
)


# ============================================================================
# Assets
# ============================================================================


class Asset(Base):
    """
    SentinelSIEM managed security asset.

    Asset lifecycle and operational state are intentionally separated.

    lifecycle_status:
        ENABLED / DISABLED

    operational_status:
        ONLINE / OFFLINE / UNKNOWN / MAINTENANCE
    """

    __tablename__ = "siem_assets"

    __table_args__ = (
        CheckConstraint(
            "length(trim(name)) > 0",
            name="ck_siem_assets_name_not_empty",
        ),

        CheckConstraint(
            "length(trim(asset_type)) > 0",
            name="ck_siem_assets_asset_type_not_empty",
        ),

        CheckConstraint(
            "lifecycle_status IN ('ENABLED', 'DISABLED')",
            name="ck_siem_assets_lifecycle_status_valid",
        ),

        CheckConstraint(
            """
            operational_status IN (
                'ONLINE',
                'OFFLINE',
                'UNKNOWN',
                'MAINTENANCE'
            )
            """,
            name="ck_siem_assets_operational_status_valid",
        ),

        CheckConstraint(
            """
            risk IN (
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW',
                'INFORMATIONAL'
            )
            """,
            name="ck_siem_assets_risk_valid",
        ),

        CheckConstraint(
            "hostname IS NULL OR length(trim(hostname)) > 0",
            name="ck_siem_assets_hostname_not_empty",
        ),

        CheckConstraint(
            "mac_address IS NULL OR length(trim(mac_address)) > 0",
            name="ck_siem_assets_mac_not_empty",
        ),

        CheckConstraint(
            "operating_system IS NULL OR length(trim(operating_system)) > 0",
            name="ck_siem_assets_os_not_empty",
        ),

        CheckConstraint(
            "environment IS NULL OR length(trim(environment)) > 0",
            name="ck_siem_assets_environment_not_empty",
        ),

        CheckConstraint(
            "owner IS NULL OR length(trim(owner)) > 0",
            name="ck_siem_assets_owner_not_empty",
        ),

        CheckConstraint(
            "location IS NULL OR length(trim(location)) > 0",
            name="ck_siem_assets_location_not_empty",
        ),

        CheckConstraint(
            "jsonb_typeof(metadata) = 'object'",
            name="ck_siem_assets_metadata_object",
        ),

        CheckConstraint(
            "jsonb_typeof(tags) = 'array'",
            name="ck_siem_assets_tags_array",
        ),
    )

    asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
    )

    mac_address: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    asset_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    environment: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    risk: Mapped[str] = mapped_column(
        String(32),
        default="INFORMATIONAL",
        server_default=text("'INFORMATIONAL'"),
        nullable=False,
    )

    lifecycle_status: Mapped[str] = mapped_column(
        String(32),
        default="ENABLED",
        server_default=text("'ENABLED'"),
        nullable=False,
    )

    operational_status: Mapped[str] = mapped_column(
        String(32),
        default="UNKNOWN",
        server_default=text("'UNKNOWN'"),
        nullable=False,
    )

    owner: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    location: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    tags: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        server_default=text("'[]'::jsonb"),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    asset_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        onupdate=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )


# ============================================================================
# Asset Indexes
# ============================================================================


Index(
    "ix_siem_assets_name",
    Asset.name,
)

Index(
    "ix_siem_assets_hostname",
    Asset.hostname,
)

Index(
    "ix_siem_assets_ip_address",
    Asset.ip_address,
)

Index(
    "ix_siem_assets_mac_address",
    Asset.mac_address,
)

Index(
    "ix_siem_assets_asset_type",
    Asset.asset_type,
)

Index(
    "ix_siem_assets_operating_system",
    Asset.operating_system,
)

Index(
    "ix_siem_assets_environment",
    Asset.environment,
)

Index(
    "ix_siem_assets_lifecycle_status",
    Asset.lifecycle_status,
)

Index(
    "ix_siem_assets_operational_status",
    Asset.operational_status,
)

Index(
    "ix_siem_assets_risk",
    Asset.risk,
)

Index(
    "ix_siem_assets_owner",
    Asset.owner,
)

Index(
    "ix_siem_assets_location",
    Asset.location,
)

Index(
    "ix_siem_assets_first_seen",
    Asset.first_seen.desc(),
)

Index(
    "ix_siem_assets_last_seen",
    Asset.last_seen.desc(),
)

Index(
    "ix_siem_assets_created_at",
    Asset.created_at.desc(),
)

Index(
    "ix_siem_assets_updated_at",
    Asset.updated_at.desc(),
)


# ============================================================================
# MITRE ATT&CK Knowledge
# ============================================================================
#
# IMPORTANT ARCHITECTURAL RULE
# ----------------------------
#
# These models represent the imported MITRE ATT&CK knowledge dataset.
#
# They do NOT represent:
#
#     Detection -> MITRE mappings
#
# Detection-to-MITRE mappings remain in the existing SentinelSIEM mapping
# subsystem and are intentionally not coupled to these ORM models.
#
# MITRE knowledge is imported from:
#
#     backend/data/mitre/enterprise-attack.json
#
# and exposed through read-only application APIs.
# ============================================================================


# ============================================================================
# MITRE Technique <-> Tactic Association
# ============================================================================


mitre_technique_tactic_table = Table(
    "siem_mitre_technique_tactics",
    Base.metadata,
    Column(
        "technique_id",
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_mitre_techniques.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
    Column(
        "tactic_id",
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_mitre_tactics.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
)


# ============================================================================
# MITRE Technique <-> Platform Association
# ============================================================================


mitre_technique_platform_table = Table(
    "siem_mitre_technique_platforms",
    Base.metadata,
    Column(
        "technique_id",
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_mitre_techniques.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
    Column(
        "platform_id",
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_mitre_platforms.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
)


# ============================================================================
# MITRE Tactics
# ============================================================================


class MitreTacticModel(Base):
    """
    MITRE ATT&CK tactic.

    Example:

        TA0001 -> Initial Access
        TA0002 -> Execution
    """

    __tablename__ = "siem_mitre_tactics"

    __table_args__ = (
        UniqueConstraint(
            "external_id",
            name="uq_siem_mitre_tactics_external_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    external_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    techniques: Mapped[list["MitreTechniqueModel"]] = relationship(
        "MitreTechniqueModel",
        secondary=mitre_technique_tactic_table,
        back_populates="tactics",
        lazy="selectin",
    )


Index(
    "ix_siem_mitre_tactics_name",
    MitreTacticModel.name,
)

Index(
    "ix_siem_mitre_tactics_external_id",
    MitreTacticModel.external_id,
)


# ============================================================================
# MITRE Platforms
# ============================================================================


class MitrePlatformModel(Base):
    """
    MITRE ATT&CK platform.

    Platform identifiers are normalized by the importer from the
    x_mitre_platforms values present on ATT&CK attack-pattern objects.
    """

    __tablename__ = "siem_mitre_platforms"

    __table_args__ = (
        UniqueConstraint(
            "external_id",
            name="uq_siem_mitre_platforms_external_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    external_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    techniques: Mapped[list["MitreTechniqueModel"]] = relationship(
        "MitreTechniqueModel",
        secondary=mitre_technique_platform_table,
        back_populates="platforms",
        lazy="selectin",
    )


Index(
    "ix_siem_mitre_platforms_name",
    MitrePlatformModel.name,
)

Index(
    "ix_siem_mitre_platforms_external_id",
    MitrePlatformModel.external_id,
)


# ============================================================================
# MITRE Techniques
# ============================================================================


class MitreTechniqueModel(Base):
    """
    MITRE ATT&CK technique or sub-technique.

    Examples:

        T1059
        T1059.001
        T1078
    """

    __tablename__ = "siem_mitre_techniques"

    __table_args__ = (
        UniqueConstraint(
            "external_id",
            name="uq_siem_mitre_techniques_external_id",
        ),

        CheckConstraint(
            "type IN ('TECHNIQUE', 'SUB_TECHNIQUE')",
            name="ck_siem_mitre_techniques_type_valid",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    external_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    parent_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_mitre_techniques.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    # ------------------------------------------------------------------------
    # Self-referencing parent/sub-technique relationship
    # ------------------------------------------------------------------------

    parent: Mapped["MitreTechniqueModel | None"] = relationship(
        "MitreTechniqueModel",
        remote_side=lambda: MitreTechniqueModel.id,
        back_populates="sub_techniques",
        foreign_keys=lambda: [MitreTechniqueModel.parent_id],
    )

    sub_techniques: Mapped[list["MitreTechniqueModel"]] = relationship(
        "MitreTechniqueModel",
        back_populates="parent",
        foreign_keys=lambda: [MitreTechniqueModel.parent_id],
        lazy="selectin",
    )

    # ------------------------------------------------------------------------
    # Tactics
    # ------------------------------------------------------------------------

    tactics: Mapped[list[MitreTacticModel]] = relationship(
        "MitreTacticModel",
        secondary=mitre_technique_tactic_table,
        back_populates="techniques",
        lazy="selectin",
    )

    # ------------------------------------------------------------------------
    # Platforms
    # ------------------------------------------------------------------------

    platforms: Mapped[list[MitrePlatformModel]] = relationship(
        "MitrePlatformModel",
        secondary=mitre_technique_platform_table,
        back_populates="techniques",
        lazy="selectin",
    )

    # ------------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------------

    references: Mapped[list["MitreReferenceModel"]] = relationship(
        "MitreReferenceModel",
        back_populates="technique",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )


Index(
    "ix_siem_mitre_techniques_external_id",
    MitreTechniqueModel.external_id,
)

Index(
    "ix_siem_mitre_techniques_name",
    MitreTechniqueModel.name,
)

Index(
    "ix_siem_mitre_techniques_type",
    MitreTechniqueModel.type,
)

Index(
    "ix_siem_mitre_techniques_parent_id",
    MitreTechniqueModel.parent_id,
)


# ============================================================================
# MITRE References
# ============================================================================


class MitreReferenceModel(Base):
    """
    External reference associated with a MITRE technique.

    Examples include:

        MITRE ATT&CK URLs
        CAPEC
        external documentation
        procedure references
    """

    __tablename__ = "siem_mitre_references"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    technique_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_mitre_techniques.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    source_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    external_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    technique: Mapped[MitreTechniqueModel] = relationship(
        "MitreTechniqueModel",
        back_populates="references",
        lazy="selectin",
    )


Index(
    "ix_siem_mitre_references_technique_id",
    MitreReferenceModel.technique_id,
)

Index(
    "ix_siem_mitre_references_external_id",
    MitreReferenceModel.external_id,
)


# ============================================================================
# MITRE STIX Relationships
# ============================================================================


class MitreRelationshipModel(Base):
    """
    Raw MITRE STIX relationship.

    This table stores the relationship graph from the authoritative
    Enterprise ATT&CK STIX dataset.

    It is deliberately generic because relationship endpoints can refer to
    different ATT&CK object types.
    """

    __tablename__ = "siem_mitre_relationships"

    __table_args__ = (
        UniqueConstraint(
            "relationship_external_id",
            name="uq_siem_mitre_relationships_external_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    relationship_external_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    relationship_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    source_external_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    target_external_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )


Index(
    "ix_siem_mitre_relationships_source",
    MitreRelationshipModel.source_external_id,
)

Index(
    "ix_siem_mitre_relationships_target",
    MitreRelationshipModel.target_external_id,
)

Index(
    "ix_siem_mitre_relationships_type",
    MitreRelationshipModel.relationship_type,
)


# ============================================================================
# MITRE Import History
# ============================================================================


class MitreImportModel(Base):
    """
    MITRE ATT&CK dataset import history.

    Each successful or failed dataset import creates one audit-like
    operational record for the knowledge ingestion pipeline.
    """

    __tablename__ = "siem_mitre_imports"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    dataset_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    dataset_version: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    source_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    object_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    tactic_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    technique_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    subtechnique_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    platform_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    relationship_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    reference_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=text("NOW()"),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )


Index(
    "ix_siem_mitre_imports_imported_at",
    MitreImportModel.imported_at.desc(),
)

Index(
    "ix_siem_mitre_imports_status",
    MitreImportModel.status,
)

Index(
    "ix_siem_mitre_imports_dataset",
    MitreImportModel.dataset_name,
)


# ============================================================================
# MITRE ORM Export List
# ============================================================================


__all__ = [
    # Base
    "Base",

    # Generic storage
    "StorageRecord",

    # Authentication
    "AuthUser",
    "AuthRole",
    "AuthPermission",
    "AuthUserRole",
    "AuthRolePermission",
    "AuthSession",
    "AuthAudit",

    # Assets
    "Asset",

    # MITRE association tables
    "mitre_technique_tactic_table",
    "mitre_technique_platform_table",

    # MITRE knowledge
    "MitreTacticModel",
    "MitrePlatformModel",
    "MitreTechniqueModel",
    "MitreReferenceModel",
    "MitreRelationshipModel",
    "MitreImportModel",
]