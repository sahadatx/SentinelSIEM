"""
SentinelSIEM — Central Audit Domain Models
==========================================

Canonical SQLAlchemy persistence model for the SentinelSIEM centralized
security audit subsystem.

Canonical database table
------------------------

    siem_auth_audit

Canonical SQLAlchemy model
--------------------------

    AuditEvent


Architecture
------------

    Authentication
          |
    Authorization
          |
    User Management
          |
    Security Events
          |
          v
      AuditService
          |
          v
    AuditRepository
          |
          v
       AuditEvent
          |
          v
    siem_auth_audit


Audit Guarantees
----------------

This model represents historical security telemetry.

Application-level guarantees:

    - append-only
    - immutable after creation
    - centralized
    - single canonical ORM model
    - single canonical database table
    - no public update operation
    - no public delete operation

The model itself intentionally does NOT implement authorization or
transaction management.


Canonical Identity References
-----------------------------

Actor:

    actor_user_id

Target:

    target_user_id

These UUID fields are the canonical persisted identity references.

Resolved identity information such as:

    username
    role

belongs to the service / mapper / API presentation layer and is not
duplicated into this persistence model.


Canonical Metadata
------------------

Python ORM attribute:

    metadata_json

Database column:

    metadata_json

IMPORTANT:

The database schema uses ``metadata_json``.

Do NOT map the Python attribute to a database column named ``metadata``.

SQLAlchemy Declarative Base already exposes ``metadata`` at the class level,
so the ORM attribute remains ``metadata_json``.


Security
--------

This model MUST NOT contain:

    - plaintext passwords
    - password hashes
    - access tokens
    - refresh tokens
    - JWTs
    - API keys
    - client secrets
    - private keys
    - encryption keys
    - signing keys
    - authorization headers
    - cookies
    - session tokens
    - credential material

Metadata security validation belongs to the service/repository layer.

This model stores persistence data only.


Database Type Guarantees
------------------------

source_ip:

    PostgreSQL INET

metadata_json:

    PostgreSQL JSONB

UUID fields:

    PostgreSQL UUID

created_at:

    TIMESTAMP WITH TIME ZONE


Model Responsibilities
----------------------

This model owns:

    - database table mapping
    - column definitions
    - database indexes
    - safe ORM representation

This model does NOT own:

    - authentication
    - authorization
    - RBAC
    - metadata security policy
    - HTTP/FastAPI
    - request validation
    - API response formatting
    - transaction management
    - commit
    - rollback
    - audit write authorization
    - audit update policy
    - audit delete policy


Compatibility
-------------

AuditRecord and AuditLog are Python aliases of AuditEvent.

They are NOT separate ORM classes.

They do NOT create additional tables.

Canonical model:

    AuditEvent

Canonical table:

    siem_auth_audit
"""

from __future__ import annotations

# =============================================================================
# Standard Library
# =============================================================================

from datetime import datetime
from typing import Any
from uuid import UUID


# =============================================================================
# Third-Party
# =============================================================================

from sqlalchemy import (
    DateTime,
    Index,
    String,
)

from sqlalchemy.dialects.postgresql import (
    INET,
    JSONB,
    UUID as PGUUID,
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)


# =============================================================================
# SentinelSIEM
# =============================================================================

from app.db.session import Base


# =============================================================================
# Constants
# =============================================================================

AUDIT_TABLE_NAME = "siem_auth_audit"

AUDIT_ACTION_MAX_LENGTH = 150
AUDIT_OUTCOME_MAX_LENGTH = 50
AUDIT_REQUEST_ID_MAX_LENGTH = 100


# =============================================================================
# Canonical Audit Event
# =============================================================================


class AuditEvent(Base):
    """
    Canonical SentinelSIEM audit persistence model.

    Database table:

        siem_auth_audit

    Audit events are treated by the application as immutable and
    append-only historical security telemetry.

    Actor and target identities are stored only as UUID references.

    Username / role resolution belongs to the service layer.

    No ORM relationships are intentionally declared here.
    """

    __tablename__ = AUDIT_TABLE_NAME

    # =========================================================================
    # Primary Identity
    # =========================================================================

    audit_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        nullable=False,
    )

    # =========================================================================
    # Actor Identity
    # =========================================================================

    actor_user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        index=True,
        comment=(
            "Canonical UUID of the user responsible for the event. "
            "NULL represents a system or anonymous event."
        ),
    )

    # =========================================================================
    # Target Identity
    # =========================================================================

    target_user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        index=True,
        comment=(
            "Canonical UUID of the user affected by the event. "
            "NULL means the event has no user target."
        ),
    )

    # =========================================================================
    # Session Correlation
    # =========================================================================

    session_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        index=True,
        comment=(
            "Authentication/session correlation UUID. "
            "Must never contain a session secret or token."
        ),
    )

    # =========================================================================
    # Request Correlation
    # =========================================================================

    request_id: Mapped[str | None] = mapped_column(
        String(AUDIT_REQUEST_ID_MAX_LENGTH),
        nullable=True,
        index=True,
        comment=(
            "Application-level request or correlation identifier."
        ),
    )

    # =========================================================================
    # Network Source
    # =========================================================================

    source_ip: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
        comment=(
            "Source/client IP address stored using PostgreSQL INET."
        ),
    )

    # =========================================================================
    # Audit Action
    # =========================================================================

    action: Mapped[str] = mapped_column(
        String(AUDIT_ACTION_MAX_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "Canonical namespaced audit action."
        ),
    )

    # =========================================================================
    # Audit Outcome
    # =========================================================================

    outcome: Mapped[str] = mapped_column(
        String(AUDIT_OUTCOME_MAX_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "Canonical audit outcome: success, failure, or denied."
        ),
    )

    # =========================================================================
    # Canonical Audit Metadata
    # =========================================================================
    #
    # IMPORTANT:
    #
    # Python ORM attribute:
    #
    #     metadata_json
    #
    # Database column:
    #
    #     metadata_json
    #
    # The previous implementation incorrectly mapped this attribute to:
    #
    #     "metadata"
    #
    # That generated SQL similar to:
    #
    #     INSERT INTO siem_auth_audit (..., metadata, ...)
    #
    # But the actual database schema contains:
    #
    #     metadata_json
    #
    # Therefore the ORM MUST use the actual database column name.
    #

    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        comment=(
            "Safe non-sensitive audit metadata. "
            "Credential material is prohibited."
        ),
    )

    # =========================================================================
    # Creation Timestamp
    # =========================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment=(
            "UTC timestamp at which the audit event was created."
        ),
    )

    # =========================================================================
    # Composite Indexes
    # =========================================================================

    __table_args__ = (

        # ---------------------------------------------------------------------
        # Target history
        # ---------------------------------------------------------------------

        Index(
            "ix_siem_auth_audit_target_created",
            "target_user_id",
            "created_at",
        ),

        # ---------------------------------------------------------------------
        # Actor history
        # ---------------------------------------------------------------------

        Index(
            "ix_siem_auth_audit_actor_created",
            "actor_user_id",
            "created_at",
        ),

        # ---------------------------------------------------------------------
        # Action history
        # ---------------------------------------------------------------------

        Index(
            "ix_siem_auth_audit_action_created",
            "action",
            "created_at",
        ),

        # ---------------------------------------------------------------------
        # Outcome analysis
        # ---------------------------------------------------------------------

        Index(
            "ix_siem_auth_audit_outcome_created",
            "outcome",
            "created_at",
        ),

        # ---------------------------------------------------------------------
        # Session correlation
        # ---------------------------------------------------------------------

        Index(
            "ix_siem_auth_audit_session_created",
            "session_id",
            "created_at",
        ),

        # ---------------------------------------------------------------------
        # Request correlation
        # ---------------------------------------------------------------------

        Index(
            "ix_siem_auth_audit_request_created",
            "request_id",
            "created_at",
        ),

        # ---------------------------------------------------------------------
        # Chronological investigation
        # ---------------------------------------------------------------------

        Index(
            "ix_siem_auth_audit_created_action",
            "created_at",
            "action",
        ),
    )

    # =========================================================================
    # Safe Representation
    # =========================================================================

    def __repr__(self) -> str:
        """
        Return a concise security-safe representation.

        Sensitive/correlation-heavy fields are intentionally excluded.

        Excluded:

            metadata_json
            request_id
            source_ip
            session_id

        Credential material is never exposed.
        """

        return (
            "AuditEvent("
            f"audit_id={self.audit_id!r}, "
            f"actor_user_id={self.actor_user_id!r}, "
            f"target_user_id={self.target_user_id!r}, "
            f"action={self.action!r}, "
            f"outcome={self.outcome!r}, "
            f"created_at={self.created_at!r}"
            ")"
        )


# =============================================================================
# Compatibility Aliases
# =============================================================================
#
# These are direct Python aliases.
#
# They are NOT subclasses.
#
# They do NOT create:
#
#     - another SQLAlchemy mapper
#     - another database table
#     - another persistence source
#
# Therefore:
#
#     AuditEvent
#     AuditRecord
#     AuditLog
#
# all refer to exactly the same ORM model.
# =============================================================================

AuditRecord = AuditEvent

AuditLog = AuditEvent


# =============================================================================
# Public Exports
# =============================================================================

__all__ = [
    # Constants
    "AUDIT_TABLE_NAME",
    "AUDIT_ACTION_MAX_LENGTH",
    "AUDIT_OUTCOME_MAX_LENGTH",
    "AUDIT_REQUEST_ID_MAX_LENGTH",

    # Canonical model
    "AuditEvent",

    # Compatibility aliases
    "AuditRecord",
    "AuditLog",
]