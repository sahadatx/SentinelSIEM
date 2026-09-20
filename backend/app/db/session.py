"""
SentinelSIEM Database ORM Base
================================

Shared SQLAlchemy declarative base for SentinelSIEM ORM models.

Architecture
------------

This module owns only the SQLAlchemy ORM model registry/base.

PostgreSQL connection and AsyncSession lifecycle are managed by:

    app.storage.postgres.session.PostgresSessionManager

This module MUST NOT:

    - create a database engine
    - create an AsyncSession
    - manage transactions
    - create database connections
    - define application tables

ORM models import Base from here:

    from app.db.session import Base

Example:

    class AuditEvent(Base):
        __tablename__ = "siem_auth_audit"
        ...

The application/service layer remains responsible for transaction
boundaries.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase

# ============================================================================
# Declarative Base
# ============================================================================


class Base(DeclarativeBase):
    """
    Shared SQLAlchemy declarative base.

    All SentinelSIEM ORM models must inherit from this class.

    Example
    -------

        class AuditEvent(Base):
            __tablename__ = "siem_auth_audit"
            ...
    """

    pass


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "Base",
]
