from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config


# ============================================================================
# Project Path
# ============================================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# ============================================================================
# Application Models
# ============================================================================

from backend.app.storage.postgres.models import Base


# ============================================================================
# Alembic Configuration
# ============================================================================

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# ============================================================================
# SQLAlchemy Metadata
# ============================================================================

target_metadata = Base.metadata


# ============================================================================
# Alembic Settings
# ============================================================================

VERSION_TABLE = "alembic_version"
VERSION_TABLE_SCHEMA = None


# ============================================================================
# Tables Managed Outside Alembic
# ============================================================================

EXCLUDED_TABLES = {
    "storage_metadata",
    "siem_schema_migrations",
}


def include_object(
    object_,
    name,
    type_,
    reflected,
    compare_to,
):
    """
    Exclude tables managed by SentinelSIEM's
    application-level SQL migration system.
    """

    if type_ == "table":
        if name in EXCLUDED_TABLES:
            return False

    return True


# ============================================================================
# Server Default Comparison
# ============================================================================


def compare_server_default(
    context_,
    inspected_column,
    metadata_column,
    inspected_default,
    metadata_default,
    rendered_metadata_default,
):
    """
    Handle PostgreSQL server-default comparison.

    The existing database already contains the correct
    default for siem_sessions.created_at. PostgreSQL
    may render equivalent timestamp expressions
    differently during reflection.

    Do not generate a migration for this known-equivalent
    default.
    """

    if (
        inspected_column is not None
        and metadata_column is not None
        and inspected_column.name == "created_at"
        and inspected_column.table.name == "siem_sessions"
    ):
        return False

    return None


# ============================================================================
# Database URL
# ============================================================================


def get_database_url() -> str:
    """
    Read the PostgreSQL connection URL from the environment.
    """

    url = os.getenv("SIEM_DATABASE_URL")

    if not url:
        raise RuntimeError(
            "SIEM_DATABASE_URL environment variable is not set"
        )

    return url


# ============================================================================
# Offline Migrations
# ============================================================================


def run_migrations_offline() -> None:
    """
    Run migrations without establishing a database connection.
    """

    url = get_database_url()

    context.configure(
        url=url,
        target_metadata=target_metadata,

        literal_binds=True,

        dialect_opts={
            "paramstyle": "named",
        },

        compare_type=True,
        compare_server_default=compare_server_default,

        include_object=include_object,

        version_table=VERSION_TABLE,
        version_table_schema=VERSION_TABLE_SCHEMA,
    )

    with context.begin_transaction():
        context.run_migrations()


# ============================================================================
# Online Migration Configuration
# ============================================================================


def do_run_migrations(connection) -> None:
    """
    Configure and execute Alembic migrations using
    an active SQLAlchemy connection.
    """

    context.configure(
        connection=connection,
        target_metadata=target_metadata,

        compare_type=True,
        compare_server_default=compare_server_default,

        include_object=include_object,

        version_table=VERSION_TABLE,
        version_table_schema=VERSION_TABLE_SCHEMA,
    )

    with context.begin_transaction():
        context.run_migrations()


# ============================================================================
# Async Migration Runner
# ============================================================================


async def run_async_migrations() -> None:
    """
    Create an async SQLAlchemy engine and run Alembic
    through SQLAlchemy's synchronous migration bridge.
    """

    configuration = config.get_section(
        config.config_ini_section
    )

    if configuration is None:
        configuration = {}

    configuration["sqlalchemy.url"] = get_database_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    try:
        async with connectable.connect() as connection:
            await connection.run_sync(
                do_run_migrations
            )

    finally:
        await connectable.dispose()


# ============================================================================
# Online Migration Entry Point
# ============================================================================


def run_migrations_online() -> None:
    """
    Run Alembic migrations against PostgreSQL.
    """

    asyncio.run(
        run_async_migrations()
    )


# ============================================================================
# Alembic Entry Point
# ============================================================================


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()