"""
Database migration commands for SentinelSIEM.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    create_async_engine,
)

from app.core.config import Settings

# ============================================================================
# Constants
# ============================================================================

MIGRATIONS_DIR: Final[Path] = Path(__file__).resolve().parents[2] / "storage" / "migrations"

MIGRATION_TABLE: Final[str] = "siem_schema_migrations"

MIGRATION_FILENAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<version>\d+)_(?P<name>[a-zA-Z0-9][a-zA-Z0-9_-]*)\.sql$"
)

OUTER_TRANSACTION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\s*BEGIN\s*;\s*(?P<body>.*?)\s*COMMIT\s*;\s*$",
    re.IGNORECASE | re.DOTALL,
)

BASELINE_REQUIREMENTS: Final[dict[str, tuple[str, ...]]] = {
    "001": (
        "storage_metadata",
        "storage_records",
    ),
    "002": (
        "siem_users",
        "siem_roles",
        "siem_permissions",
        "siem_user_roles",
        "siem_role_permissions",
        "siem_sessions",
        "siem_auth_audit",
    ),
}

EXPECTED_ROLE_COUNT: Final[int] = 5
EXPECTED_PERMISSION_COUNT: Final[int] = 18


# ============================================================================
# Exceptions
# ============================================================================


class MigrationError(RuntimeError):
    """Raised when database migration processing fails."""


# ============================================================================
# Migration model
# ============================================================================


@dataclass(frozen=True, slots=True)
class Migration:
    """A discovered SQL migration."""

    version: str
    name: str
    path: Path

    @property
    def numeric_version(self) -> int:
        """Return the numeric migration version."""
        return int(self.version)

    @property
    def canonical_version(self) -> str:
        """Return the canonical zero-padded migration version."""
        return f"{self.numeric_version:03d}"

    @property
    def identifier(self) -> str:
        """Return the stable migration identifier."""
        return f"{self.canonical_version}_{self.name}"


# ============================================================================
# Typer application
# ============================================================================


database = typer.Typer(
    name="database",
    help="Database and migration management commands.",
    no_args_is_help=True,
)


# ============================================================================
# Version helpers
# ============================================================================


def _canonical_version(version: int | str) -> str:
    """Normalize a migration version to three digits."""
    try:
        numeric_version = int(version)
    except (TypeError, ValueError) as exc:
        raise MigrationError(f"Invalid migration version: {version!r}") from exc

    if numeric_version < 1:
        raise MigrationError(f"Migration version must be positive: {version!r}")

    return f"{numeric_version:03d}"


# ============================================================================
# Migration discovery
# ============================================================================


def _discover_migrations() -> list[Migration]:
    """Discover and validate SQL migration files."""
    if not MIGRATIONS_DIR.exists():
        raise MigrationError(f"Migration directory does not exist: {MIGRATIONS_DIR}")

    if not MIGRATIONS_DIR.is_dir():
        raise MigrationError(f"Migration path is not a directory: {MIGRATIONS_DIR}")

    migrations: list[Migration] = []

    for path in MIGRATIONS_DIR.iterdir():
        if not path.is_file():
            continue

        if path.suffix.lower() != ".sql":
            continue

        match = MIGRATION_FILENAME_PATTERN.match(path.name)

        if match is None:
            raise MigrationError(
                f"Invalid migration filename: {path.name}. Expected '<version>_<name>.sql'."
            )

        migrations.append(
            Migration(
                version=_canonical_version(match.group("version")),
                name=match.group("name"),
                path=path,
            )
        )

    migrations.sort(key=lambda migration: migration.numeric_version)

    seen_versions: set[str] = set()

    for migration in migrations:
        if migration.version in seen_versions:
            raise MigrationError(f"Duplicate migration version: {migration.identifier}")

        seen_versions.add(migration.version)

    return migrations


# ============================================================================
# Database configuration
# ============================================================================


def _get_database_url() -> str:
    """Load the database URL required by migration commands."""
    try:
        settings = Settings()
    except Exception as exc:
        raise MigrationError("Unable to load database configuration.") from exc

    database_url = settings.database_url

    if not database_url:
        raise MigrationError("SIEM_DATABASE_URL is not configured.")

    return database_url


def _create_engine() -> AsyncEngine:
    """Create the PostgreSQL async engine."""
    return create_async_engine(
        _get_database_url(),
        pool_pre_ping=True,
    )


# ============================================================================
# Migration tracking
# ============================================================================


async def _ensure_tracking_table(
    engine: AsyncEngine,
) -> None:
    """Create the migration tracking table if necessary."""
    query = text(
        f"""
        CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
            version VARCHAR(32) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    async with engine.begin() as connection:
        await connection.execute(query)


async def _get_applied_migrations(
    engine: AsyncEngine,
) -> dict[str, str]:
    """Return applied migrations normalized to canonical versions."""
    query = text(
        f"""
        SELECT
            version,
            name
        FROM {MIGRATION_TABLE}
        ORDER BY version
        """
    )

    async with engine.connect() as connection:
        result = await connection.execute(query)
        rows = result.mappings().all()

    applied: dict[str, str] = {}

    for row in rows:
        version = _canonical_version(str(row["version"]))
        name = str(row["name"])

        existing_name = applied.get(version)

        if existing_name is not None and existing_name != name:
            raise MigrationError(
                "Migration tracking conflict: "
                f"version {version} has multiple names: "
                f"'{existing_name}' and '{name}'."
            )

        applied[version] = name

    return applied


def _validate_migration_identity(
    migration: Migration,
    applied: dict[str, str],
) -> None:
    """Ensure tracked migration name matches the local migration."""
    existing_name = applied.get(migration.canonical_version)

    if existing_name is None:
        return

    if existing_name != migration.name:
        raise MigrationError(
            "Migration version conflict: "
            f"{migration.identifier} is recorded as "
            f"'{existing_name}', but the local migration is "
            f"'{migration.name}'."
        )


# ============================================================================
# Schema validation
# ============================================================================


async def _table_exists(
    connection: AsyncConnection,
    table_name: str,
) -> bool:
    """Return whether a public PostgreSQL table exists."""
    result = await connection.execute(
        text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name = :table_name
            )
            """
        ),
        {
            "table_name": table_name,
        },
    )

    return bool(result.scalar_one())


async def _validate_required_tables(
    engine: AsyncEngine,
    required_tables: tuple[str, ...],
) -> None:
    """Validate that required tables exist."""
    missing_tables: list[str] = []

    async with engine.connect() as connection:
        for table_name in required_tables:
            if not await _table_exists(
                connection,
                table_name,
            ):
                missing_tables.append(table_name)

    if not missing_tables:
        return

    formatted = "\n".join(f"  - {table_name}" for table_name in missing_tables)

    raise MigrationError(f"Baseline validation failed. Missing required tables:\n{formatted}")


async def _validate_authentication_schema(
    engine: AsyncEngine,
) -> None:
    """Validate the foundational authentication schema from migration 002."""
    async with engine.connect() as connection:
        role_count_result = await connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM siem_roles
                """
            )
        )

        permission_count_result = await connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM siem_permissions
                """
            )
        )

        role_count = int(role_count_result.scalar_one())
        permission_count = int(permission_count_result.scalar_one())

    if role_count != EXPECTED_ROLE_COUNT:
        raise MigrationError(
            "Baseline validation failed for migration 002: "
            f"expected {EXPECTED_ROLE_COUNT} roles, "
            f"found {role_count}."
        )

    if permission_count != EXPECTED_PERMISSION_COUNT:
        raise MigrationError(
            "Baseline validation failed for migration 002: "
            f"expected {EXPECTED_PERMISSION_COUNT} permissions, "
            f"found {permission_count}."
        )


async def _validate_baseline(
    engine: AsyncEngine,
    migrations: list[Migration],
    through: int,
) -> list[Migration]:
    """Validate the existing database before baselining."""
    selected = [migration for migration in migrations if migration.numeric_version <= through]

    if not selected:
        raise MigrationError(f"No migrations exist through version {through:03d}.")

    for migration in selected:
        requirements = BASELINE_REQUIREMENTS.get(migration.canonical_version)

        if requirements is None:
            raise MigrationError(f"No baseline validation is defined for {migration.identifier}.")

        await _validate_required_tables(
            engine,
            requirements,
        )

        if migration.numeric_version == 2:
            await _validate_authentication_schema(engine)

    return selected


# ============================================================================
# SQL preparation
# ============================================================================


def _read_migration_sql(
    migration: Migration,
) -> str:
    """Read and normalize migration SQL."""
    try:
        sql = migration.path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MigrationError(f"Unable to read migration: {migration.path.name}") from exc

    sql = sql.strip()

    if not sql:
        raise MigrationError(f"Migration is empty: {migration.path.name}")

    match = OUTER_TRANSACTION_PATTERN.match(sql)

    if match is not None:
        sql = match.group("body").strip()

    if not sql:
        raise MigrationError(f"Migration contains no executable SQL: {migration.path.name}")

    return sql


# ============================================================================
# PostgreSQL SQL statement splitter
# ============================================================================


def _split_sql_statements(sql: str) -> list[str]:
    """
    Split a PostgreSQL migration script into executable statements.

    The parser recognizes:

    - single quoted strings
    - double quoted identifiers
    - PostgreSQL dollar-quoted strings
    - line comments
    - block comments

    Semicolons inside strings and comments are not treated as statement
    boundaries.

    The migration runner executes every resulting statement inside one
    transaction.
    """
    statements: list[str] = []
    buffer: list[str] = []

    index = 0
    length = len(sql)

    in_single_quote = False
    in_double_quote = False
    in_line_comment = False
    in_block_comment = False
    dollar_tag: str | None = None

    while index < length:
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < length else ""

        # ------------------------------------------------------------------
        # Line comment
        # ------------------------------------------------------------------
        if in_line_comment:
            buffer.append(char)

            if char == "\n":
                in_line_comment = False

            index += 1
            continue

        # ------------------------------------------------------------------
        # Block comment
        # ------------------------------------------------------------------
        if in_block_comment:
            buffer.append(char)

            if char == "*" and next_char == "/":
                buffer.append(next_char)
                index += 2
                in_block_comment = False
                continue

            index += 1
            continue

        # ------------------------------------------------------------------
        # Dollar-quoted string
        # ------------------------------------------------------------------
        if dollar_tag is not None:
            if sql.startswith(dollar_tag, index):
                buffer.append(dollar_tag)
                index += len(dollar_tag)
                dollar_tag = None
                continue

            buffer.append(char)
            index += 1
            continue

        # ------------------------------------------------------------------
        # Single quoted string
        # ------------------------------------------------------------------
        if in_single_quote:
            buffer.append(char)

            if char == "'":
                if next_char == "'":
                    buffer.append(next_char)
                    index += 2
                    continue

                in_single_quote = False

            index += 1
            continue

        # ------------------------------------------------------------------
        # Double quoted identifier
        # ------------------------------------------------------------------
        if in_double_quote:
            buffer.append(char)

            if char == '"':
                if next_char == '"':
                    buffer.append(next_char)
                    index += 2
                    continue

                in_double_quote = False

            index += 1
            continue

        # ------------------------------------------------------------------
        # Start comments
        # ------------------------------------------------------------------
        if char == "-" and next_char == "-":
            buffer.append(char)
            buffer.append(next_char)
            index += 2
            in_line_comment = True
            continue

        if char == "/" and next_char == "*":
            buffer.append(char)
            buffer.append(next_char)
            index += 2
            in_block_comment = True
            continue

        # ------------------------------------------------------------------
        # Start single quoted string
        # ------------------------------------------------------------------
        if char == "'":
            buffer.append(char)
            index += 1
            in_single_quote = True
            continue

        # ------------------------------------------------------------------
        # Start double quoted identifier
        # ------------------------------------------------------------------
        if char == '"':
            buffer.append(char)
            index += 1
            in_double_quote = True
            continue

        # ------------------------------------------------------------------
        # Start dollar quoted string
        # ------------------------------------------------------------------
        if char == "$":
            dollar_match = re.match(
                r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$",
                sql[index:],
            )

            if dollar_match is not None:
                tag = dollar_match.group(0)
                buffer.append(tag)
                index += len(tag)
                dollar_tag = tag
                continue

        # ------------------------------------------------------------------
        # Statement boundary
        # ------------------------------------------------------------------
        if char == ";":
            statement = "".join(buffer).strip()

            if statement:
                statements.append(statement)

            buffer = []
            index += 1
            continue

        # ------------------------------------------------------------------
        # Normal character
        # ------------------------------------------------------------------
        buffer.append(char)
        index += 1

    # ----------------------------------------------------------------------
    # Validate parser state
    # ----------------------------------------------------------------------
    if in_single_quote:
        raise MigrationError("Unterminated single-quoted string in migration SQL.")

    if in_double_quote:
        raise MigrationError("Unterminated double-quoted identifier in migration SQL.")

    if in_block_comment:
        raise MigrationError("Unterminated block comment in migration SQL.")

    if dollar_tag is not None:
        raise MigrationError(f"Unterminated PostgreSQL dollar-quoted string ({dollar_tag}).")

    statement = "".join(buffer).strip()

    if statement:
        statements.append(statement)

    return statements


# ============================================================================
# Error formatting
# ============================================================================


def _format_exception_chain(exc: BaseException) -> str:
    """Return a readable exception chain."""
    parts: list[str] = []
    current: BaseException | None = exc
    seen: set[int] = set()

    while current is not None:
        current_id = id(current)

        if current_id in seen:
            break

        seen.add(current_id)

        message = str(current).strip()

        if message:
            parts.append(f"{type(current).__name__}: {message}")
        else:
            parts.append(type(current).__name__)

        current = current.__cause__ or current.__context__

    return "\n".join(parts)


# ============================================================================
# Migration execution
# ============================================================================


async def _execute_migration_sql(
    connection: AsyncConnection,
    migration: Migration,
    sql: str,
) -> None:
    """
    Execute every SQL statement from one migration.

    All statements execute on the same connection and therefore remain
    part of the surrounding transaction.
    """
    statements = _split_sql_statements(sql)

    if not statements:
        raise MigrationError(f"Migration contains no executable SQL: {migration.path.name}")

    total = len(statements)

    for index, statement in enumerate(
        statements,
        start=1,
    ):
        try:
            await connection.exec_driver_sql(statement)
        except Exception as exc:
            preview = " ".join(statement.split())

            if len(preview) > 500:
                preview = preview[:500] + "..."

            raise MigrationError(
                f"Migration failed: {migration.path.name}\n"
                f"Statement {index}/{total} failed:\n"
                f"{preview}\n"
                "Database error:\n"
                f"{_format_exception_chain(exc)}"
            ) from exc


async def _apply_migration(
    engine: AsyncEngine,
    migration: Migration,
) -> None:
    """
    Execute and record one migration atomically.

    SQL statements and the tracking INSERT are committed together.
    """
    sql = _read_migration_sql(migration)

    tracking_insert = text(
        f"""
        INSERT INTO {MIGRATION_TABLE} (
            version,
            name
        )
        VALUES (
            :version,
            :name
        )
        """
    )

    try:
        async with engine.begin() as connection:
            await _execute_migration_sql(
                connection,
                migration,
                sql,
            )

            await connection.execute(
                tracking_insert,
                {
                    "version": migration.canonical_version,
                    "name": migration.name,
                },
            )

    except MigrationError:
        raise

    except Exception as exc:
        raise MigrationError(
            f"Migration failed: {migration.path.name}\n"
            "Database error:\n"
            f"{_format_exception_chain(exc)}"
        ) from exc


# ============================================================================
# Baseline execution
# ============================================================================


async def _baseline(through: int) -> list[Migration]:
    """Baseline existing migrations without executing their SQL."""
    if through < 1:
        raise MigrationError("Baseline version must be >= 1.")

    migrations = _discover_migrations()

    available_versions = {migration.numeric_version for migration in migrations}

    if through not in available_versions:
        raise MigrationError(f"Unknown migration version: {through:03d}")

    engine = _create_engine()

    try:
        await _ensure_tracking_table(engine)

        applied = await _get_applied_migrations(engine)

        selected = await _validate_baseline(
            engine,
            migrations,
            through,
        )

        pending_baseline = [
            migration for migration in selected if migration.canonical_version not in applied
        ]

        if not pending_baseline:
            return []

        for migration in pending_baseline:
            _validate_migration_identity(
                migration,
                applied,
            )

        tracking_insert = text(
            f"""
            INSERT INTO {MIGRATION_TABLE} (
                version,
                name
            )
            VALUES (
                :version,
                :name
            )
            """
        )

        try:
            async with engine.begin() as connection:
                for migration in pending_baseline:
                    await connection.execute(
                        tracking_insert,
                        {
                            "version": migration.canonical_version,
                            "name": migration.name,
                        },
                    )

        except Exception as exc:
            raise MigrationError(
                f"Unable to record baseline migrations:\n{_format_exception_chain(exc)}"
            ) from exc

        return pending_baseline

    finally:
        await engine.dispose()


# ============================================================================
# Status
# ============================================================================


async def _migration_status() -> list[tuple[Migration, bool]]:
    """Return migration status."""
    migrations = _discover_migrations()
    engine = _create_engine()

    try:
        await _ensure_tracking_table(engine)

        applied = await _get_applied_migrations(engine)

        migration_status: list[tuple[Migration, bool]] = []

        for migration in migrations:
            _validate_migration_identity(
                migration,
                applied,
            )

            migration_status.append(
                (
                    migration,
                    migration.canonical_version in applied,
                )
            )

        return migration_status

    finally:
        await engine.dispose()


# ============================================================================
# Migration coordinator
# ============================================================================


async def _migrate() -> tuple[int, int]:
    """Apply all pending migrations in version order."""
    migrations = _discover_migrations()
    engine = _create_engine()

    applied_count = 0
    skipped_count = 0

    try:
        await _ensure_tracking_table(engine)

        applied = await _get_applied_migrations(engine)

        for migration in migrations:
            _validate_migration_identity(
                migration,
                applied,
            )

            if migration.canonical_version in applied:
                skipped_count += 1
                continue

            typer.echo(f"Applying {migration.identifier}...")

            await _apply_migration(
                engine,
                migration,
            )

            typer.echo(f"Applied {migration.identifier}")

            applied_count += 1
            applied[migration.canonical_version] = migration.name

        return applied_count, skipped_count

    finally:
        await engine.dispose()


# ============================================================================
# CLI commands
# ============================================================================


@database.command("status")
def status() -> None:
    """Show database migration status."""
    try:
        migration_status = asyncio.run(_migration_status())

    except MigrationError as exc:
        typer.echo(
            f"Migration status error:\n{exc}",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    except Exception as exc:
        typer.echo(
            f"Unexpected migration status error:\n{_format_exception_chain(exc)}",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    if not migration_status:
        typer.echo("No migrations found.")
        return

    typer.echo("Database migrations:")
    typer.echo("")

    for migration, applied in migration_status:
        state = "APPLIED" if applied else "PENDING"
        typer.echo(f"{migration.identifier:<40} {state}")


@database.command("baseline")
def baseline(
    through: int = typer.Option(
        ...,
        "--through",
        min=1,
        help="Mark existing migrations as applied through this version.",
    ),
) -> None:
    """Baseline existing database migrations."""
    try:
        baselined = asyncio.run(_baseline(through))

    except MigrationError as exc:
        typer.echo(
            f"Baseline error:\n{exc}",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    except Exception as exc:
        typer.echo(
            f"Unexpected baseline error:\n{_format_exception_chain(exc)}",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    if not baselined:
        typer.echo("No migrations needed to be baselined.")
        return

    typer.echo("Baselined migrations:")

    for migration in baselined:
        typer.echo(f"  {migration.identifier}")


@database.command("migrate")
def migrate() -> None:
    """Apply all pending database migrations."""
    try:
        applied_count, skipped_count = asyncio.run(_migrate())

    except MigrationError as exc:
        typer.echo(
            f"Migration error:\n{exc}",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    except Exception as exc:
        typer.echo(
            f"Unexpected migration error:\n{_format_exception_chain(exc)}",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    typer.echo("")
    typer.echo(f"Migration complete: {applied_count} applied, {skipped_count} already applied.")


# ============================================================================
# Public exports
# ============================================================================

__all__ = [
    "database",
]
