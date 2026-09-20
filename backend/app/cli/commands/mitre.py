"""
SentinelSIEM MITRE ATT&CK CLI commands.

Commands
--------
    siem mitre import
    siem mitre status

Architecture
------------
The MITRE knowledge workflow is dataset-driven:

    enterprise-attack.json
            │
            ▼
      MitreImporter
            │
            ▼
        PostgreSQL
            │
            ▼
     MITRE read APIs

Important
---------
Detection → MITRE mappings are NOT managed by this CLI.

They remain part of the existing SentinelSIEM detection/mapping subsystem.
MITRE ATT&CK knowledge and Detection → MITRE mappings are intentionally
separate concerns.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import typer
from sqlalchemy import func, select

from app.core.config import get_settings
from app.mitre.importer import (
    DEFAULT_DATASET_PATH,
    MitreImportError,
    MitreImporter,
)
from app.storage.postgres.models import (
    MitreImportModel,
    MitrePlatformModel,
    MitreReferenceModel,
    MitreRelationshipModel,
    MitreTacticModel,
    MitreTechniqueModel,
)
from app.storage.postgres.session import (
    PostgresSessionManager,
)


logger = logging.getLogger(__name__)


# =============================================================================
# CLI Application
# =============================================================================

mitre = typer.Typer(
    name="mitre",
    help="MITRE ATT&CK dataset and knowledge-base commands.",
    no_args_is_help=True,
)


# =============================================================================
# Constants
# =============================================================================

# The importer owns the canonical dataset location.
#
# Expected location:
#
#     backend/data/mitre/enterprise-attack.json
#
DATASET_PATH = DEFAULT_DATASET_PATH


# =============================================================================
# Async Runner
# =============================================================================


def _run(
    coroutine: Any,
) -> Any:
    """
    Execute one asynchronous CLI operation.

    The CLI normally runs without an active asyncio event loop, therefore
    asyncio.run() provides the lifecycle boundary.
    """

    try:
        return asyncio.run(
            coroutine,
        )

    except KeyboardInterrupt:
        typer.echo(
            "",
        )

        typer.echo(
            "MITRE operation cancelled.",
            err=True,
        )

        raise typer.Exit(
            code=130,
        ) from None


# =============================================================================
# PostgreSQL Session Management
# =============================================================================


def _create_session_manager() -> PostgresSessionManager:
    """
    Create a PostgreSQL session manager using centralized application
    configuration.
    """

    settings = get_settings()

    database_url = getattr(
        settings,
        "database_url",
        None,
    )

    if not database_url:
        raise RuntimeError(
            "PostgreSQL database_url is not configured.",
        )

    return PostgresSessionManager(
        database_url,
    )


# =============================================================================
# Dataset Validation
# =============================================================================


def _resolve_dataset_path(
    dataset_path: Path | None,
) -> Path:
    """
    Resolve and validate the MITRE ATT&CK dataset path.
    """

    path = (
        dataset_path
        if dataset_path is not None
        else DATASET_PATH
    )

    path = Path(
        path,
    ).expanduser()

    if not path.is_absolute():
        path = (
            Path.cwd()
            / path
        )

    path = path.resolve()

    if not path.exists():
        raise RuntimeError(
            "MITRE ATT&CK dataset was not found: "
            f"{path}",
        )

    if not path.is_file():
        raise RuntimeError(
            "MITRE ATT&CK dataset path is not a file: "
            f"{path}",
        )

    if path.stat().st_size <= 0:
        raise RuntimeError(
            "MITRE ATT&CK dataset is empty: "
            f"{path}",
        )

    return path


# =============================================================================
# Formatting Helpers
# =============================================================================


def _print_import_result(
    result: Any,
) -> None:
    """
    Print the canonical MITRE importer result.
    """

    typer.echo(
        "",
    )

    typer.echo(
        "MITRE ATT&CK import completed successfully.",
    )

    typer.echo(
        "",
    )

    fields = (
        (
            "Dataset",
            "dataset_name",
        ),
        (
            "Dataset version",
            "dataset_version",
        ),
        (
            "Objects",
            "object_count",
        ),
        (
            "Tactics",
            "tactic_count",
        ),
        (
            "Techniques",
            "technique_count",
        ),
        (
            "Sub-techniques",
            "subtechnique_count",
        ),
        (
            "Platforms",
            "platform_count",
        ),
        (
            "Relationships",
            "relationship_count",
        ),
        (
            "References",
            "reference_count",
        ),
        (
            "Dataset SHA-256",
            "dataset_hash",
        ),
    )

    for label, attribute in fields:
        value = getattr(
            result,
            attribute,
            None,
        )

        if value is None:
            continue

        typer.echo(
            f"{label}: {value}",
        )

    warnings = getattr(
        result,
        "warnings",
        None,
    )

    if warnings:
        typer.echo(
            "",
        )

        typer.echo(
            "Warnings:",
        )

        for warning in warnings:
            typer.echo(
                f"  - {warning}",
            )


# =============================================================================
# Import Command
# =============================================================================


@mitre.command(
    "import",
)
def import_command(
    dataset: Path | None = typer.Option(
        None,
        "--dataset",
        "-d",
        help=(
            "Path to the Enterprise ATT&CK STIX JSON dataset. "
            "Defaults to backend/data/mitre/enterprise-attack.json."
        ),
        exists=False,
        readable=True,
        resolve_path=True,
    ),
) -> None:
    """
    Import the official MITRE ATT&CK Enterprise STIX dataset into PostgreSQL.

    The import is authoritative and idempotent. Re-running the same dataset
    does not create duplicate knowledge records.
    """

    async def operation() -> Any:
        resolved_dataset = _resolve_dataset_path(
            dataset,
        )

        typer.echo(
            "MITRE ATT&CK import",
        )

        typer.echo(
            f"Dataset: {resolved_dataset}",
        )

        typer.echo(
            "",
        )

        session_manager = _create_session_manager()

        try:
            async with session_manager.session() as session:
                importer = MitreImporter(
                session=session,
                dataset_path=resolved_dataset,
            )

                result = await importer.import_dataset()

                await session.commit()

                return result

        except MitreImportError:
            raise

        except Exception:
            logger.exception(
                "MITRE ATT&CK import failed.",
            )

            raise

    try:
        result = _run(
            operation(),
        )

        _print_import_result(
            result,
        )

    except MitreImportError as exc:
        typer.echo(
            "",
        )

        typer.echo(
            f"MITRE import failed: {exc}",
            err=True,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception as exc:
        typer.echo(
            "",
        )

        typer.echo(
            f"MITRE import failed: {exc}",
            err=True,
        )

        raise typer.Exit(
            code=1,
        ) from None


# =============================================================================
# Status Query
# =============================================================================


async def _collect_status() -> dict[str, Any]:
    """
    Collect PostgreSQL MITRE knowledge statistics.
    """

    session_manager = _create_session_manager()

    async with session_manager.session() as session:

        tactics = await session.scalar(
            select(
                func.count(),
            ).select_from(
                MitreTacticModel,
            ),
        )

        platforms = await session.scalar(
            select(
                func.count(),
            ).select_from(
                MitrePlatformModel,
            ),
        )

        techniques = await session.scalar(
            select(
                func.count(),
            ).select_from(
                MitreTechniqueModel,
            ).where(
                MitreTechniqueModel.type == "TECHNIQUE",
            ),
        )

        subtechniques = await session.scalar(
            select(
                func.count(),
            ).select_from(
                MitreTechniqueModel,
            ).where(
                MitreTechniqueModel.type == "SUB_TECHNIQUE",
            ),
        )

        references = await session.scalar(
            select(
                func.count(),
            ).select_from(
                MitreReferenceModel,
            ),
        )

        relationships = await session.scalar(
            select(
                func.count(),
            ).select_from(
                MitreRelationshipModel,
            ),
        )

        latest_import = await session.scalar(
            select(
                MitreImportModel,
            )
            .order_by(
                MitreImportModel.imported_at.desc(),
            )
            .limit(1),
        )

        return {
            "tactics": int(
                tactics or 0,
            ),
            "platforms": int(
                platforms or 0,
            ),
            "techniques": int(
                techniques or 0,
            ),
            "subtechniques": int(
                subtechniques or 0,
            ),
            "references": int(
                references or 0,
            ),
            "relationships": int(
                relationships or 0,
            ),
            "latest_import": latest_import,
        }


# =============================================================================
# Status Command
# =============================================================================


@mitre.command(
    "status",
)
def status_command() -> None:
    """
    Show the current PostgreSQL MITRE ATT&CK knowledge-base status.
    """

    async def operation() -> dict[str, Any]:
        return await _collect_status()

    try:
        status_data = _run(
            operation(),
        )

    except Exception as exc:
        typer.echo(
            f"Failed to read MITRE status: {exc}",
            err=True,
        )

        raise typer.Exit(
            code=1,
        ) from None

    typer.echo(
        "MITRE ATT&CK Knowledge Status",
    )

    typer.echo(
        "================================",
    )

    typer.echo(
        f"Tactics:         {status_data['tactics']}",
    )

    typer.echo(
        f"Platforms:       {status_data['platforms']}",
    )

    typer.echo(
        f"Techniques:      {status_data['techniques']}",
    )

    typer.echo(
        f"Sub-techniques:  {status_data['subtechniques']}",
    )

    typer.echo(
        f"References:      {status_data['references']}",
    )

    typer.echo(
        f"Relationships:   {status_data['relationships']}",
    )

    latest_import = status_data[
        "latest_import"
    ]

    typer.echo(
        "",
    )

    if latest_import is None:
        typer.echo(
            "Latest import:   None",
        )

        return

    typer.echo(
        "Latest import:",
    )

    typer.echo(
        f"  Dataset:       {latest_import.dataset_name}",
    )

    typer.echo(
        f"  Version:       {latest_import.dataset_version}",
    )

    typer.echo(
        f"  Status:        {latest_import.status}",
    )

    typer.echo(
        f"  Objects:       {latest_import.object_count}",
    )

    typer.echo(
        f"  Imported at:   {latest_import.imported_at}",
    )

    if latest_import.error_message:
        typer.echo(
            f"  Error:         {latest_import.error_message}",
        )


# =============================================================================
# Public API
# =============================================================================


__all__ = [
    "mitre",
]
