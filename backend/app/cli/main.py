from __future__ import annotations

import typer

from app.cli.collector import collector
from app.cli.commands.database import database
from app.cli.commands.mitre import mitre
from app.cli.worker import worker
from app.core.version import __version__


# =============================================================================
# Root CLI
# =============================================================================

cli = typer.Typer(
    name="siem",
    help="SIEM Security Platform operational CLI.",
    no_args_is_help=True,
)


# =============================================================================
# Core Commands
# =============================================================================


@cli.command()
def version() -> None:
    """Show the application version."""
    typer.echo(__version__)


@cli.command()
def health() -> None:
    """Show local application foundation status."""
    typer.echo(
        "SIEM Security Platform foundation: ready",
    )


# =============================================================================
# Runtime Commands
# =============================================================================


cli.command(
    name="worker",
)(worker)


cli.command(
    name="collector",
)(collector)


# =============================================================================
# Command Groups
# =============================================================================


cli.add_typer(
    database,
)


cli.add_typer(
    mitre,
)


# =============================================================================
# Entry Point
# =============================================================================


def main() -> None:
    """Run the SIEM CLI."""
    cli()


if __name__ == "__main__":
    main()