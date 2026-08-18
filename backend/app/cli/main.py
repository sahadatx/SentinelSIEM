from __future__ import annotations

import typer

from app.cli.collector import collector
from app.cli.worker import worker
from app.core.version import __version__

cli = typer.Typer(
    name="siem",
    help="SIEM Security Platform operational CLI.",
    no_args_is_help=True,
)


@cli.command()
def version() -> None:
    """Show the application version."""
    typer.echo(__version__)


@cli.command()
def health() -> None:
    """Show local application foundation status."""
    typer.echo("SIEM Security Platform foundation: ready")


cli.command(name="worker")(worker)
cli.command(name="collector")(collector)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
