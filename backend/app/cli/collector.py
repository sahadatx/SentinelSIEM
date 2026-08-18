from __future__ import annotations

import asyncio

import typer

from app.ingestion.collector_runtime import run_collector


def collector() -> None:
    """Run the TCP-based SIEM collector runtime."""
    try:
        asyncio.run(run_collector())

    except KeyboardInterrupt:
        typer.echo("Collector stopped.")

    except Exception as exc:
        typer.echo(
            f"Collector failed: {exc}",
            err=True,
        )
        raise typer.Exit(code=1) from exc
