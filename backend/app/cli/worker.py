from __future__ import annotations

import asyncio

import typer

from app.ingestion.worker import run_worker


def worker() -> None:
    """Run the Redis-backed SIEM ingestion worker."""
    try:
        asyncio.run(run_worker())

    except KeyboardInterrupt:
        typer.echo("Worker stopped.")

    except Exception as exc:
        typer.echo(
            f"Worker failed: {exc}",
            err=True,
        )
        raise typer.Exit(code=1) from exc
