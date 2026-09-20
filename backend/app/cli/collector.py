from __future__ import annotations

import asyncio

import typer

from app.ingestion.collector_runtime import run_collector


def collector() -> None:
    """
    Run the TCP-based SIEM collector runtime.

    The collector runtime is responsible for:
        - Starting the configured TCP collector.
        - Receiving incoming raw events.
        - Converting payloads into RawEvent instances.
        - Enqueuing events into the Redis ingestion queue.
        - Managing the collector lifecycle.
    """

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


def main() -> None:
    """
    CLI entrypoint for the collector.

    This function is intentionally separate from ``collector()``
    so the module can be executed directly with:

        python -m app.cli.collector
    """

    collector()


if __name__ == "__main__":
    main()


__all__ = [
    "collector",
    "main",
]