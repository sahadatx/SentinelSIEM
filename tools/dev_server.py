"""
SentinelSIEM Development Server
================================

Runs the FastAPI backend and Vite frontend together for local development.

Developer workflow:

    Edit -> Save -> Browser Refresh

Browser entrypoint:

    http://localhost:8000

Architecture:

    Browser :8000
        |
        v
    Vite Dev Server
        |
        +-- Frontend
        |
        +-- /api/* -> FastAPI :8001
        |
        +-- /ws/*  -> FastAPI :8001

The backend is automatically reloaded when Python source files change.

The frontend is served directly from the Vite development server.

The repository .env file is never modified by this module.

Development-only environment overrides are applied to child processes.

IMPORTANT:

    This launcher must remain lightweight.

    The parent supervisor MUST NOT use a busy loop.
    Child process status checks are throttled with Event.wait().

===============================================================================
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path


# ============================================================================
# Project Configuration
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8001

FRONTEND_HOST = "127.0.0.1"
FRONTEND_PORT = 8000

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379

SUPERVISOR_INTERVAL_SECONDS = 0.25
PROCESS_TERMINATE_TIMEOUT_SECONDS = 5.0


# ============================================================================
# Development Environment
# ============================================================================


def _environment() -> dict[str, str]:
    """
    Build the environment for development child processes.

    The repository .env file is never modified.

    Development overrides:

        SIEM_ENVIRONMENT=development
        ENVIRONMENT=development

    Redis is normalized from Docker hostname to host localhost when needed.
    """

    environment = os.environ.copy()

    # ------------------------------------------------------------------------
    # Application environment
    # ------------------------------------------------------------------------

    environment["SIEM_ENVIRONMENT"] = "development"
    environment["ENVIRONMENT"] = "development"

    # ------------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------------
    #
    # FastAPI runs directly on the host.
    #
    # Docker:
    #
    #     redis:6379
    #
    # Host:
    #
    #     127.0.0.1:6379
    #
    # Keep existing credentials/database configuration whenever possible.
    #

    redis_url = environment.get("REDIS_URL")

    if redis_url:
        redis_url = redis_url.replace(
            "@redis:6379",
            f"@{REDIS_HOST}:{REDIS_PORT}",
        )

        redis_url = redis_url.replace(
            "redis://redis:6379",
            f"redis://{REDIS_HOST}:{REDIS_PORT}",
        )

        environment["REDIS_URL"] = redis_url

    else:
        environment["REDIS_URL"] = (
            f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
        )

    return environment


# ============================================================================
# Executable Resolution
# ============================================================================


def _npm_command() -> str:
    """
    Resolve the npm executable.

    Prefer PATH resolution so the launcher works with normal Linux Node.js
    installations while remaining simple and predictable.
    """

    npm = "npm"

    if os.name == "nt":
        npm = "npm.cmd"

    return npm


# ============================================================================
# Backend
# ============================================================================


def _start_backend(
    environment: dict[str, str],
) -> subprocess.Popen[str]:
    """
    Start FastAPI with Uvicorn automatic reload.

    Uvicorn handles Python source watching/reloading.
    """

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--app-dir",
        str(BACKEND_DIR),
        "--host",
        BACKEND_HOST,
        "--port",
        str(BACKEND_PORT),
        "--reload",
    ]

    print(
        "[SentinelSIEM] Starting FastAPI on "
        f"http://{BACKEND_HOST}:{BACKEND_PORT}",
        flush=True,
    )

    return subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        text=True,
    )


# ============================================================================
# Frontend
# ============================================================================


def _start_frontend(
    environment: dict[str, str],
) -> subprocess.Popen[str]:
    """
    Start the Vite development server.

    Vite runs on the browser-facing port 8000.
    """

    command = [
        _npm_command(),
        "run",
        "dev",
        "--",
        "--host",
        FRONTEND_HOST,
        "--port",
        str(FRONTEND_PORT),
    ]

    print(
        "[SentinelSIEM] Starting Vite on "
        f"http://localhost:{FRONTEND_PORT}",
        flush=True,
    )

    return subprocess.Popen(
        command,
        cwd=FRONTEND_DIR,
        env=environment,
        text=True,
    )


# ============================================================================
# Process Management
# ============================================================================


def _terminate_process(
    process: subprocess.Popen[str],
) -> None:
    """
    Gracefully terminate a child process.

    If the process does not stop within the configured timeout,
    forcefully kill it.
    """

    if process.poll() is not None:
        return

    try:
        process.terminate()

        process.wait(
            timeout=PROCESS_TERMINATE_TIMEOUT_SECONDS,
        )

    except subprocess.TimeoutExpired:
        process.kill()

        process.wait()


def _shutdown_processes(
    processes: list[subprocess.Popen[str]],
) -> None:
    """
    Stop all development child processes.

    Children are stopped in reverse startup order.
    """

    for process in reversed(processes):
        _terminate_process(process)


# ============================================================================
# Main Development Runner
# ============================================================================


def main() -> int:
    """
    Start and supervise the development processes.

    One command starts:

        FastAPI :8001
        Vite    :8000

    Browser entrypoint:

        http://localhost:8000
    """

    environment = _environment()

    processes: list[subprocess.Popen[str]] = []

    shutdown_event = threading.Event()

    shutting_down = False

    # ------------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------------

    def shutdown(*_: object) -> None:
        """
        Handle Ctrl+C and termination signals.

        Shutdown is idempotent so repeated signals do not attempt to
        terminate the same processes multiple times.
        """

        nonlocal shutting_down

        if shutting_down:
            return

        shutting_down = True

        shutdown_event.set()

        print(
            "\n[SentinelSIEM] "
            "Shutting down development servers...",
            flush=True,
        )

        _shutdown_processes(processes)

    signal.signal(
        signal.SIGINT,
        shutdown,
    )

    signal.signal(
        signal.SIGTERM,
        shutdown,
    )

    # ------------------------------------------------------------------------
    # Start backend
    # ------------------------------------------------------------------------

    try:
        backend = _start_backend(environment)
        processes.append(backend)

        # ---------------------------------------------------------------
        # Start frontend
        # ---------------------------------------------------------------

        frontend = _start_frontend(environment)
        processes.append(frontend)

    except Exception:
        shutdown()
        raise

    # ------------------------------------------------------------------------
    # Startup information
    # ------------------------------------------------------------------------

    print(
        "\n"
        "==============================================\n"
        " SentinelSIEM Development Environment\n"
        "==============================================\n"
        "\n"
        " Browser : http://localhost:8000\n"
        " Backend : http://localhost:8001\n"
        " Redis   : 127.0.0.1:6379\n"
        "\n"
        " Workflow:\n"
        "   Edit -> Save -> Browser Refresh\n"
        "\n"
        " Frontend changes:\n"
        "   Served directly by Vite\n"
        "\n"
        " Backend changes:\n"
        "   Automatically reloaded by Uvicorn\n"
        "\n"
        " Infrastructure:\n"
        "   Redis is accessed from the host\n"
        "\n"
        " Supervisor:\n"
        "   Low-CPU event-based process monitoring\n"
        "\n"
        " Press Ctrl+C to stop.\n",
        flush=True,
    )

    # ------------------------------------------------------------------------
    # Process supervision
    # ------------------------------------------------------------------------
    #
    # IMPORTANT:
    #
    # Do NOT use:
    #
    #     while True:
    #         process.poll()
    #
    # without a blocking wait.
    #
    # Event.wait() allows the supervisor thread/process to sleep efficiently.
    #

    try:
        while not shutdown_event.is_set():
            for process in processes:
                return_code = process.poll()

                if return_code is None:
                    continue

                if process is backend:
                    print(
                        "[SentinelSIEM] Backend process stopped "
                        f"with code {return_code}.",
                        flush=True,
                    )
                else:
                    print(
                        "[SentinelSIEM] Frontend process stopped "
                        f"with code {return_code}.",
                        flush=True,
                    )

                shutdown()

                return return_code

            shutdown_event.wait(
                timeout=SUPERVISOR_INTERVAL_SECONDS,
            )

    except KeyboardInterrupt:
        shutdown()

        return 0

    finally:
        if not shutting_down:
            shutdown()

    return 0


# ============================================================================
# Entry Point
# ============================================================================


if __name__ == "__main__":
    raise SystemExit(main())