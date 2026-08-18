# SentinelSIEM Phase 19 — Performance, Hardening & Production Deployment

This archive is the **Phase 19 deployment/hardening bundle** for the existing SentinelSIEM repository.

## Scope

- Production-oriented Dockerfiles for backend, frontend, worker, and collector images
- Docker Compose development/production topologies
- Nginx reverse proxy configuration
- Kubernetes manifests for the core services
- Production environment contract and deployment notes
- Explicit runtime command injection for worker/collector services so no nonexistent application entrypoint is invented
- Non-root containers, minimal runtime images, health checks, resource limits, and secret placeholders

## Important integration note

The model environment does not have direct write access to the user's live `~/Projects/SentinelSIEM` checkout. Therefore this archive intentionally contains the **Phase 19 deployment overlay**, not a falsely claimed full post-Phase-18 repository snapshot.

Before applying it to the live repository:

1. Copy the `deployment/` tree into the repository.
2. Review `deployment/production/.env.example` and create real secrets outside Git.
3. Set the real worker and collector commands (`WORKER_COMMAND`, `COLLECTOR_COMMAND`) to the entrypoints that exist in the current checkout.
4. Build and smoke-test the backend/frontend images before enabling the production Compose or Kubernetes manifests.

Phase 19 hardening of existing Python runtime code (for example `config.py`/`lifecycle.py`) must be applied and validated against the live Phase 18 tree rather than blindly replacing files from this bundle.
