# Phase 15 — API & Real-Time Event Streaming

## Scope

Phase 15 adds the external FastAPI access layer and a bounded WebSocket streaming foundation.

## HTTP API

All public endpoints are versioned under `/api/v1`.

Core resources:

- health
- events
- alerts
- incidents
- detections
- iocs
- assets
- users
- roles
- auth
- mitre
- dashboard
- system

The API layer does not bypass domain managers or repositories. Storage-backed dependencies are injected through `APIContainer`.

## WebSocket

The WebSocket endpoint is `/ws` and supports these channels:

- `events`
- `alerts`
- `incidents`
- `notifications`

The connection manager enforces a maximum connection count and message size, isolates failed clients, and removes stale connections.

## Phase boundary

Authentication/RBAC implementation remains deferred to Phase 17. The frontend remains deferred to Phase 16. Production deployment and performance hardening remain outside Phase 15.
