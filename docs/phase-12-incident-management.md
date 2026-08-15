# Phase 12 — Incident Management & Investigation

## Scope

Phase 12 adds an incident domain above the Phase 11 alert layer.

Supported capabilities:

- Alert grouping / linked alerts
- Incident lifecycle
- Investigation notes
- Evidence records
- Incident timeline
- Assignment and ownership
- Related events
- Related IOCs as references
- Assets
- Response/containment state
- Incident audit trail

## Lifecycle

```text
NEW
 ↓
INVESTIGATING
 ↓
CONTAINED
 ↓
RESOLVED
 ↓
CLOSED
```

`CONTAINED -> INVESTIGATING` and `RESOLVED -> INVESTIGATING` are supported for controlled recovery/reopening during investigation.

## Phase boundary

This phase intentionally does not implement:

- Threat intelligence feed ingestion
- IOC feed synchronization
- MITRE ATT&CK mapping
- FastAPI routes
- WebSocket streaming
- Dashboard UI
- Authentication/RBAC
- Persistent production database integration
- Deployment

Those capabilities remain in their roadmap phases.

## Architecture

```text
Phase 11 Alert
      ↓
IncidentManager
      ├── Lifecycle
      ├── Investigation
      ├── Evidence
      ├── Timeline
      ├── Assignment
      └── Audit
```

The implementation is an in-memory application/domain layer, consistent with the current pre-production phase boundary.
