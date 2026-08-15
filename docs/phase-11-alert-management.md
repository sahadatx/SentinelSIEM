# Phase 11 — Alert Management

## Scope

Phase 11 converts detection/correlation results into managed alerts and provides the alert lifecycle required by the master roadmap.

## Lifecycle

```text
NEW
 ↓
ACKNOWLEDGED
 ↓
INVESTIGATING
 ↓
ESCALATED
 ↓
RESOLVED
 ↓
CLOSED
```

Alternative terminal path:

```text
NEW → SUPPRESSED
```

## Responsibilities

- Alert creation from detection/correlation results
- Stable deduplication keys
- Duplicate occurrence aggregation
- Explicit lifecycle transition validation
- Suppression policy
- Escalation policy
- Assignment and ownership
- SLA timestamp field
- Immutable audit history
- Notification adapter boundary

## Design boundaries

Phase 11 does not implement incident management, threat-intelligence ingestion, MITRE mapping, REST/WebSocket APIs, dashboard behavior, authentication/RBAC, or production deployment. Those remain in their later roadmap phases.

The default manager is deterministic and in-memory for unit/integration validation. Persistence is intentionally kept behind the application boundary so storage-specific concerns do not leak into the alert domain.
