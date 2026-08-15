# System Architecture

## Status

Phase 01 architecture baseline.

## 1. Purpose

The SIEM Security Platform is designed as a modular, scalable, secure, testable, observable, resilient, plugin-based security monitoring platform.

Its security-monitoring lifecycle is:

```text
Collect → Ingest → Parse → Normalize → Enrich → Detect
→ Correlate → Risk Score → Prioritize → Alert → Investigate
→ Incident Response → Threat Intelligence → MITRE ATT&CK Mapping
→ Dashboard → Reporting
```

## 2. Architecture Style

The initial deployment architecture is a **modular monolith with independently scalable workers**, event-driven processing, and a plugin system.

The architecture intentionally avoids unnecessary microservice decomposition.

## 3. Layered Architecture

```text
Presentation
    ↓
API / CLI
    ↓
Application Services
    ↓
Domain Logic
    ↓
Infrastructure
    ↓
Storage / Messaging / External Systems
```

Domain logic must not directly depend on infrastructure implementations. Application services depend on abstractions such as repository interfaces.

## 4. Data Plane

```text
Collectors
    ↓
Receivers
    ↓
Queue
    ↓
Ingestion
    ↓
Parsing
    ↓
Normalization
    ↓
Enrichment
    ↓
Detection
    ↓
Correlation
    ↓
Risk Scoring
    ↓
Alerting
```

The data plane processes untrusted security telemetry and must tolerate malformed input, dependency failures, overload, and plugin failures.

## 5. Control Plane

```text
Dashboard
    ↓
REST API
    ↓
Application Services
    ↓
Configuration / Rules / Plugins / Users / RBAC / System Administration
```

CLI and dashboard operations must share application services rather than duplicate business logic.

## 6. Core Responsibilities

| Component | Responsibility |
|---|---|
| Collectors | Obtain telemetry from supported sources |
| Receivers | Accept telemetry through supported transport mechanisms |
| Queue | Buffer and decouple ingestion from processing |
| Parsing | Convert source-specific raw data into structured data |
| Normalization | Produce a canonical event representation |
| Enrichment | Add contextual security information |
| Detection | Evaluate detection rules |
| Correlation | Combine multiple events into higher-confidence patterns |
| Risk | Calculate explainable risk and priority |
| Alerts | Manage alert lifecycle |
| Incidents | Manage investigations and response workflow |
| Threat Intelligence | Normalize, match, and enrich with IOC intelligence |
| MITRE | Map detections and coverage to ATT&CK concepts |
| API | Provide controlled programmatic access |
| Dashboard | Provide SOC visualization and workflows |
| Plugins | Extend collectors, parsers, detectors, and enrichers |

## 7. Storage Responsibilities

- PostgreSQL: control-plane relational data such as users, roles, permissions, alerts, incidents, IOC metadata, configuration, and audit records.
- OpenSearch: high-volume security events, search, analytics, and aggregations.
- Redis: cache, queues, temporary state, correlation state, and rate-limiting state.

## 8. Security Principles

- Treat logs and events as untrusted input.
- Enforce least privilege.
- Validate inputs at trust boundaries.
- Do not expose secrets or sensitive configuration.
- Do not leak internal exception details through external interfaces.
- Isolate plugin failures.
- Bound queues, requests, queries, retries, and concurrent connections.
- Preserve auditability for security-relevant actions.
- Design for TLS-secured deployment.

## 9. Reliability Principles

The platform must support graceful degradation for PostgreSQL, OpenSearch, Redis, queues, workers, plugins, and external integrations.

Retries must use bounded backoff and must not create unsafe retry storms. Operations that may be retried must have an appropriate idempotency strategy.

## 10. Scalability Principles

The design permits horizontal scaling of API instances, workers, collectors, queue consumers, and OpenSearch capacity while avoiding unnecessary global mutable state.

## 11. Architectural Constraints

- Preserve the locked project directory structure.
- Keep responsibilities separated.
- Prefer interfaces and dependency inversion.
- Do not hard-code plugin implementations into core engines.
- Do not move business logic into the CLI.
- Do not introduce premature microservices.
- Do not implement future-phase functionality in Phase 01.
