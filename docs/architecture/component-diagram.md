# Component Diagram

## Logical Component View

```text
                         ┌──────────────────────┐
                         │ External Log Sources │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │      Collectors      │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │      Receivers       │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Queue / Messaging  │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │     Ingestion        │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │ Parse / Normalize /  │
                         │       Enrich         │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │ Detection /          │
                         │ Correlation / Risk   │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │ Alerts / Incidents   │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
             ┌──────▼──────┐                 ┌──────▼──────┐
             │ REST API     │                 │ WebSocket   │
             └──────┬──────┘                 └──────┬──────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                             ┌──────▼──────┐
                             │  Dashboard  │
                             └─────────────┘

Storage / State:
  PostgreSQL | OpenSearch | Redis

Extension:
  Collectors | Parsers | Detectors | Enrichers
```

## Component Boundary Rule

Each component owns a clear responsibility. Core engines discover and interact with extension points rather than hard-coding individual plugins.
