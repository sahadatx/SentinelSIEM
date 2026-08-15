# Phase 06 — Storage & Search Layer

## Scope

Phase 06 introduces repository boundaries and adapters for PostgreSQL, OpenSearch, and Redis.

- PostgreSQL: async SQLAlchemy session lifecycle for structured/control-plane repositories.
- OpenSearch: high-volume security-event persistence and search.
- Redis: cache/state key-value access with explicit TTL.
- Repositories isolate application services from storage clients.

Domain-specific repositories for alerts, incidents, IOC metadata, users, roles, and permissions are intentionally deferred to their owning roadmap phases.

## Storage boundaries

```text
EnrichedEvent
     |
     v
EventRepository
     |
     +--> OpenSearchEventRepository
     |
     +--> future repository implementations

Control-plane repository
     |
     +--> PostgreSQL / SQLAlchemy

Temporary state / cache
     |
     +--> RedisKeyValueRepository
```

## Security

- PostgreSQL requires the `postgresql+asyncpg://` scheme.
- OpenSearch TLS certificate verification is enabled by default in the client wrapper.
- Redis values are bytes and TTL is explicit.
- OpenSearch mappings use strict dynamic mapping to reduce accidental schema drift.
- Repository interfaces prevent business services from depending directly on storage clients.

## Validation

Unit tests use fakes and do not require external services. Real integration validation requires PostgreSQL, OpenSearch, and Redis instances and must be performed before the Phase 06 gate is closed.
