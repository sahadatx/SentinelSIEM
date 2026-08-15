# ADR-0002: Storage Strategy

## Status

Accepted

## Context

A SIEM has both high-volume event/search workloads and transactional control-plane workloads. One storage technology is not optimal for all responsibilities.

## Decision

Use:

- **PostgreSQL** for transactional/control-plane data.
- **OpenSearch** for high-volume security events, search, analytics, and aggregations.
- **Redis** for cache, queueing, temporary state, correlation state, and rate limiting.

## Alternatives

### PostgreSQL Only

Rejected for the target high-volume search and analytics workload.

### OpenSearch Only

Rejected because transactional control-plane relationships, constraints, and workflows are better suited to a relational database.

### Redis as Primary Storage

Rejected because Redis is intended for temporary state, queueing, and caching rather than authoritative long-term platform storage.

## Consequences

### Positive

- Clear responsibility per storage system
- Appropriate search engine for event analytics
- Strong relational integrity for control-plane data
- Fast temporary state and queue operations

### Negative

- Multiple operational dependencies
- Cross-system consistency must be designed explicitly
- Backup and recovery procedures must cover multiple systems

## Security Implications

- Each storage system requires least-privilege credentials.
- Network access should be restricted to required components.
- Sensitive data must not be logged.
- Data retention and access controls must be defined per storage role.
- Backup security must protect all three storage systems.
