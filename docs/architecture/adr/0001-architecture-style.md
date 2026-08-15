# ADR-0001: Architecture Style

## Status

Accepted

## Context

The SIEM must support high-volume event processing, extensibility, security boundaries, testability, and independent scaling without introducing unnecessary distributed-system complexity at the beginning.

## Decision

Use a **modular monolith with independently scalable workers, event-driven processing, and a plugin system**.

The application will maintain clear domain, application, infrastructure, API, CLI, and extension boundaries.

## Alternatives

### Full Microservices

Rejected for the initial architecture because it introduces operational and distributed-system complexity before it is necessary.

### Monolith Without Worker Separation

Rejected because high-volume SIEM processing requires independently scalable data-plane workers.

### Serverless-First

Rejected because continuous log processing, controlled state, plugins, and predictable deployment boundaries are better served by the selected architecture.

## Consequences

### Positive

- Clear module boundaries
- Easier initial development and testing
- Independent worker scaling
- Event-driven processing
- Plugin extensibility
- Lower operational complexity than premature microservices

### Negative

- Requires disciplined dependency boundaries
- The modular monolith can become tightly coupled if architectural rules are ignored
- Worker and queue lifecycle require careful operational design

## Security Implications

- Domain logic remains isolated from infrastructure.
- Plugin execution has explicit contracts.
- API and storage boundaries are explicit.
- Least privilege can be applied per component.
- The architecture avoids unnecessary network trust boundaries introduced by premature service decomposition.
