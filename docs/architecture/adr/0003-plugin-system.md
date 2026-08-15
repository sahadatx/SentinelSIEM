# ADR-0003: Plugin System

## Status

Accepted

## Context

Collectors, parsers, detectors, and enrichers must be extensible without repeatedly modifying core engines.

## Decision

Use a plugin-first architecture with explicit contracts, discovery, validation, registration, lifecycle management, health reporting, and failure isolation.

Plugin categories:

```text
plugins/collectors/
plugins/parsers/
plugins/detectors/
plugins/enrichers/
```

A plugin contract should support, where applicable:

- unique plugin ID
- name
- description
- version
- author/maintainer
- plugin type
- supported platform/version
- configuration schema
- dependencies
- capabilities
- enabled state
- health status
- initialization
- validation
- shutdown
- error isolation

## Alternatives

### Hard-coded Implementations

Rejected because every new extension would require core engine changes.

### Runtime Code Injection Without Contracts

Rejected because it weakens validation, lifecycle management, and failure isolation.

### Separate Microservice Per Plugin

Rejected for the initial architecture because it adds operational complexity and unnecessary network boundaries.

## Consequences

### Positive

- New extensions can be added with minimal core changes.
- Plugin lifecycle can be standardized.
- Plugin health can be observed.
- Faulty plugins can be isolated.
- Core engines remain generic.

### Negative

- Plugin contracts require careful versioning.
- Third-party code remains a security and supply-chain concern.
- Runtime discovery must be validated and controlled.

## Security Implications

Plugins are treated as a restricted trust boundary. They must be validated, observable, least-privileged where possible, and prevented from bringing down the entire platform.

Plugin failures must not crash the platform.
