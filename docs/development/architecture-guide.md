# Architecture Guide

The project follows the Phase 01 architecture:

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

Phase 02 establishes only the shared foundation. Future domain modules must not
couple directly to concrete infrastructure implementations.

The CLI is an operational interface and must call application services rather
than contain business logic.
