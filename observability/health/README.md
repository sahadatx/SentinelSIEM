# Health

Phase 18 distinguishes liveness from readiness.

- Liveness answers whether the application process is alive.
- Readiness checks required runtime dependencies when they are configured.
- Dependency failure must return a `not_ready` state rather than exposing
  connection details or exception text.
