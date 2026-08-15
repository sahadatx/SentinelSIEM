# Testing Standards

Phase 02 establishes the test foundation.

## Test categories

```text
backend/tests/unit/
backend/tests/integration/
backend/tests/contract/
backend/tests/security/
backend/tests/performance/
backend/tests/resilience/
```

Only tests relevant to Phase 02 are implemented now.

## Requirements

Tests should verify behavior rather than merely increase coverage.

Minimum Phase 02 coverage includes:

- configuration defaults and environment parsing
- safe configuration boundaries
- application health behavior
- lifecycle behavior
- version metadata
- CLI foundation
