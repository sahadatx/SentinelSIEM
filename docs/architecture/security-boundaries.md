# Security Boundaries

## Security Control Map

```text
External Input
    ↓
Input Validation
    ↓
Rate / Size Limits
    ↓
Receiver
    ↓
Queue Isolation
    ↓
Processing Validation
    ↓
Plugin Isolation
    ↓
Detection / Correlation
    ↓
Repository / Storage Boundary
    ↓
Authentication
    ↓
Authorization / RBAC
    ↓
Dashboard / API Consumer
```

## Required Controls

### Input Security
- Validate all externally supplied data.
- Enforce request and event size limits.
- Reject unsafe or malformed input safely.

### Authentication
- Protected control-plane operations require authentication.
- Credential material must not be logged.

### Authorization
- Enforce least privilege.
- Apply role and permission checks at protected boundaries.

### Resource Protection
- Bound queues and buffers.
- Limit expensive searches.
- Bound retries and concurrent connections.
- Protect WebSocket resources.

### Secret Protection
Never log or expose passwords, tokens, API keys, secrets, or credentials.

### Error Handling
External errors must be structured and safe. Internal stack traces and sensitive implementation details must not be exposed.

### Auditability
Security-relevant administrative and workflow actions should be auditable.

### Plugin Security
Plugin execution must have a defined contract, lifecycle, health state, and failure isolation strategy.
