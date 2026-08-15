# Data Flow

## 1. End-to-End Security Event Lifecycle

```text
External Source
    ↓
Collector
    ↓
Receiver
    ↓
Queue
    ↓
Ingestion
    ↓
Parser
    ↓
Normalizer
    ↓
Enricher
    ↓
Canonical Security Event
    ↓
Detection
    ↓
Correlation
    ↓
Risk Scoring
    ↓
Prioritization
    ↓
Alert
    ↓
Investigation / Incident
    ↓
Dashboard / Reporting
```

## 2. Event Transformation

```text
Raw Event
    ↓
Parsed Event
    ↓
Normalized Event
    ↓
Canonical Security Event
    ↓
Enriched Security Event
```

## 3. Failure Paths

### Malformed Event

```text
Malformed Event → Validation / Error Handling → DLQ or controlled rejection
```

Malformed input must not crash the ingestion pipeline.

### Queue Overload

```text
High Input Rate → Backpressure → Bounded Buffering → Controlled Processing
```

### Temporary Dependency Failure

```text
Dependency Failure → Health Detection → Bounded Retry / Recovery → Degraded Operation
```

### Worker Failure

```text
Worker Failure → Queue Preserves Work → Replacement/Recovery Worker → Continue Processing
```

## 4. Trust Considerations

All externally supplied telemetry is untrusted until validated and normalized. Enrichment data must not be allowed to override trusted security controls or create unsafe execution paths.

## 5. Idempotency

The architecture should support event identifiers, deduplication keys, processing state, unique constraints, and idempotency keys where appropriate.

## 6. Backpressure and Resource Safety

The processing path must define limits for event size, queue depth, memory, concurrency, query cost, retry count, and WebSocket connections.
