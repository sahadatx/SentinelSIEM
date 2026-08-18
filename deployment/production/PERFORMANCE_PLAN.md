# Phase 19 Performance Validation Plan

Use the Phase 18 metrics as the observation layer.

## Baseline

Capture at minimum:

- ingestion submitted/processed rate
- processing failure rate
- ingestion processing latency p50/p95/p99
- detection latency p50/p95/p99
- correlation latency p50/p95/p99
- API request latency p50/p95/p99
- queue depth
- alert creation rate
- PostgreSQL latency/health
- Redis latency/health
- OpenSearch latency/health
- CPU and memory utilization

## Test progression

1. Baseline with no load.
2. Sustained low load.
3. Sustained medium load.
4. Burst load.
5. Dependency failure during load.
6. Recovery and queue drain.
7. Soak test.

Do not treat the example rates from the phase plan as hard production SLAs. Record the actual benchmark environment and measured results before selecting production limits.
