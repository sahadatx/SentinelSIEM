# Availability

## 1. Availability Objective

The platform should degrade gracefully rather than fail completely when individual dependencies or processing components become unavailable.

## 2. PostgreSQL Failure

Expected architecture:

```text
Database Failure
    ↓
Health State = Degraded
    ↓
Safe Retry / Recovery
    ↓
Resume Normal Operation
```

The exact recovery mechanism is deployment-specific and must be validated in later resilience phases.

## 3. OpenSearch Failure

The ingestion/data-plane design should preserve events through queueing/buffering where capacity allows, while clearly exposing degraded search/storage health.

## 4. Redis Failure

Redis failure should be visible through health checks. Components must avoid unsafe behavior when temporary state, queueing, or caching is unavailable.

## 5. Worker Failure

Queue-based processing permits replacement/recovery workers to continue processing retained work.

## 6. Plugin Failure

A faulty plugin must not crash the entire platform. Plugin failures must be isolated and observable.

## 7. API Failure

API instances should be horizontally replaceable where the deployment environment supports it.

## 8. Health States

The architecture supports:

- liveness
- readiness
- dependency health
- worker health
- plugin health
- degraded operation

## 9. Limitations

High availability guarantees are deployment-specific and are not claimed as implemented until validated in later phases.
