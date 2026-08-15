# Scalability

## 1. Scaling Objectives

The platform should support horizontal scaling of:

- API instances
- Data-processing workers
- Collectors
- Queue consumers
- OpenSearch capacity
- PostgreSQL read capacity where required
- Redis usage according to workload

## 2. Worker Scaling

```text
Queue
 ├── Worker 1
 ├── Worker 2
 ├── Worker 3
 └── Worker N
```

Work should be partitionable without requiring shared mutable global state.

## 3. API Scaling

```text
Load Balancer / Reverse Proxy
        │
   ┌────┼────┐
   ▼    ▼    ▼
 API-1 API-2 API-N
```

API instances should remain as stateless as practical.

## 4. Resource Safety

The design must bound:

- event size
- queue depth
- memory usage
- processing concurrency
- expensive queries
- WebSocket connections
- retries
- external requests

## 5. Capacity Signals

Important operational signals include:

- events per second
- processing latency
- queue depth
- dropped/DLQ events
- CPU
- memory
- PostgreSQL latency
- OpenSearch latency
- Redis health
- detection latency
- correlation latency
- API latency

## 6. Scaling Principle

Scale based on measured bottlenecks and workload evidence rather than introducing premature complexity.
