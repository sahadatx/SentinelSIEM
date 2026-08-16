# SentinelSIEM Metrics

The application exposes Prometheus-compatible metrics at `/metrics`.

Required operational metric families for Phase 18 are:

- HTTP request count and latency
- processing failures
- detection latency
- correlation latency
- queue depth
- alert rate
- PostgreSQL latency/health
- OpenSearch latency
- Redis health
- worker health
- plugin health
- dead-letter events

Metric labels must remain bounded and low-cardinality. Never use request IDs,
URLs, usernames, IP addresses, tokens, raw events, or other user-controlled
values as labels.
