# Tracing

Phase 18 preserves the existing `X-Request-ID` correlation mechanism.

OpenTelemetry export is intentionally not enabled here because the current
project baseline does not include an OpenTelemetry dependency or exporter.
The observability interfaces remain compatible with later tracing work.
