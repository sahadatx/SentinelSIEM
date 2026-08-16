from __future__ import annotations

from app.core.metrics import MetricsRegistry


def test_metrics_registry_basic_recording_is_bounded() -> None:
    registry = MetricsRegistry()

    for _ in range(1000):
        registry.inc_counter(
            "siem_perf_requests_total",
            help_text="Performance test.",
            labels={"method": "GET"},
        )

    output = registry.render()

    assert 'siem_perf_requests_total{method="GET"} 1000' in output
