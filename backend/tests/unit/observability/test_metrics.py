from __future__ import annotations

import pytest

from app.core.metrics import MetricsRegistry


def test_counter_and_gauge_render_prometheus() -> None:
    registry = MetricsRegistry()

    registry.inc_counter(
        "siem_test_requests_total",
        help_text="Test requests.",
        labels={"method": "GET"},
    )

    registry.set_gauge(
        "siem_test_ready",
        1,
        help_text="Test readiness.",
    )

    output = registry.render()

    assert "# TYPE siem_test_requests_total counter" in output
    assert 'siem_test_requests_total{method="GET"} 1' in output
    assert "siem_test_ready 1" in output


def test_metric_names_and_labels_are_bounded() -> None:
    registry = MetricsRegistry()

    with pytest.raises(ValueError):
        registry.set_gauge("bad-name", 1)

    with pytest.raises(ValueError):
        registry.set_gauge(
            "valid_metric",
            1,
            labels={"request_id": "x" * 65},
        )


def test_histogram_render_contains_count_sum_and_inf() -> None:
    registry = MetricsRegistry()

    registry.observe(
        "siem_test_latency_seconds",
        0.2,
        help_text="Test latency.",
    )

    output = registry.render()

    assert "siem_test_latency_seconds_bucket" in output
    assert 'le="+Inf"' in output
    assert "siem_test_latency_seconds_count 1" in output
    assert "siem_test_latency_seconds_sum 0.2" in output
