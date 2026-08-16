from __future__ import annotations

from app.core.metrics import MetricsRegistry


def test_metrics_do_not_accept_unbounded_high_cardinality_labels() -> None:
    registry = MetricsRegistry()

    try:
        registry.inc_counter(
            "siem_security_test_total",
            labels={
                "label1": "a",
                "label2": "b",
                "label3": "c",
                "label4": "d",
                "label5": "e",
                "label6": "f",
            },
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Metrics registry accepted excessive label cardinality"
        )
