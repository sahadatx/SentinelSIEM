from app.ingestion.backpressure import BackpressurePolicy


def test_backpressure_policy_throttles_at_high_watermark() -> None:
    policy = BackpressurePolicy(max_queue_size=100, high_watermark=0.8)

    assert policy.accepts(79)
    assert policy.throttled(80)
    assert not policy.accepts(100)
