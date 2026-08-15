import pytest

from app.ingestion.retry import RetryPolicy, with_retry


@pytest.mark.anyio
async def test_retry_succeeds_after_transient_failures() -> None:
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError("temporary")
        return "ok"

    result = await with_retry(
        operation,
        policy=RetryPolicy(max_attempts=3, base_delay_seconds=0),
    )

    assert result == "ok"
    assert attempts == 3
