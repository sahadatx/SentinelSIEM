from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded exponential retry policy."""

    max_attempts: int = 3
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 5.0

    def __post_init__(self) -> None:
        """Validate retry policy configuration."""
        if self.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")

        if self.base_delay_seconds < 0:
            raise ValueError("base_delay_seconds must not be negative")

        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds must be >= base_delay_seconds")

    def delay_for(
        self,
        attempt: int,
    ) -> float:
        """Return the bounded exponential delay for a retry attempt."""
        if attempt <= 0:
            raise ValueError("attempt must be positive")

        delay = self.base_delay_seconds * (2 ** (attempt - 1))

        return min(
            self.max_delay_seconds,
            delay,
        )


async def with_retry[T](
    operation: Callable[[], Awaitable[T]],
    *,
    policy: RetryPolicy,
) -> T:
    """Execute an asynchronous operation with bounded retries."""
    last_error: Exception | None = None

    for attempt in range(
        1,
        policy.max_attempts + 1,
    ):
        try:
            return await operation()

        except Exception as exc:
            last_error = exc

            if attempt >= policy.max_attempts:
                break

            await asyncio.sleep(policy.delay_for(attempt))

    if last_error is None:
        raise RuntimeError("Retry operation failed without an exception.")

    raise last_error
