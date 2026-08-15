from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BackpressurePolicy:
    max_queue_size: int
    high_watermark: float = 0.8

    def __post_init__(self) -> None:
        if self.max_queue_size <= 0:
            raise ValueError("max_queue_size must be positive")
        if not 0 < self.high_watermark <= 1:
            raise ValueError("high_watermark must be in (0, 1]")

    @property
    def high_watermark_size(self) -> int:
        return max(1, int(self.max_queue_size * self.high_watermark))

    def accepts(self, queue_size: int) -> bool:
        if queue_size < 0:
            raise ValueError("queue_size must not be negative")
        return queue_size < self.max_queue_size

    def throttled(self, queue_size: int) -> bool:
        if queue_size < 0:
            raise ValueError("queue_size must not be negative")
        return queue_size >= self.high_watermark_size
