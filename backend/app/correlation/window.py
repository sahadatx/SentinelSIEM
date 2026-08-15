from __future__ import annotations

from datetime import datetime, timedelta


def within_window(start: datetime, current: datetime, seconds: int) -> bool:
    if current < start:
        return False
    return current - start <= timedelta(seconds=seconds)
