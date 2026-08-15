from __future__ import annotations

from collections.abc import Generator

from app.core.config import Settings, get_settings


def settings_dependency() -> Generator[Settings, None, None]:
    yield get_settings()
