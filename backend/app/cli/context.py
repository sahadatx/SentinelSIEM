from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings


@dataclass(frozen=True, slots=True)
class CLIContext:
    settings: Settings
