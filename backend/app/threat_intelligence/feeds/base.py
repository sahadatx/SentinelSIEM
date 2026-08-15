from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from app.threat_intelligence.models import IOCCreate


class ThreatIntelFeed(Protocol):
    """Contract implemented by external threat-intelligence feed plugins."""

    @property
    def name(self) -> str:
        ...

    def fetch(self) -> Iterable[IOCCreate]:
        ...
