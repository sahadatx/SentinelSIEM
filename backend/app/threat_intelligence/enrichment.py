from __future__ import annotations

from app.threat_intelligence.matcher import IOCMatcher
from app.threat_intelligence.models import IOC, IOCMatch


class IOCEnricher:
    """Attach threat-intelligence matches to an observable."""

    def __init__(self, matcher: IOCMatcher | None = None) -> None:
        self._matcher = matcher or IOCMatcher()

    def enrich(self, value: str, iocs: list[IOC]) -> tuple[IOCMatch, ...]:
        return tuple(self._matcher.match(value, iocs))
