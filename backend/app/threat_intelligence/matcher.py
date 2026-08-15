from __future__ import annotations

from app.threat_intelligence.models import IOC, IOCMatch


class IOCMatcher:
    """Match normalized observables against active IOCs."""

    def match(self, value: str, iocs: list[IOC]) -> list[IOCMatch]:
        candidate = value.strip().lower()
        matches: list[IOCMatch] = []

        for ioc in iocs:
            if ioc.normalized_value.lower() != candidate:
                continue

            matches.append(
                IOCMatch(
                    ioc_id=ioc.ioc_id,
                    ioc_type=ioc.ioc_type,
                    value=ioc.normalized_value,
                    confidence=ioc.confidence,
                    reputation=ioc.reputation,
                    source=ioc.source,
                )
            )

        return matches
