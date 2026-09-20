"""
Threat Intelligence IOC matching.

Matches an observable against normalized IOC values and returns
domain-level IOCMatch objects.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import IOC, IOCMatch


class IOCMatcher:
    """
    Match observables against IOC records.

    Matching is intentionally deterministic and conservative:
    an observable matches an IOC when the normalized observable
    equals the IOC's normalized value.
    """

    @staticmethod
    def _normalise(value: str) -> str:
        return value.strip().lower()

    @classmethod
    def _ioc_value(cls, ioc: IOC) -> str:
        normalized = getattr(ioc, "normalized_value", None)

        if normalized:
            return cls._normalise(str(normalized))

        return cls._normalise(str(ioc.value))

    @staticmethod
    def _enum_value(value: Any, default: str) -> str:
        if value is None:
            return default

        raw = getattr(value, "value", value)

        if raw is None:
            return default

        return str(raw)

    @classmethod
    def match(
        cls,
        value: str,
        iocs: Iterable[IOC],
    ) -> tuple[IOCMatch, ...]:
        """
        Match a single observable against supplied IOC records.

        Returns only matching IOCMatch records.
        """

        normalized_value = cls._normalise(value)

        if not normalized_value:
            return ()

        matches: list[IOCMatch] = []

        for ioc in iocs:
            if cls._ioc_value(ioc) != normalized_value:
                continue

            matches.append(
                IOCMatch(
                    ioc_id=ioc.ioc_id,
                    ioc_type=ioc.ioc_type,
                    value=ioc.value,
                    confidence=ioc.confidence,
                    severity=cls._enum_value(
                        getattr(ioc, "severity", None),
                        "info",
                    ),
                    status=cls._enum_value(
                        getattr(ioc, "status", None),
                        "active",
                    ),
                    reputation=cls._enum_value(
                        getattr(ioc, "reputation", None),
                        "unknown",
                    ),
                    source=ioc.source,
                    feed=ioc.feed,
                    tags=tuple(ioc.tags or ()),
                )
            )

        return tuple(matches)
