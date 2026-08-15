from __future__ import annotations

from datetime import UTC, datetime

from app.threat_intelligence.models import IOCType


class IOCValidator:
    """Validate semantic constraints before IOC creation."""

    def validate(
        self,
        ioc_type: IOCType,
        normalized_value: str,
        expiration: datetime | None,
    ) -> None:
        """Validate a normalized IOC and its optional expiration."""
        if not normalized_value.strip():
            raise ValueError("normalized IOC value cannot be empty")

        if expiration is not None:
            if (
                expiration.tzinfo is None
                or expiration.utcoffset() is None
            ):
                raise ValueError("expiration must be timezone-aware")

            if expiration <= datetime.now(UTC):
                raise ValueError("expiration must be in the future")

        if (
            ioc_type in {IOCType.DOMAIN, IOCType.HOSTNAME}
            and "." not in normalized_value
        ):
            raise ValueError("domain/hostname must contain a dot")
