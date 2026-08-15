from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from app.threat_intelligence.models import IOCType


class IOCNormalizer:
    """Canonicalize IOC values without changing their semantic type."""

    def normalize(self, ioc_type: IOCType, value: str) -> str:
        candidate = value.strip()

        if not candidate:
            raise ValueError("IOC value cannot be empty")

        if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
            address = ipaddress.ip_address(candidate)
            if (
                ioc_type == IOCType.IPV4
                and address.version != 4
            ) or (
                ioc_type == IOCType.IPV6
                and address.version != 6
            ):
                raise ValueError("IP address does not match IOC type")
            return str(address)

        if ioc_type == IOCType.DOMAIN:
            return candidate.rstrip(".").lower()

        if ioc_type == IOCType.HOSTNAME:
            return candidate.rstrip(".").lower()

        if ioc_type == IOCType.EMAIL:
            parts = candidate.rsplit("@", 1)
            if len(parts) != 2 or not all(parts):
                raise ValueError("invalid email IOC")
            return f"{parts[0].lower()}@{parts[1].lower()}"

        if ioc_type == IOCType.URL:
            parsed = urlsplit(candidate)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("URL IOC must be an HTTP(S) URL")
            return candidate.rstrip()

        if ioc_type == IOCType.HASH:
            normalized = candidate.lower()
            if len(normalized) not in {32, 40, 64, 96, 128}:
                raise ValueError("unsupported hash length")
            if any(char not in "0123456789abcdef" for char in normalized):
                raise ValueError("hash contains non-hexadecimal characters")
            return normalized

        raise ValueError(f"unsupported IOC type: {ioc_type}")
