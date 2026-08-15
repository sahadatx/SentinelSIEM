from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HealthStatus:
    status: str
    service: str
    version: str

    def as_dict(self) -> dict[str, str]:
        return {
            "status": self.status,
            "service": self.service,
            "version": self.version,
        }
