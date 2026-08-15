from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FeatureFlags:
    """Phase-02 foundation for explicit feature configuration."""

    experimental_features: bool = False
