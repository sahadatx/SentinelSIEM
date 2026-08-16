from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecurityDefaults:
    """Safe baseline values shared by the application foundation."""

    expose_debug_errors: bool = False
    require_environment_secrets: bool = True
    redact_sensitive_logs: bool = True