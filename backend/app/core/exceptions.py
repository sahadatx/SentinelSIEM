from __future__ import annotations


class ApplicationError(Exception):
    """Base exception for controlled application errors."""


class ConfigurationError(ApplicationError):
    """Raised when application configuration is invalid."""


class LifecycleError(ApplicationError):
    """Raised when an application lifecycle operation fails."""
