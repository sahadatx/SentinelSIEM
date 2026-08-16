from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import (
    DEFAULT_APP_NAME,
    DEFAULT_ENVIRONMENT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
)
from app.core.exceptions import ConfigurationError


class Settings(BaseSettings):
    """Validated runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="SIEM_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    app_name: str = Field(
        default=DEFAULT_APP_NAME,
        min_length=1,
        max_length=100,
    )

    environment: str = Field(
        default=DEFAULT_ENVIRONMENT,
        min_length=1,
        max_length=32,
    )

    debug: bool = False

    log_level: str = DEFAULT_LOG_LEVEL

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    api_host: str = "127.0.0.1"

    api_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
    )

    max_request_bytes: int = Field(
        default=DEFAULT_MAX_REQUEST_BYTES,
        ge=1,
        le=100_000_000,
    )

    shutdown_timeout_seconds: int = Field(
        default=DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
        ge=1,
        le=300,
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    database_url: str | None = Field(
        default=None,
        min_length=1,
    )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    auth_secret_key: str | None = None

    auth_algorithm: str = "HS256"

    auth_access_token_expire_minutes: int = Field(
        default=30,
        ge=1,
        le=1440,
    )

    auth_issuer: str = "sentinelsiem"

    auth_audience: str = "sentinelsiem-api"

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()

        allowed = {
            "CRITICAL",
            "ERROR",
            "WARNING",
            "INFO",
            "DEBUG",
        }

        if normalized not in allowed:
            raise ValueError(
                f"Unsupported log level: {value}"
            )

        return normalized

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        normalized = value.lower()

        allowed = {
            "development",
            "test",
            "staging",
            "production",
        }

        if normalized not in allowed:
            raise ValueError(
                f"Unsupported environment: {value}"
            )

        return normalized

    @field_validator("auth_algorithm")
    @classmethod
    def validate_auth_algorithm(cls, value: str) -> str:
        normalized = value.upper()

        allowed = {
            "HS256",
        }

        if normalized not in allowed:
            raise ValueError(
                f"Unsupported authentication algorithm: {value}"
            )

        return normalized

    @field_validator("database_url")
    @classmethod
    def validate_database_url(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            return None

        allowed_prefixes = (
            "postgresql+asyncpg://",
        )

        if not normalized.startswith(allowed_prefixes):
            raise ValueError(
                "SIEM_DATABASE_URL must use the "
                "postgresql+asyncpg:// scheme."
            )

        return normalized

    # ------------------------------------------------------------------
    # Cross-field security validation
    # ------------------------------------------------------------------

    def validate_security_configuration(self) -> None:
        """
        Validate security-sensitive runtime configuration.

        Authentication and database configuration must be explicitly
        available in staging and production environments.
        """

        if self.environment in {
            "staging",
            "production",
        }:
            # ----------------------------------------------------------
            # Authentication secret
            # ----------------------------------------------------------

            if not self.auth_secret_key:
                raise ValueError(
                    "SIEM_AUTH_SECRET_KEY must be configured "
                    "in staging or production."
                )

            if len(self.auth_secret_key) < 32:
                raise ValueError(
                    "SIEM_AUTH_SECRET_KEY must contain at least "
                    "32 characters."
                )

            # ----------------------------------------------------------
            # Database
            # ----------------------------------------------------------

            if not self.database_url:
                raise ValueError(
                    "SIEM_DATABASE_URL must be configured "
                    "in staging or production."
                )

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def database_configured(self) -> bool:
        """Return whether a PostgreSQL database URL is configured."""

        return self.database_url is not None

    @property
    def authentication_configured(self) -> bool:
        """Return whether the authentication secret is configured."""

        return bool(self.auth_secret_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Load and cache validated application settings.

    Configuration errors are wrapped so callers do not receive
    sensitive configuration details.
    """

    try:
        settings = Settings()
        settings.validate_security_configuration()
        return settings

    except Exception as exc:
        raise ConfigurationError(
            "Application configuration is invalid."
        ) from exc
