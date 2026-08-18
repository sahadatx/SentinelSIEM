from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, field_validator
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
    """Validated SentinelSIEM runtime configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SIEM_",
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
    # PostgreSQL
    # ------------------------------------------------------------------

    database_url: str | None = Field(
        default=None,
        min_length=1,
    )

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------

    redis_url: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices(
            "SIEM_REDIS_URL",
            "REDIS_URL",
        ),
    )

    # ------------------------------------------------------------------
    # OpenSearch
    # ------------------------------------------------------------------

    opensearch_url: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices(
            "SIEM_OPENSEARCH_URL",
            "OPENSEARCH_URL",
        ),
    )

    opensearch_username: str = Field(
        default="admin",
        min_length=1,
        max_length=128,
        validation_alias=AliasChoices(
            "SIEM_OPENSEARCH_USERNAME",
            "OPENSEARCH_USERNAME",
        ),
    )

    opensearch_password: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices(
            "SIEM_OPENSEARCH_PASSWORD",
            "OPENSEARCH_INITIAL_ADMIN_PASSWORD",
        ),
    )

    opensearch_verify_certs: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "SIEM_OPENSEARCH_VERIFY_CERTS",
            "OPENSEARCH_VERIFY_CERTS",
        ),
    )

    opensearch_ca_certs: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices(
            "SIEM_OPENSEARCH_CA_CERTS",
            "OPENSEARCH_CA_CERTS",
        ),
    )

    # ------------------------------------------------------------------
    # Ingestion Worker
    # ------------------------------------------------------------------

    event_queue_name: str = Field(
        default="siem:events",
        min_length=1,
        max_length=200,
        validation_alias=AliasChoices(
            "SIEM_EVENT_QUEUE_NAME",
            "EVENT_QUEUE_NAME",
        ),
    )

    worker_retry_delay_seconds: float = Field(
        default=2.0,
        gt=0,
        le=300,
        validation_alias=AliasChoices(
            "SIEM_WORKER_RETRY_DELAY_SECONDS",
            "WORKER_RETRY_DELAY_SECONDS",
        ),
    )

    # ------------------------------------------------------------------
    # Collector Runtime
    # ------------------------------------------------------------------

    collector_host: str = Field(
        default="0.0.0.0",
        min_length=1,
        max_length=255,
        validation_alias=AliasChoices(
            "SIEM_COLLECTOR_HOST",
            "COLLECTOR_HOST",
        ),
    )

    collector_port: int = Field(
        default=1514,
        ge=1,
        le=65_535,
        validation_alias=AliasChoices(
            "SIEM_COLLECTOR_PORT",
            "COLLECTOR_PORT",
        ),
    )

    collector_name: str = Field(
        default="tcp-collector",
        min_length=1,
        max_length=128,
        validation_alias=AliasChoices(
            "SIEM_COLLECTOR_NAME",
            "COLLECTOR_NAME",
        ),
    )

    collector_source: str = Field(
        default="tcp-collector",
        min_length=1,
        max_length=255,
        validation_alias=AliasChoices(
            "SIEM_COLLECTOR_SOURCE",
            "COLLECTOR_SOURCE",
        ),
    )

    collector_max_line_bytes: int = Field(
        default=64 * 1024,
        ge=1,
        le=10 * 1024 * 1024,
        validation_alias=AliasChoices(
            "SIEM_COLLECTOR_MAX_LINE_BYTES",
            "COLLECTOR_MAX_LINE_BYTES",
        ),
    )

    collector_queue_size: int = Field(
        default=10_000,
        ge=1,
        le=1_000_000,
        validation_alias=AliasChoices(
            "SIEM_COLLECTOR_QUEUE_SIZE",
            "COLLECTOR_QUEUE_SIZE",
        ),
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

        if normalized not in {"HS256"}:
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

        if not normalized.startswith(
            "postgresql+asyncpg://",
        ):
            raise ValueError(
                "SIEM_DATABASE_URL must use the "
                "postgresql+asyncpg:// scheme."
            )

        return normalized

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            return None

        parsed = urlparse(normalized)

        if parsed.scheme not in {"redis", "rediss"}:
            raise ValueError(
                "Redis URL must use redis:// or rediss://."
            )

        if not parsed.hostname:
            raise ValueError(
                "Redis URL must contain a hostname."
            )

        return normalized

    @field_validator("opensearch_url")
    @classmethod
    def validate_opensearch_url(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            return None

        parsed = urlparse(normalized)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError(
                "OpenSearch URL must use http:// or https://."
            )

        if not parsed.hostname:
            raise ValueError(
                "OpenSearch URL must contain a hostname."
            )

        return normalized

    @field_validator("opensearch_username")
    @classmethod
    def validate_opensearch_username(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "OpenSearch username must not be empty."
            )

        return normalized

    @field_validator("opensearch_password")
    @classmethod
    def validate_opensearch_password(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            return None

        return normalized

    @field_validator("opensearch_ca_certs")
    @classmethod
    def validate_opensearch_ca_certs(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            return None

        return normalized

    @field_validator("event_queue_name")
    @classmethod
    def validate_event_queue_name(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Event queue name must not be empty."
            )

        return normalized

    # ------------------------------------------------------------------
    # Security validation
    # ------------------------------------------------------------------

    def validate_security_configuration(self) -> None:
        """
        Validate mandatory security configuration.

        Staging and production require authentication and PostgreSQL.
        Ingestion dependencies are validated separately by the worker.
        """

        if self.environment in {"staging", "production"}:
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

            if not self.database_url:
                raise ValueError(
                    "SIEM_DATABASE_URL must be configured "
                    "in staging or production."
                )

            if (
                self.opensearch_url
                and self.opensearch_url.startswith("https://")
                and self.opensearch_verify_certs
                and not self.opensearch_ca_certs
            ):
                raise ValueError(
                    "SIEM_OPENSEARCH_CA_CERTS must be configured "
                    "when OpenSearch TLS certificate verification "
                    "is enabled."
                )

    # ------------------------------------------------------------------
    # Runtime dependency helpers
    # ------------------------------------------------------------------

    @property
    def database_configured(self) -> bool:
        """Return whether PostgreSQL is configured."""

        return self.database_url is not None

    @property
    def authentication_configured(self) -> bool:
        """Return whether authentication is configured."""

        return bool(self.auth_secret_key)

    @property
    def redis_configured(self) -> bool:
        """Return whether Redis is configured."""

        return self.redis_url is not None

    @property
    def opensearch_configured(self) -> bool:
        """Return whether OpenSearch is fully configured."""

        return (
            self.opensearch_url is not None
            and self.opensearch_password is not None
        )

    @property
    def opensearch_ca_configured(self) -> bool:
        """Return whether an OpenSearch CA bundle is configured."""

        return self.opensearch_ca_certs is not None

    def validate_ingestion_configuration(self) -> None:
        """Validate configuration required by the ingestion worker."""

        if not self.redis_url:
            raise ValueError(
                "Redis URL must be configured for ingestion."
            )

        if not self.opensearch_url:
            raise ValueError(
                "OpenSearch URL must be configured for ingestion."
            )

        if not self.opensearch_password:
            raise ValueError(
                "OpenSearch password must be configured for ingestion."
            )

        if (
            self.opensearch_url.startswith("https://")
            and self.opensearch_verify_certs
            and not self.opensearch_ca_certs
        ):
            raise ValueError(
                "OpenSearch CA certificates must be configured "
                "when HTTPS certificate verification is enabled."
            )

    def runtime_summary(self) -> dict[str, object]:
        """
        Return a non-sensitive runtime configuration summary.

        Secrets and credentials are intentionally excluded.
        """

        return {
            "environment": self.environment,
            "debug": self.debug,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "database_configured": self.database_configured,
            "authentication_configured": self.authentication_configured,
            "redis_configured": self.redis_configured,
            "opensearch_configured": self.opensearch_configured,
            "opensearch_username": self.opensearch_username,
            "opensearch_verify_certs": self.opensearch_verify_certs,
            "opensearch_ca_configured": self.opensearch_ca_configured,
            "event_queue_name": self.event_queue_name,
            "worker_retry_delay_seconds": (
                self.worker_retry_delay_seconds
            ),
            "collector_host": self.collector_host,
            "collector_port": self.collector_port,
            "collector_name": self.collector_name,
            "collector_source": self.collector_source,
            "collector_max_line_bytes": (
                self.collector_max_line_bytes
            ),
            "collector_queue_size": (
                self.collector_queue_size
            ),
        }


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
