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

    app_name: str = Field(default=DEFAULT_APP_NAME, min_length=1, max_length=100)
    environment: str = Field(default=DEFAULT_ENVIRONMENT, min_length=1, max_length=32)
    debug: bool = False
    log_level: str = DEFAULT_LOG_LEVEL

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    max_request_bytes: int = Field(default=DEFAULT_MAX_REQUEST_BYTES, ge=1, le=100_000_000)
    shutdown_timeout_seconds: int = Field(default=DEFAULT_SHUTDOWN_TIMEOUT_SECONDS, ge=1, le=300)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        if normalized not in allowed:
            raise ValueError(f"Unsupported log level: {value}")
        return normalized

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        normalized = value.lower()
        allowed = {"development", "test", "staging", "production"}
        if normalized not in allowed:
            raise ValueError(f"Unsupported environment: {value}")
        return normalized


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:
        return Settings()
    except Exception as exc:
        raise ConfigurationError("Application configuration is invalid.") from exc
