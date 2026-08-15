from __future__ import annotations

from pytest import MonkeyPatch

from app.core.config import Settings


def test_settings_defaults_are_safe() -> None:
    settings = Settings()
    assert settings.app_name == "siem-security-platform"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.max_request_bytes == 1_048_576


def test_settings_accept_environment_override(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("SIEM_ENVIRONMENT", "test")
    monkeypatch.setenv("SIEM_LOG_LEVEL", "WARNING")

    settings = Settings()

    assert settings.environment == "test"
    assert settings.log_level == "WARNING"
