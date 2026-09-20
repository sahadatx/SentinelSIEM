from __future__ import annotations

from typing import Any

from app.domain.events.models import NormalizedEvent, ParsedEvent


# =========================================================
# Linux Authentication Normalizer
# =========================================================


def _require_string(
    data: dict[str, Any],
    field: str,
) -> str:
    """Return a required non-empty string field."""

    value = data.get(field)

    if not isinstance(value, str):
        raise ValueError(
            f"linux auth normalizer requires string field: {field}",
        )

    value = value.strip()

    if not value:
        raise ValueError(
            f"linux auth normalizer requires non-empty field: {field}",
        )

    return value


def _optional_string(
    data: dict[str, Any],
    field: str,
) -> str | None:
    """Return an optional normalized string field."""

    value = data.get(field)

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(
            f"linux auth field must be a string: {field}",
        )

    value = value.strip()

    return value or None


def _optional_int(
    data: dict[str, Any],
    field: str,
) -> int | None:
    """Return an optional integer field."""

    value = data.get(field)

    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"linux auth field must be an integer: {field}",
        )

    return value


def _validate_port(
    value: int | None,
    field: str,
) -> int | None:
    """Validate a network port."""

    if value is None:
        return None

    if not 0 <= value <= 65535:
        raise ValueError(
            f"{field} must be between 0 and 65535",
        )

    return value


def _normalize_protocol(
    value: str | None,
) -> str | None:
    """Normalize the protocol representation."""

    if value is None:
        return None

    protocol = value.strip().lower()

    if not protocol:
        return None

    # Linux SSH logs commonly expose "ssh2".
    if protocol == "ssh2":
        return "ssh"

    return protocol


def _normalize_outcome(
    value: str,
) -> str:
    """Normalize authentication outcome."""

    outcome = value.strip().lower()

    mapping = {
        "success": "success",
        "successful": "success",
        "accepted": "success",
        "failure": "failure",
        "failed": "failure",
        "denied": "failure",
    }

    try:
        return mapping[outcome]
    except KeyError as exc:
        raise ValueError(
            f"unsupported Linux auth outcome: {value}",
        ) from exc


def _normalize_action(
    value: str,
) -> str:
    """Normalize authentication action."""

    action = value.strip().lower()

    mapping = {
        "login": "login",
        "session_open": "session_open",
        "session_close": "session_close",
    }

    try:
        return mapping[action]
    except KeyError as exc:
        raise ValueError(
            f"unsupported Linux auth action: {value}",
        ) from exc


def _build_normalized_data(
    event: ParsedEvent,
) -> dict[str, Any]:
    """
    Convert parser-specific Linux authentication data into
    the normalized security-event representation.
    """

    data = event.parsed_data

    normalized: dict[str, Any] = {
        "service": _require_string(
            data,
            "service",
        ),
        "message": _require_string(
            data,
            "message",
        ),
        "action": _normalize_action(
            _require_string(
                data,
                "action",
            ),
        ),
        "outcome": _normalize_outcome(
            _require_string(
                data,
                "outcome",
            ),
        ),
    }

    username = _optional_string(
        data,
        "username",
    )

    if username is not None:
        normalized["username"] = username

    source_ip = _optional_string(
        data,
        "source_ip",
    )

    if source_ip is not None:
        normalized["source_ip"] = source_ip

    source_port = _validate_port(
        _optional_int(
            data,
            "source_port",
        ),
        "source_port",
    )

    if source_port is not None:
        normalized["source_port"] = source_port

    destination_port = _validate_port(
        _optional_int(
            data,
            "destination_port",
        ),
        "destination_port",
    )

    if destination_port is not None:
        normalized["destination_port"] = destination_port

    protocol = _normalize_protocol(
        _optional_string(
            data,
            "protocol",
        ),
    )

    if protocol is not None:
        normalized["protocol"] = protocol

    hostname = _optional_string(
        data,
        "hostname",
    )

    if hostname is not None:
        normalized["hostname"] = hostname

    process = _optional_string(
        data,
        "process",
    )

    if process is not None:
        normalized["process"] = process

    pid = _optional_int(
        data,
        "pid",
    )

    if pid is not None:
        if pid < 0:
            raise ValueError(
                "pid must not be negative",
            )

        normalized["pid"] = pid

    return normalized


# =========================================================
# Public Normalizer
# =========================================================


def normalize_linux_auth(
    event: ParsedEvent,
) -> NormalizedEvent:
    """
    Normalize a parsed Linux authentication event.

    Contract:

        ParsedEvent
            ↓
        NormalizedEvent

    Parser-specific fields are validated and converted into a
    stable representation for canonicalization and downstream
    security analytics.

    The original event identity and event context are preserved.
    """

    if not isinstance(event, ParsedEvent):
        raise TypeError(
            "linux authentication normalizer expects ParsedEvent",
        )

    if not event.parsed_data:
        raise ValueError(
            "linux authentication event contains no parsed data",
        )

    normalized_data = _build_normalized_data(
        event,
    )

    return NormalizedEvent(
        **event.model_dump(
            exclude={"stage"},
        ),
        normalized_data=normalized_data,
    )


# =========================================================
# Public API
# =========================================================

__all__ = [
    "normalize_linux_auth",
]
