from __future__ import annotations

from typing import Any

from app.domain.events.models import NormalizedEvent, ParsedEvent


# ============================================================
# Generic Security Normalizer
# ============================================================


_CANONICAL_FIELDS = frozenset(
    {
        "hostname",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "username",
        "process",
        "command",
        "action",
        "outcome",
        "severity",
        "category",
    }
)


def _clean_string(value: Any) -> str | None:
    """
    Normalize an optional string value.

    Empty strings are converted to None.
    Non-string values are converted to strings only when
    they are explicitly present.
    """

    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        return value

    return str(value).strip() or None


def _clean_int(value: Any) -> int | None:
    """
    Normalize an optional integer value.

    Boolean values are rejected because bool is a subclass of int
    in Python and should never represent a network port here.
    """

    if value is None:
        return None

    if isinstance(value, bool):
        raise TypeError("integer security fields cannot be boolean")

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        try:
            return int(value)
        except ValueError as exc:
            raise ValueError(
                f"invalid integer security field: {value!r}",
            ) from exc

    raise TypeError(
        f"unsupported integer security field type: {type(value).__name__}",
    )


def _normalize_security_data(
    parsed_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Normalize generic security-event fields.

    Parser output is copied rather than mutated so the original
    ParsedEvent remains unchanged.
    """

    normalized: dict[str, Any] = {}

    # --------------------------------------------------------
    # Preserve parser metadata/context
    # --------------------------------------------------------

    for key, value in parsed_data.items():
        if key not in _CANONICAL_FIELDS:
            normalized[key] = value

    # --------------------------------------------------------
    # String fields
    # --------------------------------------------------------

    string_fields = (
        "hostname",
        "source_ip",
        "destination_ip",
        "protocol",
        "username",
        "process",
        "command",
        "action",
        "outcome",
        "severity",
        "category",
    )

    for field_name in string_fields:
        if field_name not in parsed_data:
            continue

        value = _clean_string(
            parsed_data.get(field_name),
        )

        if value is not None:
            normalized[field_name] = value

    # --------------------------------------------------------
    # Integer fields
    # --------------------------------------------------------

    integer_fields = (
        "source_port",
        "destination_port",
    )

    for field_name in integer_fields:
        if field_name not in parsed_data:
            continue

        value = _clean_int(
            parsed_data.get(field_name),
        )

        if value is not None:
            normalized[field_name] = value

    return normalized


# ============================================================
# Public Normalizer
# ============================================================


def normalize_generic_security(
    event: ParsedEvent,
) -> NormalizedEvent:
    """
    Normalize a generic security event.

    The generic security parser is responsible for validating
    the event taxonomy:

        action
        outcome
        severity
        category

    This normalizer intentionally preserves those values.

    It does NOT apply Linux authentication semantics such as:

        failure -> high
        success -> info
        authentication category

    Those semantics belong exclusively to the Linux auth route.
    """

    if not isinstance(event, ParsedEvent):
        raise TypeError(
            "generic security normalizer expects ParsedEvent",
        )

    parsed_data = event.parsed_data

    if not isinstance(parsed_data, dict):
        raise TypeError(
            "ParsedEvent.parsed_data must be a dictionary",
        )

    normalized_data = _normalize_security_data(
        parsed_data,
    )

    # --------------------------------------------------------
    # Required generic security taxonomy
    # --------------------------------------------------------

    required_fields = (
        "action",
        "outcome",
        "severity",
        "category",
    )

    missing_fields = [
        field_name
        for field_name in required_fields
        if not normalized_data.get(field_name)
    ]

    if missing_fields:
        raise ValueError(
            "generic security event is missing required normalized "
            f"fields: {', '.join(missing_fields)}",
        )

    # --------------------------------------------------------
    # Build NormalizedEvent
    # --------------------------------------------------------

    return NormalizedEvent(
        **event.model_dump(exclude={"stage", "parsed_data"}),
        normalized_data=normalized_data,
    )


# ============================================================
# Public API
# ============================================================


__all__ = [
    "normalize_generic_security",
]
