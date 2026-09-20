from __future__ import annotations

from typing import Any

from app.domain.events.enums import (
    EventCategory,
    EventOutcome,
    EventSeverity,
)
from app.domain.events.models import (
    CanonicalSecurityEvent,
    NormalizedEvent,
    RawEvent,
)


# ============================================================
# Canonical Field Contract
# ============================================================

_CANONICAL_STRING_FIELDS = frozenset(
    {
        "hostname",
        "source_ip",
        "destination_ip",
        "protocol",
        "username",
        "process",
        "command",
        "action",
    }
)

_CANONICAL_INTEGER_FIELDS = frozenset(
    {
        "source_port",
        "destination_port",
    }
)

_CANONICAL_ENUM_FIELDS = frozenset(
    {
        "outcome",
        "severity",
        "category",
    }
)

_CANONICAL_FIELDS = frozenset(
    {
        *_CANONICAL_STRING_FIELDS,
        *_CANONICAL_INTEGER_FIELDS,
        *_CANONICAL_ENUM_FIELDS,
    }
)


# ============================================================
# Linux Authentication Actions
# ============================================================

_LINUX_AUTH_ACTIONS = frozenset(
    {
        "login",
        "session_open",
        "session_close",
    }
)


# ============================================================
# Validation Helpers
# ============================================================


def _require_normalized_event(
    event: NormalizedEvent,
) -> None:
    """
    Ensure the supplied event is a NormalizedEvent.
    """

    if not isinstance(event, NormalizedEvent):
        raise TypeError(
            "canonicalization expects NormalizedEvent",
        )


def _optional_string(
    data: dict[str, Any],
    field: str,
) -> str | None:
    """
    Read an optional string field from normalized data.
    """

    value = data.get(field)

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(
            f"canonical field must be a string: {field}",
        )

    value = value.strip()

    return value or None


def _optional_int(
    data: dict[str, Any],
    field: str,
) -> int | None:
    """
    Read an optional integer field from normalized data.
    """

    value = data.get(field)

    if value is None:
        return None

    if isinstance(value, bool):
        raise ValueError(
            f"canonical field must be an integer: {field}",
        )

    if not isinstance(value, int):
        raise ValueError(
            f"canonical field must be an integer: {field}",
        )

    return value


def _normalize_outcome(
    value: Any,
) -> EventOutcome:
    """
    Convert a value into EventOutcome.
    """

    if isinstance(value, EventOutcome):
        return value

    if not isinstance(value, str):
        raise ValueError(
            "canonical outcome must be a string",
        )

    normalized = value.strip().lower()

    try:
        return EventOutcome(normalized)

    except ValueError as exc:
        raise ValueError(
            f"unsupported canonical outcome: {value}",
        ) from exc


def _normalize_severity(
    value: Any,
) -> EventSeverity:
    """
    Convert a value into EventSeverity.
    """

    if isinstance(value, EventSeverity):
        return value

    if not isinstance(value, str):
        raise ValueError(
            "canonical severity must be a string",
        )

    normalized = value.strip().lower()

    try:
        return EventSeverity(normalized)

    except ValueError as exc:
        raise ValueError(
            f"unsupported canonical severity: {value}",
        ) from exc


def _normalize_category(
    value: Any,
) -> EventCategory:
    """
    Convert a value into EventCategory.
    """

    if isinstance(value, EventCategory):
        return value

    if not isinstance(value, str):
        raise ValueError(
            "canonical category must be a string",
        )

    normalized = value.strip().lower()

    try:
        return EventCategory(normalized)

    except ValueError as exc:
        raise ValueError(
            f"unsupported canonical category: {value}",
        ) from exc


def _normalize_canonical_field(
    field: str,
    value: Any,
) -> Any:
    """
    Validate and normalize a single canonical field.
    """

    if field in _CANONICAL_STRING_FIELDS:
        if not isinstance(value, str):
            raise ValueError(
                f"canonical field must be a string: {field}",
            )

        value = value.strip()

        if not value:
            raise ValueError(
                f"canonical field must not be empty: {field}",
            )

        return value

    if field in _CANONICAL_INTEGER_FIELDS:
        if isinstance(value, bool):
            raise ValueError(
                f"canonical field must be an integer: {field}",
            )

        if not isinstance(value, int):
            raise ValueError(
                f"canonical field must be an integer: {field}",
            )

        if field in {
            "source_port",
            "destination_port",
        }:
            if not 0 <= value <= 65535:
                raise ValueError(
                    f"{field} must be between 0 and 65535",
                )

        return value

    if field == "outcome":
        return _normalize_outcome(value)

    if field == "severity":
        return _normalize_severity(value)

    if field == "category":
        return _normalize_category(value)

    raise ValueError(
        f"unsupported canonical field: {field}",
    )


def _validate_explicit_fields(
    fields: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate explicitly supplied canonical fields.

    Unknown fields are rejected so parser-specific data cannot
    accidentally leak into the canonical event model.
    """

    if not isinstance(fields, dict):
        raise TypeError(
            "canonical fields must be a dictionary",
        )

    normalized: dict[str, Any] = {}

    for field, value in fields.items():
        if field not in _CANONICAL_FIELDS:
            raise ValueError(
                f"unsupported canonical field: {field}",
            )

        if value is None:
            continue

        normalized[field] = _normalize_canonical_field(
            field,
            value,
        )

    return normalized


# ============================================================
# Normalized → Canonical Mapping
# ============================================================


def normalized_to_canonical_fields(
    event: NormalizedEvent,
) -> dict[str, Any]:
    """
    Promote canonical fields from NormalizedEvent.normalized_data.

    Only fields belonging to the canonical security-event
    contract are promoted.

    Parser-specific fields such as:

        service
        message
        pid

    remain inside normalized_data.
    """

    _require_normalized_event(event)

    data = event.normalized_data

    if not isinstance(data, dict):
        raise ValueError(
            "normalized event data must be a dictionary",
        )

    if not data:
        raise ValueError(
            "normalized event contains no normalized data",
        )

    fields: dict[str, Any] = {}

    # --------------------------------------------------------
    # String fields
    # --------------------------------------------------------

    for field in _CANONICAL_STRING_FIELDS:
        if field not in data:
            continue

        value = _optional_string(
            data,
            field,
        )

        if value is not None:
            fields[field] = value

    # --------------------------------------------------------
    # Integer fields
    # --------------------------------------------------------

    for field in _CANONICAL_INTEGER_FIELDS:
        if field not in data:
            continue

        value = _optional_int(
            data,
            field,
        )

        if value is not None:
            fields[field] = value

    # --------------------------------------------------------
    # Enum fields
    # --------------------------------------------------------

    if data.get("outcome") is not None:
        fields["outcome"] = _normalize_outcome(
            data["outcome"],
        )

    if data.get("severity") is not None:
        fields["severity"] = _normalize_severity(
            data["severity"],
        )

    if data.get("category") is not None:
        fields["category"] = _normalize_category(
            data["category"],
        )

    return fields


# ============================================================
# Linux Authentication Security Semantics
# ============================================================


def _apply_linux_auth_semantics(
    fields: dict[str, Any],
) -> dict[str, Any]:
    """
    Apply Linux authentication-specific canonical semantics.

    These rules MUST NOT affect generic security events.

    Rules:

        login/session_open/session_close
            → authentication

        failure
            → high

        success
            → info

    The function only applies when the action belongs to the
    Linux authentication action family.

    Generic events such as:

        file_access
        process_start
        network_connection
        privilege_escalation

    are left untouched.
    """

    action = fields.get("action")

    # --------------------------------------------------------
    # Only Linux authentication actions receive these rules.
    # --------------------------------------------------------

    if action not in _LINUX_AUTH_ACTIONS:
        return fields

    outcome = fields.get("outcome")

    # --------------------------------------------------------
    # Category
    # --------------------------------------------------------

    fields["category"] = EventCategory.AUTHENTICATION

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    if outcome == EventOutcome.FAILURE:
        fields["severity"] = EventSeverity.HIGH

    elif outcome == EventOutcome.SUCCESS:
        fields["severity"] = EventSeverity.INFO

    return fields


def linux_auth_to_canonical_fields(
    event: NormalizedEvent,
) -> dict[str, Any]:
    """
    Convert normalized Linux authentication data into
    canonical security-event fields.
    """

    _require_normalized_event(event)

    fields = normalized_to_canonical_fields(
        event,
    )

    return _apply_linux_auth_semantics(
        fields,
    )


# ============================================================
# Generic Security Canonical Semantics
# ============================================================


def _apply_generic_security_semantics(
    fields: dict[str, Any],
) -> dict[str, Any]:
    """
    Apply generic security-event semantics.

    Generic security events already contain explicit:

        action
        outcome
        severity
        category

    values.

    Therefore this function intentionally does not rewrite
    those values.

    This preserves the diversity supplied by the generic
    parser and normalizer.
    """

    return fields


# ============================================================
# Canonical Event Context
# ============================================================


def _build_canonical_context(
    event: NormalizedEvent,
) -> dict[str, Any]:
    """
    Preserve event-ingestion context while excluding fields
    that are explicitly constructed by canonicalization.
    """

    return event.model_dump(
        mode="python",
        exclude={
            "stage",
            *_CANONICAL_FIELDS,
        },
    )


# ============================================================
# Canonical Event Construction
# ============================================================


def canonicalize_event(
    event: NormalizedEvent,
    *,
    fields: dict[str, Any] | None = None,
) -> CanonicalSecurityEvent:
    """
    Convert a NormalizedEvent into CanonicalSecurityEvent.

    Processing order:

        NormalizedEvent
            ↓
        normalized_data extraction
            ↓
        canonical field mapping
            ↓
        route-aware semantics
            ↓
        explicit overrides
            ↓
        CanonicalSecurityEvent

    Linux authentication actions receive Linux-auth-specific
    semantics.

    Generic security actions preserve their supplied
    category,
    severity,
    and outcome values.
    """

    _require_normalized_event(event)

    # --------------------------------------------------------
    # Automatically promote normalized fields
    # --------------------------------------------------------

    canonical_fields = normalized_to_canonical_fields(
        event,
    )

    # --------------------------------------------------------
    # Route-aware security semantics
    # --------------------------------------------------------

    action = canonical_fields.get("action")

    if action in _LINUX_AUTH_ACTIONS:
        canonical_fields = _apply_linux_auth_semantics(
            canonical_fields,
        )

    else:
        canonical_fields = _apply_generic_security_semantics(
            canonical_fields,
        )

    # --------------------------------------------------------
    # Explicit canonical overrides
    # --------------------------------------------------------

    if fields is not None:
        explicit_fields = _validate_explicit_fields(
            fields,
        )

        canonical_fields.update(
            explicit_fields,
        )

    # --------------------------------------------------------
    # Preserve ingestion context
    # --------------------------------------------------------

    context = _build_canonical_context(
        event,
    )

    # --------------------------------------------------------
    # Construct canonical event
    # --------------------------------------------------------

    canonical = CanonicalSecurityEvent(
        **context,
        **canonical_fields,
    )

    # --------------------------------------------------------
    # Identity invariant
    # --------------------------------------------------------

    if canonical.event_id != event.event_id:
        raise ValueError(
            "canonicalization must preserve event_id",
        )

    return canonical


# ============================================================
# Linux Authentication Convenience API
# ============================================================


def canonicalize_linux_auth(
    event: RawEvent | NormalizedEvent,
    *,
    hostname: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    protocol: str | None = None,
    username: str | None = None,
    process: str | None = None,
    command: str | None = None,
    action: str | None = None,
    outcome: EventOutcome | str | None = None,
    severity: EventSeverity | str | None = None,
    category: EventCategory | str | None = None,
) -> CanonicalSecurityEvent:
    """
    Canonicalize a Linux authentication event.

    Supported input:

        RawEvent
        NormalizedEvent

    For NormalizedEvent input, canonical security fields are
    automatically extracted from normalized_data.

    Explicit keyword arguments override automatically mapped
    values.
    """

    explicit_fields: dict[str, Any] = {}

    supplied_fields = {
        "hostname": hostname,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "username": username,
        "process": process,
        "command": command,
        "action": action,
        "outcome": outcome,
        "severity": severity,
        "category": category,
    }

    for field, value in supplied_fields.items():
        if value is not None:
            explicit_fields[field] = value

    # --------------------------------------------------------
    # NormalizedEvent compatibility path
    # --------------------------------------------------------

    if isinstance(event, NormalizedEvent):
        return canonicalize_event(
            event,
            fields=explicit_fields or None,
        )

    # --------------------------------------------------------
    # RawEvent compatibility path
    # --------------------------------------------------------

    if isinstance(event, RawEvent):
        context = event.model_dump(
            mode="python",
            exclude={
                "stage",
                *_CANONICAL_FIELDS,
            },
        )

        canonical_fields = _validate_explicit_fields(
            explicit_fields,
        )

        canonical = CanonicalSecurityEvent(
            **context,
            **canonical_fields,
        )

        if canonical.event_id != event.event_id:
            raise ValueError(
                "canonicalization must preserve event_id",
            )

        return canonical

    # --------------------------------------------------------
    # Invalid input
    # --------------------------------------------------------

    raise TypeError(
        "Linux auth canonicalization expects "
        "RawEvent or NormalizedEvent",
    )


# ============================================================
# Public API
# ============================================================


__all__ = [
    "canonicalize_event",
    "canonicalize_linux_auth",
    "linux_auth_to_canonical_fields",
    "normalized_to_canonical_fields",
]