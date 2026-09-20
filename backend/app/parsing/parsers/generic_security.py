from __future__ import annotations

import re
from typing import Any

from app.domain.events.enums import (
    EventCategory,
    EventOutcome,
    EventSeverity,
)
from app.domain.events.models import ParsedEvent, RawEvent


# ============================================================
# Generic Security Event Parser
# ============================================================
#
# Supported message format:
#
#   SECURITY_EVENT
#   action=<action>
#   outcome=<outcome>
#   severity=<severity>
#   category=<category>
#   username=<username>
#   source_ip=<source_ip>
#   destination_ip=<destination_ip>
#   source_port=<source_port>
#   destination_port=<destination_port>
#   protocol=<protocol>
#   process=<process>
#   command=<command>
#
# The complete event may optionally be wrapped in a syslog
# prefix:
#
#   <34>Sep 7 08:00:00 kali sentinel[1234]: SECURITY_EVENT ...
#
# Fields are whitespace-separated key=value pairs.
# Values containing spaces should be quoted:
#
#   command="sudo systemctl restart ssh"
#
# ============================================================


# ============================================================
# Allowed Canonical Values
# ============================================================

_SUPPORTED_ACTIONS = frozenset(
    {
        "login",
        "logout",
        "file_access",
        "file_modify",
        "process_start",
        "process_stop",
        "command_execution",
        "network_connection",
        "privilege_escalation",
        "account_change",
        "policy_change",
    }
)

_SUPPORTED_OUTCOMES = frozenset(
    {
        "success",
        "failure",
        "allowed",
        "denied",
        "blocked",
        "error",
        "unknown",
    }
)

_SUPPORTED_SEVERITIES = frozenset(
    {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }
)

_SUPPORTED_CATEGORIES = frozenset(
    {
        "authentication",
        "authorization",
        "network",
        "process",
        "file",
        "web",
        "system",
        "malware",
        "cloud",
        "other",
    }
)


# ============================================================
# Syslog Prefix
# ============================================================

_SYSLOG_PREFIX_RE = re.compile(
    r"""
    ^
    (?:<\d{1,3}>)?
    [A-Z][a-z]{2}
    \s+\d{1,2}
    \s+\d{2}:\d{2}:\d{2}
    \s+
    (?P<hostname>\S+)
    \s+
    (?P<process>[A-Za-z0-9_.-]+)
    (?:\[(?P<pid>\d+)\])?
    :
    """,
    re.VERBOSE,
)


# ============================================================
# Generic Key/Value Fields
# ============================================================

_FIELD_RE = re.compile(
    r"""
    (?P<key>[a-zA-Z_][a-zA-Z0-9_]*)
    =
    (?:
        "(?P<quoted>[^"]*)"
        |
        '(?P<single_quoted>[^']*)'
        |
        (?P<plain>\S+)
    )
    """,
    re.VERBOSE,
)


# ============================================================
# Helpers
# ============================================================


def _extract_message(raw_event: str) -> str:
    """
    Extract the application message from a syslog record.
    """

    if not isinstance(raw_event, str):
        raise TypeError("raw_event must be a string")

    value = raw_event.strip()

    if not value:
        raise ValueError("raw_event must not be empty")

    match = _SYSLOG_PREFIX_RE.match(value)

    if match is None:
        return value

    return value[match.end():].strip()


def _extract_syslog_context(
    raw_event: str,
) -> dict[str, Any]:
    """
    Extract hostname/process/pid from an optional syslog prefix.
    """

    if not isinstance(raw_event, str):
        raise TypeError("raw_event must be a string")

    value = raw_event.strip()

    if not value:
        return {}

    match = _SYSLOG_PREFIX_RE.match(value)

    if match is None:
        return {}

    context: dict[str, Any] = {}

    hostname = match.group("hostname")
    process = match.group("process")
    pid = match.group("pid")

    if hostname:
        context["hostname"] = hostname

    if process:
        context["process"] = process

    if pid is not None:
        context["pid"] = int(pid)

    return context


def _parse_fields(message: str) -> dict[str, str]:
    """
    Parse key=value fields from a generic security message.
    """

    if not isinstance(message, str):
        raise TypeError("message must be a string")

    fields: dict[str, str] = {}

    for match in _FIELD_RE.finditer(message):
        key = match.group("key")

        value = (
            match.group("quoted")
            if match.group("quoted") is not None
            else match.group("single_quoted")
            if match.group("single_quoted") is not None
            else match.group("plain")
        )

        if value is None:
            continue

        fields[key.lower()] = value.strip()

    return fields


def _require_field(
    fields: dict[str, str],
    name: str,
) -> str:
    """
    Return a required field or raise ValueError.
    """

    value = fields.get(name)

    if value is None or not value.strip():
        raise ValueError(
            f"generic security event requires field: {name}",
        )

    return value.strip()


def _optional_string(
    fields: dict[str, str],
    name: str,
) -> str | None:
    """
    Return an optional string field.
    """

    value = fields.get(name)

    if value is None:
        return None

    value = value.strip()

    return value or None


def _optional_int(
    fields: dict[str, str],
    name: str,
) -> int | None:
    """
    Parse an optional integer field.
    """

    value = fields.get(name)

    if value is None:
        return None

    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(
            f"generic security field must be an integer: {name}",
        ) from exc

    if not 0 <= parsed <= 65535:
        raise ValueError(
            f"{name} must be between 0 and 65535",
        )

    return parsed


def _validate_action(value: str) -> str:
    """
    Validate a generic security action.
    """

    normalized = value.strip().lower()

    if normalized not in _SUPPORTED_ACTIONS:
        raise ValueError(
            f"unsupported generic security action: {value}",
        )

    return normalized


def _validate_outcome(value: str) -> EventOutcome:
    """
    Validate and normalize event outcome.
    """

    normalized = value.strip().lower()

    if normalized not in _SUPPORTED_OUTCOMES:
        raise ValueError(
            f"unsupported generic security outcome: {value}",
        )

    return EventOutcome(normalized)


def _validate_severity(value: str) -> EventSeverity:
    """
    Validate and normalize event severity.
    """

    normalized = value.strip().lower()

    if normalized not in _SUPPORTED_SEVERITIES:
        raise ValueError(
            f"unsupported generic security severity: {value}",
        )

    return EventSeverity(normalized)


def _validate_category(value: str) -> EventCategory:
    """
    Validate and normalize event category.
    """

    normalized = value.strip().lower()

    if normalized not in _SUPPORTED_CATEGORIES:
        raise ValueError(
            f"unsupported generic security category: {value}",
        )

    return EventCategory(normalized)


# ============================================================
# Generic Security Event Detection
# ============================================================


def _is_generic_security_event(message: str) -> bool:
    """
    Determine whether the message uses the generic security
    event format.
    """

    return message.startswith("SECURITY_EVENT")


# ============================================================
# Generic Security Parsing
# ============================================================


def _parse_generic_security_event(
    message: str,
) -> dict[str, Any]:
    """
    Parse a generic SECURITY_EVENT message.
    """

    if not _is_generic_security_event(message):
        raise ValueError(
            "unsupported generic security event",
        )

    fields = _parse_fields(message)

    action = _validate_action(
        _require_field(fields, "action"),
    )

    outcome = _validate_outcome(
        _require_field(fields, "outcome"),
    )

    severity = _validate_severity(
        _require_field(fields, "severity"),
    )

    category = _validate_category(
        _require_field(fields, "category"),
    )

    parsed: dict[str, Any] = {
        "action": action,
        "outcome": outcome,
        "severity": severity,
        "category": category,
    }

    username = _optional_string(
        fields,
        "username",
    )

    if username is not None:
        parsed["username"] = username

    source_ip = _optional_string(
        fields,
        "source_ip",
    )

    if source_ip is not None:
        parsed["source_ip"] = source_ip

    destination_ip = _optional_string(
        fields,
        "destination_ip",
    )

    if destination_ip is not None:
        parsed["destination_ip"] = destination_ip

    source_port = _optional_int(
        fields,
        "source_port",
    )

    if source_port is not None:
        parsed["source_port"] = source_port

    destination_port = _optional_int(
        fields,
        "destination_port",
    )

    if destination_port is not None:
        parsed["destination_port"] = destination_port

    protocol = _optional_string(
        fields,
        "protocol",
    )

    if protocol is not None:
        parsed["protocol"] = protocol

    process = _optional_string(
        fields,
        "process",
    )

    if process is not None:
        parsed["process"] = process

    command = _optional_string(
        fields,
        "command",
    )

    if command is not None:
        parsed["command"] = command

    return parsed


# ============================================================
# Public Parser
# ============================================================


def parse_generic_security(
    event: RawEvent,
) -> ParsedEvent:
    """
    Parse a generic security event.

    Contract:

        RawEvent
            ↓
        ParsedEvent

    Required generic fields:

        action
        outcome
        severity
        category

    Optional fields:

        username
        source_ip
        destination_ip
        source_port
        destination_port
        protocol
        process
        command

    Raises:

        TypeError:
            If event is not a RawEvent.

        ValueError:
            If the event is empty or unsupported.
    """

    if not isinstance(event, RawEvent):
        raise TypeError(
            "generic security parser expects RawEvent",
        )

    raw_event = event.raw_event

    message = _extract_message(
        raw_event,
    )

    if not _is_generic_security_event(message):
        raise ValueError(
            "unsupported generic security event",
        )

    parsed_data: dict[str, Any] = {
        "message": message,
    }

    parsed_data.update(
        _extract_syslog_context(raw_event),
    )

    parsed_data.update(
        _parse_generic_security_event(message),
    )

    return ParsedEvent(
        **event.model_dump(
            exclude={"stage"},
        ),
        parsed_data=parsed_data,
    )


# ============================================================
# Public API
# ============================================================

__all__ = [
    "parse_generic_security",
]
