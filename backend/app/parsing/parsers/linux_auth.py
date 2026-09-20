from __future__ import annotations

import re
from typing import Any

from app.domain.events.models import ParsedEvent, RawEvent


# ============================================================
# Linux Authentication Parser
# ============================================================
#
# Supported examples:
#
# Standard syslog:
#
#   Aug 14 10:15:32 sentinel-host sshd[4242]:
#   Failed password for invalid user admin
#   from 192.168.10.55 port 54321 ssh2
#
# PRI-prefixed syslog:
#
#   <34>Sep 2 08:45:00 test-host sshd[54321]:
#   Failed password for invalid user admin
#   from 10.0.0.5 port 54321 ssh2
#
# Successful authentication:
#
#   Accepted password for sahadat from 10.0.0.5 port 54321 ssh2
#
# Invalid user:
#
#   Invalid user admin from 10.0.0.5 port 54321
#
# Session opened:
#
#   pam_unix(sshd:session): session opened for user sahadat
#
# Session closed:
#
#   pam_unix(sshd:session): session closed for user sahadat
#
# ============================================================


# ============================================================
# Authentication Patterns
# ============================================================

_FAILED_PASSWORD_RE = re.compile(
    r"""
    ^Failed\ password
    \s+for
    (?:\s+invalid\ user)?
    \s+
    (?P<username>\S+)
    \s+from\s+
    (?P<source_ip>\S+)
    \s+port\s+
    (?P<source_port>\d+)
    (?:\s+(?P<protocol>\S+))?
    """,
    re.IGNORECASE | re.VERBOSE,
)


_ACCEPTED_PASSWORD_RE = re.compile(
    r"""
    ^Accepted\ password
    \s+for\s+
    (?P<username>\S+)
    \s+from\s+
    (?P<source_ip>\S+)
    \s+port\s+
    (?P<source_port>\d+)
    (?:\s+(?P<protocol>\S+))?
    """,
    re.IGNORECASE | re.VERBOSE,
)


_INVALID_USER_RE = re.compile(
    r"""
    ^Invalid\ user
    \s+
    (?P<username>\S+)
    \s+from\s+
    (?P<source_ip>\S+)
    \s+port\s+
    (?P<source_port>\d+)
    (?:\s+(?P<protocol>\S+))?
    """,
    re.IGNORECASE | re.VERBOSE,
)


_SESSION_OPENED_RE = re.compile(
    r"""
    ^pam_unix\(sshd:session\):
    \s+
    session\s+opened
    \s+for\s+user\s+
    (?P<username>\S+)
    """,
    re.IGNORECASE | re.VERBOSE,
)


_SESSION_CLOSED_RE = re.compile(
    r"""
    ^pam_unix\(sshd:session\):
    \s+
    session\s+closed
    \s+for\s+user\s+
    (?P<username>\S+)
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# Syslog Pattern
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
# Helpers
# ============================================================

def _extract_message(raw_event: str) -> str:
    """
    Extract the application/service message from a syslog-style
    Linux authentication event.

    If no valid syslog prefix is detected, the complete event
    is preserved as the message.
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
    Extract optional syslog context.

    Supported fields:

        hostname
        process
        pid
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


def _build_base_data(
    event: RawEvent,
) -> dict[str, Any]:
    """
    Build common parser output metadata.
    """

    raw_event = event.raw_event

    data: dict[str, Any] = {
        "message": _extract_message(raw_event),
        "service": "sshd",
    }

    data.update(
        _extract_syslog_context(raw_event),
    )

    return data


# ============================================================
# Authentication Parsers
# ============================================================

def _parse_failed_password(
    message: str,
) -> dict[str, Any] | None:
    """
    Parse failed SSH password authentication.
    """

    match = _FAILED_PASSWORD_RE.search(message)

    if match is None:
        return None

    return {
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": int(match.group("source_port")),
        "destination_port": 22,
        "protocol": match.group("protocol") or "ssh2",
        "action": "login",
        "outcome": "failure",
    }


def _parse_accepted_password(
    message: str,
) -> dict[str, Any] | None:
    """
    Parse successful SSH password authentication.
    """

    match = _ACCEPTED_PASSWORD_RE.search(message)

    if match is None:
        return None

    return {
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": int(match.group("source_port")),
        "destination_port": 22,
        "protocol": match.group("protocol") or "ssh2",
        "action": "login",
        "outcome": "success",
    }


def _parse_invalid_user(
    message: str,
) -> dict[str, Any] | None:
    """
    Parse an SSH invalid-user authentication attempt.
    """

    match = _INVALID_USER_RE.search(message)

    if match is None:
        return None

    return {
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": int(match.group("source_port")),
        "destination_port": 22,
        "protocol": match.group("protocol") or "ssh2",
        "action": "login",
        "outcome": "failure",
    }


def _parse_session_opened(
    message: str,
) -> dict[str, Any] | None:
    """
    Parse an SSH session-open event.
    """

    match = _SESSION_OPENED_RE.search(message)

    if match is None:
        return None

    return {
        "username": match.group("username"),
        "action": "session_open",
        "outcome": "success",
    }


def _parse_session_closed(
    message: str,
) -> dict[str, Any] | None:
    """
    Parse an SSH session-close event.
    """

    match = _SESSION_CLOSED_RE.search(message)

    if match is None:
        return None

    return {
        "username": match.group("username"),
        "action": "session_close",
        "outcome": "success",
    }


# ============================================================
# Public Parser
# ============================================================

def parse_linux_auth(
    event: RawEvent,
) -> ParsedEvent:
    """
    Parse a Linux SSH authentication/security event.

    Supported events:

        - Failed password
        - Accepted password
        - Invalid user
        - SSH session opened
        - SSH session closed

    Contract:

        RawEvent
            ↓
        ParsedEvent

    The original event identity and ingestion context are
    preserved.

    Raises:

        TypeError:
            If event is not a RawEvent.

        ValueError:
            If raw_event is empty or unsupported.
    """

    if not isinstance(event, RawEvent):
        raise TypeError(
            "linux authentication parser expects RawEvent",
        )

    message = _extract_message(
        event.raw_event,
    )

    parsed_data = _build_base_data(
        event,
    )

    parsed_result = (
        _parse_failed_password(message)
        or _parse_accepted_password(message)
        or _parse_invalid_user(message)
        or _parse_session_opened(message)
        or _parse_session_closed(message)
    )

    if parsed_result is None:
        raise ValueError(
            "unsupported Linux authentication event",
        )

    parsed_data.update(
        parsed_result,
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
    "parse_linux_auth",
]