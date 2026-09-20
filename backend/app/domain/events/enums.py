from __future__ import annotations

from enum import StrEnum


# ============================================================
# Event Stage
# ============================================================


class EventStage(StrEnum):
    """
    Processing lifecycle stage of a security event.

    Events move through the pipeline in the following order:

        RAW
         ↓
        PARSED
         ↓
        NORMALIZED
         ↓
        CANONICAL
         ↓
        ENRICHED
    """

    RAW = "raw"
    PARSED = "parsed"
    NORMALIZED = "normalized"
    CANONICAL = "canonical"
    ENRICHED = "enriched"


# ============================================================
# Event Source Type
# ============================================================


class EventSourceType(StrEnum):
    """
    Origin or transport type of an incoming security event.
    """

    SYSLOG = "syslog"
    HTTP = "http"
    TCP = "tcp"
    FILE = "file"
    WINDOWS = "windows"
    APPLICATION = "application"
    OTHER = "other"


# ============================================================
# Event Severity
# ============================================================


class EventSeverity(StrEnum):
    """
    Severity assigned to a security event.

    Severity levels are ordered conceptually from informational
    activity to the most serious security condition.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================
# Event Category
# ============================================================


class EventCategory(StrEnum):
    """
    High-level security category associated with an event.

    Categories describe the security domain of the activity,
    while actions describe the specific operation performed.
    """

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    WEB = "web"
    SYSTEM = "system"
    MALWARE = "malware"
    CLOUD = "cloud"
    OTHER = "other"


# ============================================================
# Event Outcome
# ============================================================


class EventOutcome(StrEnum):
    """
    Outcome of the activity represented by a security event.

    The taxonomy supports authentication, authorization,
    enforcement, operational-error, and unknown outcomes.
    """

    # --------------------------------------------------------
    # Successful activity
    # --------------------------------------------------------

    SUCCESS = "success"

    # --------------------------------------------------------
    # Failed activity
    # --------------------------------------------------------

    FAILURE = "failure"

    # --------------------------------------------------------
    # Authorization / policy decision
    # --------------------------------------------------------

    ALLOWED = "allowed"
    DENIED = "denied"

    # --------------------------------------------------------
    # Security enforcement
    # --------------------------------------------------------

    BLOCKED = "blocked"

    # --------------------------------------------------------
    # Processing / operational error
    # --------------------------------------------------------

    ERROR = "error"

    # --------------------------------------------------------
    # Unknown or indeterminate result
    # --------------------------------------------------------

    UNKNOWN = "unknown"


# ============================================================
# Public API
# ============================================================


__all__ = [
    "EventCategory",
    "EventOutcome",
    "EventSeverity",
    "EventSourceType",
    "EventStage",
]