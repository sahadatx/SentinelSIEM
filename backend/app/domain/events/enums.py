from __future__ import annotations

from enum import StrEnum


class EventStage(StrEnum):
    """Processing lifecycle stage of a security event."""

    RAW = "raw"
    PARSED = "parsed"
    NORMALIZED = "normalized"
    CANONICAL = "canonical"
    ENRICHED = "enriched"


class EventSourceType(StrEnum):
    """Origin or transport type of an incoming event."""

    SYSLOG = "syslog"
    HTTP = "http"
    TCP = "tcp"
    FILE = "file"
    WINDOWS = "windows"
    APPLICATION = "application"
    OTHER = "other"


class EventSeverity(StrEnum):
    """Severity assigned to a security event."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(StrEnum):
    """Security category associated with an event."""

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


class EventOutcome(StrEnum):
    """Outcome of the activity represented by an event."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"