from __future__ import annotations

from enum import StrEnum


class EventStage(StrEnum):
    RAW = "raw"
    PARSED = "parsed"
    NORMALIZED = "normalized"
    CANONICAL = "canonical"
    ENRICHED = "enriched"


class EventSourceType(StrEnum):
    SYSLOG = "syslog"
    HTTP = "http"
    TCP = "tcp"
    FILE = "file"
    WINDOWS = "windows"
    APPLICATION = "application"
    OTHER = "other"


class EventSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(StrEnum):
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
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"
