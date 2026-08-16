from __future__ import annotations

from enum import StrEnum


class Permission(StrEnum):
    EVENTS_READ = "events:read"
    ALERTS_READ = "alerts:read"
    ALERTS_MANAGE = "alerts:manage"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_MANAGE = "incidents:manage"
    IOCS_READ = "iocs:read"
    IOCS_MANAGE = "iocs:manage"
    MITRE_READ = "mitre:read"
    DASHBOARD_READ = "dashboard:read"
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    ROLES_READ = "roles:read"
    ROLES_MANAGE = "roles:manage"
    DETECTIONS_READ = "detections:read"
    DETECTIONS_MANAGE = "detections:manage"
    ASSETS_READ = "assets:read"
    ASSETS_MANAGE = "assets:manage"
    SYSTEM_READ = "system:read"

ALL_PERMISSIONS = frozenset(permission.value for permission in Permission)
