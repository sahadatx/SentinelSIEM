from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.alerts.models import Alert


class AlertNotificationSink(Protocol):
    """Notification adapter contract; external channels belong behind this boundary."""

    def notify(self, alert: Alert, event: str) -> None:
        ...


@dataclass(slots=True)
class InMemoryNotificationSink:
    """Test-safe notification sink that records notification events."""

    notifications: list[tuple[str, str]]

    def __init__(self) -> None:
        self.notifications = []

    def notify(self, alert: Alert, event: str) -> None:
        self.notifications.append((str(alert.alert_id), event))
