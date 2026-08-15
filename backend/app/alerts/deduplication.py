from __future__ import annotations

import hashlib

from app.alerts.models import AlertCreate


class AlertDeduplicator:
    """Generate stable keys and identify repeated alert occurrences."""

    @staticmethod
    def build_key(alert: AlertCreate) -> str:
        if alert.deduplication_key:
            return alert.deduplication_key

        material = "|".join(
            (
                alert.source_type.value,
                alert.rule_id,
                alert.asset_id or "",
                alert.user_id or "",
                alert.title,
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()
