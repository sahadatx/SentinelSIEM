from __future__ import annotations

from datetime import UTC, datetime, timedelta


SuppressionKey = tuple[str, str]


class DetectionSuppression:
    """
    In-memory suppression guard for duplicate rule/event matches.

    A suppression entry is identified by:

        (rule_id, event_id)

    Once a rule/event pair is suppressed, another match for the same pair
    is considered suppressed until the configured TTL expires.

    Responsibilities
    ----------------
    - Prevent duplicate rule/event matches within a short TTL window.
    - Manage in-memory suppression entries.
    - Remove expired entries.
    - Provide explicit clearing for lifecycle/shutdown use.

    Non-responsibilities
    --------------------
    - Does not persist suppression state.
    - Does not provide distributed suppression.
    - Does not create alerts.
    - Does not modify DetectionResult.
    - Does not perform RBAC.
    - Does not manage alert lifecycle.

    Persistent or distributed suppression belongs to later alert/correlation
    infrastructure.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 60,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")

        self._ttl = timedelta(seconds=ttl_seconds)
        self._entries: dict[SuppressionKey, datetime] = {}

    @property
    def ttl(self) -> timedelta:
        """
        Return the configured suppression lifetime.
        """
        return self._ttl

    def is_suppressed(
        self,
        rule_id: str,
        event_id: str,
    ) -> bool:
        """
        Check whether a rule/event pair is currently suppressed.

        Expired entries are removed immediately when encountered.
        """
        key = self._build_key(rule_id, event_id)

        expires_at = self._entries.get(key)

        if expires_at is None:
            return False

        now = datetime.now(UTC)

        if expires_at <= now:
            self._entries.pop(key, None)
            return False

        return True

    def suppress(
        self,
        rule_id: str,
        event_id: str,
    ) -> None:
        """
        Register a rule/event pair as suppressed until the TTL expires.
        """
        key = self._build_key(rule_id, event_id)

        self._entries[key] = datetime.now(UTC) + self._ttl

    def clear(self) -> None:
        """
        Remove all suppression entries.
        """
        self._entries.clear()

    def cleanup(self) -> int:
        """
        Remove all expired suppression entries.

        Returns
        -------
        int
            Number of expired entries removed.
        """
        now = datetime.now(UTC)

        expired_keys = [
            key
            for key, expires_at in self._entries.items()
            if expires_at <= now
        ]

        for key in expired_keys:
            self._entries.pop(key, None)

        return len(expired_keys)

    def size(self) -> int:
        """
        Return the current number of stored suppression entries.

        Expired entries are cleaned before returning the size.
        """
        self.cleanup()
        return len(self._entries)

    @staticmethod
    def _build_key(
        rule_id: str,
        event_id: str,
    ) -> SuppressionKey:
        """
        Build and validate the internal suppression key.
        """
        normalized_rule_id = str(rule_id).strip()
        normalized_event_id = str(event_id).strip()

        if not normalized_rule_id:
            raise ValueError("rule_id must not be empty")

        if not normalized_event_id:
            raise ValueError("event_id must not be empty")

        return (
            normalized_rule_id,
            normalized_event_id,
        )