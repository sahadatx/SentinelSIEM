from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.detection.result import DetectionResult


@dataclass(frozen=True, slots=True)
class DetectionSearchResult:
    """
    Immutable search result returned by DetectionResult repositories.

    Attributes
    ----------
    results:
        DetectionResult objects returned for the current page.

    total:
        Total number of persisted DetectionResult objects matching the
        supplied search/filter criteria, independent of pagination.
    """

    results: tuple[DetectionResult, ...]
    total: int

    def __post_init__(self) -> None:
        if self.total < 0:
            raise ValueError("total must be greater than or equal to zero")


@dataclass(frozen=True, slots=True)
class DetectionRuleStatistics:
    """
    Immutable aggregate statistics for one detection rule.

    Statistics are derived exclusively from persisted DetectionResult
    documents.

    Attributes
    ----------
    rule_id:
        Detection rule identifier.

    matches:
        Total persisted DetectionResult documents associated with the rule.

    suppressed:
        Total persisted DetectionResult documents marked as suppressed.

    last_match_at:
        Timestamp of the most recent persisted DetectionResult for the rule.
    """

    rule_id: str
    matches: int
    suppressed: int
    last_match_at: datetime | None

    def __post_init__(self) -> None:
        rule_id = self.rule_id.strip()

        if not rule_id:
            raise ValueError("rule_id must not be empty")

        if self.matches < 0:
            raise ValueError(
                "matches must be greater than or equal to zero"
            )

        if self.suppressed < 0:
            raise ValueError(
                "suppressed must be greater than or equal to zero"
            )

        if self.suppressed > self.matches:
            raise ValueError(
                "suppressed cannot be greater than matches"
            )


class DetectionRepository(Protocol):
    """
    Repository contract for persisted DetectionResult objects.

    Detection results are stored independently from:

        - security events
        - detection rules
        - alerts
        - incidents
        - correlation results

    The repository is responsible only for:

        1. DetectionResult persistence.
        2. DetectionResult retrieval.
        3. DetectionResult searching/filtering.
        4. DetectionResult counting.
        5. Read-side per-rule statistics.

    Rule lifecycle management belongs to the Detection rule service and
    its dedicated rule persistence layer.
    """

    async def ensure_index(self) -> None:
        """
        Ensure the DetectionResult persistence index exists.

        Implementations should make this operation idempotent.
        """
        ...

    async def save(
        self,
        result: DetectionResult,
    ) -> None:
        """
        Persist one validated DetectionResult.
        """
        ...

    async def get(
        self,
        detection_id: UUID,
    ) -> DetectionResult | None:
        """
        Retrieve one DetectionResult by its unique detection ID.

        Returns None when the requested result does not exist.
        """
        ...

    async def search(
        self,
        *,
        query: str | None = None,
        rule_id: str | None = None,
        event_id: UUID | None = None,
        severity: str | None = None,
        category: str | None = None,
        suppressed: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> DetectionSearchResult:
        """
        Search persisted DetectionResult objects.

        Supported filtering dimensions
        --------------------------------
        query:
            Free-text search supported by the repository implementation.

        rule_id:
            Filter by detection rule ID.

        event_id:
            Filter by source event ID.

        severity:
            Filter by detection severity.

        category:
            Filter by detection category.

        suppressed:
            Filter by suppression state.

        start_time:
            Inclusive lower bound for matched_at.

        end_time:
            Inclusive upper bound for matched_at.

        Pagination
        ----------
        offset:
            Zero-based result offset.

        limit:
            Maximum number of results returned for the current page.

        Returns
        -------
        DetectionSearchResult
            A page of results together with the total matching count.
        """
        ...

    async def count(
        self,
        *,
        rule_id: str | None = None,
        suppressed: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """
        Return the number of persisted DetectionResult documents matching
        the supplied filters.
        """
        ...

    async def get_rule_statistics(
        self,
        *,
        rule_ids: Sequence[str] | None = None,
    ) -> tuple[DetectionRuleStatistics, ...]:
        """
        Return persisted DetectionResult statistics grouped by rule.

        For each returned rule:

            matches
                Total persisted DetectionResult documents.

            suppressed
                Total suppressed DetectionResult documents.

            last_match_at
                Latest matched_at timestamp.

        When rule_ids is supplied, only those rule IDs are considered.

        Rules with no persisted DetectionResult are not required to be
        returned by this repository method. The Detection API/service may
        merge repository statistics with the active rule registry and
        expose zero-valued statistics for rules that have never matched.
        """
        ...


__all__ = [
    "DetectionRepository",
    "DetectionRuleStatistics",
    "DetectionSearchResult",
]