from datetime import UTC, datetime, timedelta

import pytest

from app.threat_intelligence.models import (
    IOCCreate,
    IOCStatus,
    IOCType,
    Reputation,
)
from app.threat_intelligence.service import ThreatIntelligenceService


def test_ioc_creation_normalizes_domain() -> None:
    service = ThreatIntelligenceService()

    ioc = service.add_ioc(
        IOCCreate(
            ioc_type=IOCType.DOMAIN,
            value=" Evil.Example.COM. ",
            confidence=0.9,
            source="unit-test",
            reputation=Reputation.MALICIOUS,
        )
    )

    assert ioc.normalized_value == "evil.example.com"
    assert ioc.status == IOCStatus.ACTIVE


def test_ioc_match_returns_reputation_and_source() -> None:
    service = ThreatIntelligenceService()

    service.add_ioc(
        IOCCreate(
            ioc_type=IOCType.IPV4,
            value="203.0.113.50",
            confidence=0.95,
            source="test-feed",
            reputation=Reputation.MALICIOUS,
        )
    )

    matches = service.enrich("203.0.113.50")

    assert len(matches) == 1
    assert matches[0].reputation == Reputation.MALICIOUS
    assert matches[0].source == "test-feed"


def test_duplicate_ioc_merges_observations() -> None:
    service = ThreatIntelligenceService()

    first = service.add_ioc(
        IOCCreate(
            ioc_type=IOCType.DOMAIN,
            value="evil.example",
            confidence=0.4,
            source="feed-a",
            reputation=Reputation.SUSPICIOUS,
        )
    )

    second = service.add_ioc(
        IOCCreate(
            ioc_type=IOCType.DOMAIN,
            value="EVIL.EXAMPLE.",
            confidence=0.9,
            source="feed-b",
            reputation=Reputation.MALICIOUS,
        )
    )

    assert first.ioc_id == second.ioc_id
    assert second.confidence == 0.9
    assert second.reputation == Reputation.MALICIOUS


def test_expired_ioc_is_rejected() -> None:
    service = ThreatIntelligenceService()
    expired = datetime.now(UTC) - timedelta(seconds=1)

    with pytest.raises(
        ValueError,
        match="expiration must be in the future",
    ):
        service.add_ioc(
            IOCCreate(
                ioc_type=IOCType.DOMAIN,
                value="expired.example",
                confidence=0.8,
                source="test",
                expiration=expired,
            )
        )


def test_revoke_removes_ioc_from_matching() -> None:
    service = ThreatIntelligenceService()

    ioc = service.add_ioc(
        IOCCreate(
            ioc_type=IOCType.HASH,
            value="a" * 64,
            confidence=1.0,
            source="test-feed",
            reputation=Reputation.MALICIOUS,
        )
    )

    service.revoke_ioc(ioc.ioc_id)

    assert service.enrich("a" * 64) == ()
