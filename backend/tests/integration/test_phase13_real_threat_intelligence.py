from app.threat_intelligence.models import IOCCreate, IOCType, Reputation
from app.threat_intelligence.service import ThreatIntelligenceService


def test_phase13_real_threat_intelligence_workflow() -> None:
    service = ThreatIntelligenceService()

    service.add_ioc(
        IOCCreate(
            ioc_type=IOCType.IPV4,
            value="203.0.113.50",
            confidence=0.98,
            source="simulated-threat-feed",
            feed="demo-feed",
            reputation=Reputation.MALICIOUS,
        )
    )

    service.add_ioc(
        IOCCreate(
            ioc_type=IOCType.DOMAIN,
            value="c2.example.com.",
            confidence=0.91,
            source="simulated-threat-feed",
            feed="demo-feed",
            reputation=Reputation.MALICIOUS,
        )
    )

    ip_matches = service.enrich("203.0.113.50")
    domain_matches = service.enrich("C2.EXAMPLE.COM")

    assert len(ip_matches) == 1
    assert ip_matches[0].reputation == Reputation.MALICIOUS
    assert ip_matches[0].confidence == 0.98

    assert len(domain_matches) == 1
    assert domain_matches[0].value == "c2.example.com"

    print("REAL PHASE 13 THREAT INTELLIGENCE TEST PASSED")
    print("IP matches     :", len(ip_matches))
    print("Domain matches :", len(domain_matches))
    print("IOC reputation :", ip_matches[0].reputation.value)
