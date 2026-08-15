from __future__ import annotations

import pytest

from app.domain.events.enums import (
    EventCategory,
    EventOutcome,
    EventSeverity,
    EventSourceType,
    EventStage,
)
from app.domain.events.factory import create_raw_event
from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
)
from app.parsing.pipeline import ParsingPipeline


def build_pipeline() -> ParsingPipeline:
    pipeline = ParsingPipeline()

    def parse(event: RawEvent) -> ParsedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        data["parsed_data"] = {
            "action": "login",
            "username": "admin",
            "outcome": "failure",
        }
        return ParsedEvent(**data)

    def normalize(event: ParsedEvent) -> NormalizedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        data["normalized_data"] = {
            "action": "login",
            "username": "admin",
            "outcome": EventOutcome.FAILURE,
        }
        return NormalizedEvent(**data)

    def enrich(event: CanonicalSecurityEvent) -> EnrichedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        data["enrichment"] = {"asset": {"criticality": "high"}}
        return EnrichedEvent(**data)

    pipeline.parsers.register("test-parser", parse)
    pipeline.normalizers.register("test-normalizer", normalize)
    pipeline.enrichers.register("test-enricher", enrich)
    return pipeline


def test_pipeline_parse_normalize_canonicalize() -> None:
    pipeline = build_pipeline()
    raw = create_raw_event("auth01", EventSourceType.SYSLOG, "Failed password for admin")

    parsed = pipeline.parse(raw, "test-parser")
    normalized = pipeline.normalize(parsed, "test-normalizer")
    canonical = pipeline.canonicalize(
        normalized,
        fields={
            "username": "admin",
            "action": "login",
            "outcome": EventOutcome.FAILURE,
            "severity": EventSeverity.HIGH,
            "category": EventCategory.AUTHENTICATION,
        },
    )

    assert parsed.event_id == raw.event_id
    assert normalized.event_id == raw.event_id
    assert canonical.event_id == raw.event_id
    assert parsed.stage == EventStage.PARSED
    assert normalized.stage == EventStage.NORMALIZED
    assert canonical.stage == EventStage.CANONICAL
    assert parsed.parsed_data["action"] == "login"
    assert normalized.normalized_data["outcome"] == EventOutcome.FAILURE
    assert canonical.username == "admin"
    assert canonical.category == EventCategory.AUTHENTICATION


def test_pipeline_can_enrich_canonical_event() -> None:
    pipeline = build_pipeline()
    raw = create_raw_event("auth01", EventSourceType.SYSLOG, "Failed password for admin")

    parsed = pipeline.parse(raw, "test-parser")
    normalized = pipeline.normalize(parsed, "test-normalizer")
    canonical = pipeline.canonicalize(normalized)
    enriched = pipeline.enrich(canonical, "test-enricher")

    assert isinstance(enriched, EnrichedEvent)
    assert enriched.event_id == raw.event_id
    assert enriched.stage == EventStage.ENRICHED
    assert enriched.enrichment["asset"]["criticality"] == "high"


def test_pipeline_process_runs_all_stages() -> None:
    pipeline = build_pipeline()
    raw = create_raw_event("auth01", EventSourceType.SYSLOG, "Failed password for admin")

    result = pipeline.process(
        raw,
        parser_name="test-parser",
        normalizer_name="test-normalizer",
        canonical_fields={
            "username": "admin",
            "action": "login",
            "outcome": EventOutcome.FAILURE,
            "severity": EventSeverity.HIGH,
            "category": EventCategory.AUTHENTICATION,
        },
        enricher_name="test-enricher",
    )

    assert isinstance(result, EnrichedEvent)
    assert result.event_id == raw.event_id
    assert result.username == "admin"
    assert result.enrichment["asset"]["criticality"] == "high"


def test_pipeline_rejects_event_id_change() -> None:
    pipeline = ParsingPipeline()

    def bad_parser(event: RawEvent) -> ParsedEvent:
        other = create_raw_event(
            event.source,
            event.source_type,
            event.raw_event,
            timestamp=event.timestamp,
        )
        data = other.model_dump()
        data.pop("stage", None)
        return ParsedEvent(**data)

    pipeline.parsers.register("bad-parser", bad_parser)
    raw = create_raw_event("auth01", EventSourceType.SYSLOG, "event")

    with pytest.raises(ValueError, match="preserve event_id"):
        pipeline.parse(raw, "bad-parser")


def test_pipeline_rejects_wrong_parser_stage() -> None:
    pipeline = ParsingPipeline()

    def bad_parser(event: RawEvent) -> ParsedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        data["stage"] = EventStage.NORMALIZED
        return ParsedEvent.model_validate(data)

    pipeline.parsers.register("bad-parser", bad_parser)
    raw = create_raw_event("auth01", EventSourceType.SYSLOG, "event")

    with pytest.raises(ValueError, match="parsed event"):
        pipeline.parse(raw, "bad-parser")
