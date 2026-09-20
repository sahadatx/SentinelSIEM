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
    """
    Build a fully configured test parsing pipeline.

    The test pipeline intentionally registers local test
    implementations so parser, normalizer, canonicalization,
    and enrichment stages can be tested independently.
    """
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

        data["enrichment"] = {
            "asset": {
                "criticality": "high",
            },
        }

        return EnrichedEvent(**data)

    pipeline.parsers.register(
        "test-parser",
        parse,
    )

    pipeline.normalizers.register(
        "test-normalizer",
        normalize,
    )

    pipeline.enrichers.register(
        "test-enricher",
        enrich,
    )

    return pipeline


def create_test_raw_event() -> RawEvent:
    """Create a deterministic test input event."""
    return create_raw_event(
        source="auth01",
        source_type=EventSourceType.SYSLOG,
        raw_event="Failed password for admin",
    )


def test_pipeline_parse_normalize_canonicalize() -> None:
    """Verify the parser → normalizer → canonical flow."""
    pipeline = build_pipeline()
    raw = create_test_raw_event()

    parsed = pipeline.parse(
        raw,
        parser_name="test-parser",
    )

    normalized = pipeline.normalize(
        parsed,
        normalizer_name="test-normalizer",
    )

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

    # Identity preservation.
    assert parsed.event_id == raw.event_id
    assert normalized.event_id == raw.event_id
    assert canonical.event_id == raw.event_id

    # Stage transitions.
    assert parsed.stage == EventStage.PARSED
    assert normalized.stage == EventStage.NORMALIZED
    assert canonical.stage == EventStage.CANONICAL

    # Stage-specific data.
    assert parsed.parsed_data["action"] == "login"
    assert parsed.parsed_data["username"] == "admin"

    assert normalized.normalized_data["action"] == "login"
    assert normalized.normalized_data["outcome"] == EventOutcome.FAILURE

    # Canonical fields.
    assert canonical.username == "admin"
    assert canonical.action == "login"
    assert canonical.outcome == EventOutcome.FAILURE
    assert canonical.severity == EventSeverity.HIGH
    assert canonical.category == EventCategory.AUTHENTICATION


def test_pipeline_can_enrich_canonical_event() -> None:
    """Verify canonical → enriched transition."""
    pipeline = build_pipeline()
    raw = create_test_raw_event()

    parsed = pipeline.parse(
        raw,
        parser_name="test-parser",
    )

    normalized = pipeline.normalize(
        parsed,
        normalizer_name="test-normalizer",
    )

    canonical = pipeline.canonicalize(normalized)

    enriched = pipeline.enrich(
        canonical,
        enricher_name="test-enricher",
    )

    assert isinstance(enriched, EnrichedEvent)
    assert enriched.event_id == raw.event_id
    assert enriched.stage == EventStage.ENRICHED

    assert enriched.enrichment["asset"]["criticality"] == "high"


def test_pipeline_process_runs_all_stages() -> None:
    """Verify the complete parsing pipeline orchestration."""
    pipeline = build_pipeline()
    raw = create_test_raw_event()

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
    assert result.stage == EventStage.ENRICHED

    assert result.username == "admin"
    assert result.action == "login"
    assert result.outcome == EventOutcome.FAILURE
    assert result.severity == EventSeverity.HIGH
    assert result.category == EventCategory.AUTHENTICATION

    assert result.enrichment["asset"]["criticality"] == "high"


def test_pipeline_process_without_enrichment_returns_canonical() -> None:
    """Verify process() returns canonical output when no enricher is requested."""
    pipeline = build_pipeline()
    raw = create_test_raw_event()

    result = pipeline.process(
        raw,
        parser_name="test-parser",
        normalizer_name="test-normalizer",
        canonical_fields={
            "username": "admin",
            "action": "login",
            "outcome": EventOutcome.FAILURE,
        },
    )

    assert isinstance(result, CanonicalSecurityEvent)
    assert not isinstance(result, EnrichedEvent)

    assert result.event_id == raw.event_id
    assert result.stage == EventStage.CANONICAL
    assert result.username == "admin"
    assert result.action == "login"
    assert result.outcome == EventOutcome.FAILURE


def test_pipeline_rejects_event_id_change() -> None:
    """A parser must preserve the original event identity."""
    pipeline = ParsingPipeline()

    def bad_parser(event: RawEvent) -> ParsedEvent:
        other = create_raw_event(
            source=event.source,
            source_type=event.source_type,
            raw_event=event.raw_event,
            timestamp=event.timestamp,
        )

        data = other.model_dump()
        data.pop("stage", None)

        return ParsedEvent(**data)

    pipeline.parsers.register(
        "bad-parser",
        bad_parser,
    )

    raw = create_test_raw_event()

    with pytest.raises(
        ValueError,
        match="preserve event_id",
    ):
        pipeline.parse(
            raw,
            parser_name="bad-parser",
        )


def test_pipeline_rejects_wrong_parser_stage() -> None:
    """
    A parser must return an event with PARSED stage.

    The contract error intentionally contains the phrase
    'parsed event' for compatibility with the existing test
    contract.
    """
    pipeline = ParsingPipeline()

    def bad_parser(event: RawEvent) -> ParsedEvent:
        data = event.model_dump()
        data.pop("stage", None)

        data["stage"] = EventStage.NORMALIZED

        return ParsedEvent.model_validate(data)

    pipeline.parsers.register(
        "bad-parser",
        bad_parser,
    )

    raw = create_test_raw_event()

    with pytest.raises(
        ValueError,
        match="parsed event",
    ):
        pipeline.parse(
            raw,
            parser_name="bad-parser",
        )


def test_pipeline_rejects_wrong_normalizer_stage() -> None:
    """A normalizer must return an event with NORMALIZED stage."""
    pipeline = ParsingPipeline()

    def parser(event: RawEvent) -> ParsedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        data["parsed_data"] = {
            "action": "login",
        }

        return ParsedEvent(**data)

    def bad_normalizer(event: ParsedEvent) -> NormalizedEvent:
        data = event.model_dump()
        data.pop("stage", None)

        data["stage"] = EventStage.PARSED
        data["normalized_data"] = {
            "action": "login",
        }

        return NormalizedEvent.model_validate(data)

    pipeline.parsers.register(
        "parser",
        parser,
    )

    pipeline.normalizers.register(
        "bad-normalizer",
        bad_normalizer,
    )

    raw = create_test_raw_event()

    parsed = pipeline.parse(
        raw,
        parser_name="parser",
    )

    with pytest.raises(
        ValueError,
        match="normalized event",
    ):
        pipeline.normalize(
            parsed,
            normalizer_name="bad-normalizer",
        )


def test_pipeline_rejects_wrong_enricher_stage() -> None:
    """An enricher must return an event with ENRICHED stage."""
    pipeline = ParsingPipeline()

    def bad_enricher(
        event: CanonicalSecurityEvent,
    ) -> EnrichedEvent:
        data = event.model_dump()
        data.pop("stage", None)

        data["stage"] = EventStage.CANONICAL
        data["enrichment"] = {
            "test": True,
        }

        return EnrichedEvent.model_validate(data)

    pipeline.enrichers.register(
        "bad-enricher",
        bad_enricher,
    )

    raw = create_test_raw_event()

    canonical = CanonicalSecurityEvent(
        **raw.model_dump(exclude={"stage"}),
    )

    with pytest.raises(
        ValueError,
        match="enriched event",
    ):
        pipeline.enrich(
            canonical,
            enricher_name="bad-enricher",
        )


def test_pipeline_preserves_identity_through_enrichment() -> None:
    """Verify event_id remains unchanged across every pipeline stage."""
    pipeline = build_pipeline()
    raw = create_test_raw_event()

    parsed = pipeline.parse(
        raw,
        parser_name="test-parser",
    )

    normalized = pipeline.normalize(
        parsed,
        normalizer_name="test-normalizer",
    )

    canonical = pipeline.canonicalize(normalized)

    enriched = pipeline.enrich(
        canonical,
        enricher_name="test-enricher",
    )

    assert raw.event_id == parsed.event_id
    assert parsed.event_id == normalized.event_id
    assert normalized.event_id == canonical.event_id
    assert canonical.event_id == enriched.event_id
