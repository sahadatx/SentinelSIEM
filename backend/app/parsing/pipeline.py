from __future__ import annotations

from app.domain.events.enums import EventStage
from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
)
from app.parsing.registry import EnricherRegistry, NormalizerRegistry, ParserRegistry


class ParsingPipeline:
    """Orchestrate parsing, normalization, canonicalization, and enrichment."""

    def __init__(
        self,
        parser_registry: ParserRegistry | None = None,
        normalizer_registry: NormalizerRegistry | None = None,
        enricher_registry: EnricherRegistry | None = None,
    ) -> None:
        self.parsers = parser_registry or ParserRegistry()
        self.normalizers = normalizer_registry or NormalizerRegistry()
        self.enrichers = enricher_registry or EnricherRegistry()

    def parse(self, event: RawEvent, parser_name: str) -> ParsedEvent:
        parser = self.parsers.get(parser_name)
        parsed = parser(event)
        self._require_same_identity(event, parsed, "parser")
        if parsed.stage != EventStage.PARSED:
            raise ValueError("parser must return a parsed event")
        return parsed

    def normalize(
        self,
        event: ParsedEvent,
        normalizer_name: str,
    ) -> NormalizedEvent:
        normalizer = self.normalizers.get(normalizer_name)
        normalized = normalizer(event)
        self._require_same_identity(event, normalized, "normalizer")
        if normalized.stage != EventStage.NORMALIZED:
            raise ValueError("normalizer must return a normalized event")
        return normalized

    def canonicalize(
        self,
        event: NormalizedEvent,
        *,
        fields: dict[str, object] | None = None,
    ) -> CanonicalSecurityEvent:
        data = event.model_dump()
        data.pop("stage", None)
        data.update(fields or {})
        canonical = CanonicalSecurityEvent(**data)
        self._require_same_identity(event, canonical, "canonicalization")
        if canonical.stage != EventStage.CANONICAL:
            raise ValueError("canonicalization must return a canonical event")
        return canonical

    def enrich(
        self,
        event: CanonicalSecurityEvent,
        enricher_name: str,
    ) -> EnrichedEvent:
        enricher = self.enrichers.get(enricher_name)
        enriched = enricher(event)
        self._require_same_identity(event, enriched, "enricher")
        if enriched.stage != EventStage.ENRICHED:
            raise ValueError("enricher must return an enriched event")
        return enriched

    def process(
        self,
        event: RawEvent,
        *,
        parser_name: str,
        normalizer_name: str,
        canonical_fields: dict[str, object] | None = None,
        enricher_name: str | None = None,
    ) -> CanonicalSecurityEvent | EnrichedEvent:
        parsed = self.parse(event, parser_name)
        normalized = self.normalize(parsed, normalizer_name)
        canonical = self.canonicalize(normalized, fields=canonical_fields)
        if enricher_name is None:
            return canonical
        return self.enrich(canonical, enricher_name)

    @staticmethod
    def _require_same_identity(
        source: RawEvent | ParsedEvent | NormalizedEvent | CanonicalSecurityEvent,
        result: ParsedEvent | NormalizedEvent | CanonicalSecurityEvent | EnrichedEvent,
        component: str,
    ) -> None:
        if result.event_id != source.event_id:
            raise ValueError(f"{component} must preserve event_id")
