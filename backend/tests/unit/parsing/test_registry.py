from __future__ import annotations

import pytest

from app.domain.events.models import (
    EnrichedEvent,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
)
from app.parsing.registry import EnricherRegistry, NormalizerRegistry, ParserRegistry


def test_parser_registry_registers_and_resolves() -> None:
    registry = ParserRegistry()

    def parser(event: RawEvent) -> ParsedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        return ParsedEvent(**data)

    registry.register("syslog", parser)
    assert registry.get("syslog") is parser
    assert registry.names() == ("syslog",)


def test_registry_rejects_duplicate_names() -> None:
    registry = ParserRegistry()

    def parser(event: RawEvent) -> ParsedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        return ParsedEvent(**data)

    registry.register("syslog", parser)
    with pytest.raises(ValueError, match="already registered"):
        registry.register("syslog", parser)


def test_registry_rejects_empty_names() -> None:
    registry = ParserRegistry()

    def parser(event: RawEvent) -> ParsedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        return ParsedEvent(**data)

    with pytest.raises(ValueError, match="must not be empty"):
        registry.register("   ", parser)


def test_registry_names_are_deterministic() -> None:
    registry = NormalizerRegistry()

    def first(event: ParsedEvent) -> NormalizedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        return NormalizedEvent(**data)

    def second(event: ParsedEvent) -> NormalizedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        return NormalizedEvent(**data)

    registry.register("z-normalizer", first)
    registry.register("a-normalizer", second)
    assert registry.names() == ("a-normalizer", "z-normalizer")


def test_enricher_registry_resolves_component() -> None:
    registry = EnricherRegistry()

    def enricher(event: RawEvent) -> EnrichedEvent:
        data = event.model_dump()
        data.pop("stage", None)
        return EnrichedEvent(**data)

    registry.register("asset", enricher)
    assert registry.get("asset") is enricher
