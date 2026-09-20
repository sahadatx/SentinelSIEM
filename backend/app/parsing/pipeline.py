from __future__ import annotations

from typing import Any

from app.domain.events.enums import EventStage
from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
)
from app.parsing.canonical import (
    normalized_to_canonical_fields,
)
from app.parsing.registry import (
    EnricherRegistry,
    NormalizerRegistry,
    ParserRegistry,
)


class ParsingPipeline:
    """
    Production parsing pipeline for SentinelSIEM.

    Pipeline:

        RawEvent
            ↓
        Parser
            ↓
        ParsedEvent
            ↓
        Normalizer
            ↓
        NormalizedEvent
            ↓
        Canonicalization
            ↓
        CanonicalSecurityEvent
            ↓
        Optional Enricher
            ↓
        EnrichedEvent

    Responsibilities:
        - Resolve registered parsing components.
        - Execute parser contracts.
        - Execute normalizer contracts.
        - Promote normalized security fields.
        - Build canonical security events.
        - Execute optional enrichment.
        - Preserve event identity across every stage.
        - Validate domain event types.
        - Validate EventStage values.

    The pipeline does not:
        - Register components.
        - Persist events.
        - Execute detection rules.
        - Execute correlation rules.
        - Manage database sessions.
        - Manage external infrastructure.
    """

    def __init__(
        self,
        parser_registry: ParserRegistry | None = None,
        normalizer_registry: NormalizerRegistry | None = None,
        enricher_registry: EnricherRegistry | None = None,
    ) -> None:
        """
        Initialize the parsing pipeline.

        Explicit registries are supported for dependency injection
        and testing.

        When omitted, isolated empty registries are created.
        """

        self.parsers = (
            parser_registry
            if parser_registry is not None
            else ParserRegistry()
        )

        self.normalizers = (
            normalizer_registry
            if normalizer_registry is not None
            else NormalizerRegistry()
        )

        self.enrichers = (
            enricher_registry
            if enricher_registry is not None
            else EnricherRegistry()
        )

    # =========================================================
    # Parse
    # =========================================================

    def parse(
        self,
        event: RawEvent,
        parser_name: str,
    ) -> ParsedEvent:
        """
        Parse a RawEvent using a registered parser.

        Contract:

            RawEvent
                ↓
            Parser
                ↓
            ParsedEvent

        The parser must:
            - Be registered.
            - Return ParsedEvent.
            - Preserve event_id.
            - Return EventStage.PARSED.
        """

        if not isinstance(event, RawEvent):
            raise TypeError(
                "parser expects RawEvent",
            )

        if not isinstance(parser_name, str) or not parser_name.strip():
            raise ValueError(
                "parser_name must be a non-empty string",
            )

        parser = self.parsers.get(
            parser_name,
        )

        parsed = parser(event)

        self._require_result_type(
            result=parsed,
            expected_type=ParsedEvent,
            component="parser",
        )

        self._require_same_identity(
            source=event,
            result=parsed,
            component="parser",
        )

        self._require_stage(
            result=parsed,
            expected_stage=EventStage.PARSED,
            component="parser",
            expected_description="parsed event",
        )

        return parsed

    # =========================================================
    # Normalize
    # =========================================================

    def normalize(
        self,
        event: ParsedEvent,
        normalizer_name: str,
    ) -> NormalizedEvent:
        """
        Normalize a ParsedEvent using a registered normalizer.

        Contract:

            ParsedEvent
                ↓
            Normalizer
                ↓
            NormalizedEvent

        The normalizer must:
            - Be registered.
            - Return NormalizedEvent.
            - Preserve event_id.
            - Return EventStage.NORMALIZED.
        """

        if not isinstance(event, ParsedEvent):
            raise TypeError(
                "normalizer expects ParsedEvent",
            )

        if (
            not isinstance(normalizer_name, str)
            or not normalizer_name.strip()
        ):
            raise ValueError(
                "normalizer_name must be a non-empty string",
            )

        normalizer = self.normalizers.get(
            normalizer_name,
        )

        normalized = normalizer(event)

        self._require_result_type(
            result=normalized,
            expected_type=NormalizedEvent,
            component="normalizer",
        )

        self._require_same_identity(
            source=event,
            result=normalized,
            component="normalizer",
        )

        self._require_stage(
            result=normalized,
            expected_stage=EventStage.NORMALIZED,
            component="normalizer",
            expected_description="normalized event",
        )

        return normalized

    # =========================================================
    # Canonicalization
    # =========================================================

    def canonicalize(
        self,
        event: NormalizedEvent,
        *,
        fields: dict[str, Any] | None = None,
    ) -> CanonicalSecurityEvent:
        """
        Convert a NormalizedEvent into a CanonicalSecurityEvent.

        Canonical fields are automatically promoted from
        NormalizedEvent.normalized_data.

        Example:

            normalized_data = {
                "hostname": "auth01",
                "source_ip": "192.0.2.10",
                "source_port": 54321,
                "destination_port": 22,
                "protocol": "ssh",
                "username": "analyst",
                "process": "sshd",
                "action": "login",
                "outcome": "failure",
            }

        becomes:

            CanonicalSecurityEvent(
                hostname="auth01",
                source_ip="192.0.2.10",
                source_port=54321,
                destination_port=22,
                protocol="ssh",
                username="analyst",
                process="sshd",
                action="login",
                outcome=EventOutcome.FAILURE,
                ...
            )

        Existing event context is preserved.

        Explicit canonical fields supplied through ``fields``
        override automatically mapped fields.

        Preserved context includes:
            - event_id
            - timestamp
            - ingestion_timestamp
            - source
            - source_type
            - raw_event
            - metadata
            - parsed_data
            - normalized_data

        CanonicalSecurityEvent owns its EventStage.
        """

        if not isinstance(event, NormalizedEvent):
            raise TypeError(
                "canonicalization expects NormalizedEvent",
            )

        # -----------------------------------------------------
        # Automatically map normalized security fields
        # -----------------------------------------------------

        canonical_fields = normalized_to_canonical_fields(
            event,
        )

        # -----------------------------------------------------
        # Apply known security semantics
        #
        # Linux authentication:
        #
        #   login/session_* → authentication
        #   failure         → high
        #   success         → info
        #
        # These defaults only apply when the normalized event
        # has the corresponding semantic fields.
        # -----------------------------------------------------

        self._apply_security_semantics(
            canonical_fields,
        )

        # -----------------------------------------------------
        # Explicit fields override automatic mapping
        # -----------------------------------------------------

        if fields is not None:
            if not isinstance(fields, dict):
                raise TypeError(
                    "canonical fields must be a dictionary",
                )

            # Import locally to keep pipeline dependency focused
            # on the canonicalization boundary.
            from app.parsing.canonical import (
                _validate_explicit_fields,
            )

            explicit_fields = _validate_explicit_fields(
                fields,
            )

            canonical_fields.update(
                explicit_fields,
            )

        # -----------------------------------------------------
        # Preserve event context
        # -----------------------------------------------------

        canonical_data = event.model_dump(
            mode="python",
        )

        # Destination model owns its stage.
        canonical_data.pop(
            "stage",
            None,
        )

        # -----------------------------------------------------
        # Remove any canonical fields copied from the
        # NormalizedEvent itself.
        #
        # They will be supplied from canonical_fields instead.
        # -----------------------------------------------------

        for field in canonical_fields:
            canonical_data.pop(
                field,
                None,
            )

        # -----------------------------------------------------
        # Apply canonical security fields
        # -----------------------------------------------------

        canonical_data.update(
            canonical_fields,
        )

        # -----------------------------------------------------
        # Construct canonical event
        # -----------------------------------------------------

        canonical = CanonicalSecurityEvent(
            **canonical_data,
        )

        self._require_result_type(
            result=canonical,
            expected_type=CanonicalSecurityEvent,
            component="canonicalization",
        )

        self._require_same_identity(
            source=event,
            result=canonical,
            component="canonicalization",
        )

        self._require_stage(
            result=canonical,
            expected_stage=EventStage.CANONICAL,
            component="canonicalization",
            expected_description="canonical event",
        )

        return canonical

    # =========================================================
    # Security Semantics
    # =========================================================

    @staticmethod
    def _apply_security_semantics(
        fields: dict[str, Any],
    ) -> None:
        """
        Apply default security semantics to canonical fields.

        This method intentionally operates only on fields already
        extracted from normalized_data.

        Rules:

            login
            session_open
            session_close
                → authentication

            failure
                → high

            success
                → info

        Existing explicit overrides are applied later.
        """

        from app.domain.events.enums import (
            EventCategory,
            EventOutcome,
            EventSeverity,
        )

        action = fields.get(
            "action",
        )

        outcome = fields.get(
            "outcome",
        )

        # -----------------------------------------------------
        # Authentication category
        # -----------------------------------------------------

        if action in {
            "login",
            "session_open",
            "session_close",
        }:
            fields["category"] = (
                EventCategory.AUTHENTICATION
            )

        # -----------------------------------------------------
        # Failure severity
        # -----------------------------------------------------

        if outcome == EventOutcome.FAILURE:
            fields["severity"] = EventSeverity.HIGH

        # -----------------------------------------------------
        # Successful authentication severity
        # -----------------------------------------------------

        elif outcome == EventOutcome.SUCCESS:
            fields["severity"] = EventSeverity.INFO

    # =========================================================
    # Enrichment
    # =========================================================

    def enrich(
        self,
        event: CanonicalSecurityEvent,
        enricher_name: str,
    ) -> EnrichedEvent:
        """
        Enrich a CanonicalSecurityEvent using a registered enricher.

        Contract:

            CanonicalSecurityEvent
                ↓
            Enricher
                ↓
            EnrichedEvent

        The enricher must:
            - Be registered.
            - Return EnrichedEvent.
            - Preserve event_id.
            - Return EventStage.ENRICHED.
        """

        if not isinstance(
            event,
            CanonicalSecurityEvent,
        ):
            raise TypeError(
                "enricher expects CanonicalSecurityEvent",
            )

        if (
            not isinstance(enricher_name, str)
            or not enricher_name.strip()
        ):
            raise ValueError(
                "enricher_name must be a non-empty string",
            )

        enricher = self.enrichers.get(
            enricher_name,
        )

        enriched = enricher(event)

        self._require_result_type(
            result=enriched,
            expected_type=EnrichedEvent,
            component="enricher",
        )

        self._require_same_identity(
            source=event,
            result=enriched,
            component="enricher",
        )

        self._require_stage(
            result=enriched,
            expected_stage=EventStage.ENRICHED,
            component="enricher",
            expected_description="enriched event",
        )

        return enriched

    # =========================================================
    # Full Processing
    # =========================================================

    def process(
        self,
        event: RawEvent,
        *,
        parser_name: str,
        normalizer_name: str,
        canonical_fields: dict[str, Any] | None = None,
        enricher_name: str | None = None,
    ) -> CanonicalSecurityEvent | EnrichedEvent:
        """
        Execute the complete production parsing pipeline.

        Flow:

            RawEvent
                ↓
            Parser
                ↓
            ParsedEvent
                ↓
            Normalizer
                ↓
            NormalizedEvent
                ↓
            Canonicalization
                ↓
            CanonicalSecurityEvent
                ↓
            Optional Enrichment
                ↓
            EnrichedEvent

        When ``enricher_name`` is None, the canonical event
        is returned.
        """

        if not isinstance(event, RawEvent):
            raise TypeError(
                "pipeline process expects RawEvent",
            )

        parsed = self.parse(
            event,
            parser_name=parser_name,
        )

        normalized = self.normalize(
            parsed,
            normalizer_name=normalizer_name,
        )

        canonical = self.canonicalize(
            normalized,
            fields=canonical_fields,
        )

        if enricher_name is None:
            return canonical

        return self.enrich(
            canonical,
            enricher_name=enricher_name,
        )

    # =========================================================
    # Contract Validation
    # =========================================================

    @staticmethod
    def _require_result_type(
        *,
        result: object,
        expected_type: type[Any],
        component: str,
    ) -> None:
        """
        Ensure a pipeline component returned the expected
        domain event type.
        """

        if not isinstance(
            result,
            expected_type,
        ):
            raise ValueError(
                f"{component} must return "
                f"{expected_type.__name__}; "
                f"got {type(result).__name__}",
            )

    @staticmethod
    def _require_same_identity(
        *,
        source: (
            RawEvent
            | ParsedEvent
            | NormalizedEvent
            | CanonicalSecurityEvent
        ),
        result: (
            ParsedEvent
            | NormalizedEvent
            | CanonicalSecurityEvent
            | EnrichedEvent
        ),
        component: str,
    ) -> None:
        """
        Ensure event_id remains unchanged across pipeline stages.

        Event identity is immutable from the perspective of the
        parsing pipeline.
        """

        if result.event_id != source.event_id:
            raise ValueError(
                f"{component} must preserve event_id",
            )

    @staticmethod
    def _require_stage(
        *,
        result: (
            ParsedEvent
            | NormalizedEvent
            | CanonicalSecurityEvent
            | EnrichedEvent
        ),
        expected_stage: EventStage,
        component: str,
        expected_description: str,
    ) -> None:
        """
        Ensure a pipeline component returned the expected
        EventStage.
        """

        if result.stage != expected_stage:
            raise ValueError(
                f"{component} must return an "
                f"{expected_description} "
                f"with stage={expected_stage.value!r}; "
                f"got {result.stage.value!r}",
            )


__all__ = [
    "ParsingPipeline",
]