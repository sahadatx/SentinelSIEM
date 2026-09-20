from __future__ import annotations

from dataclasses import dataclass

from app.domain.events.models import RawEvent
from app.parsing.pipeline import ParsingPipeline


# =========================================================
# Parsing Route
# =========================================================


@dataclass(frozen=True, slots=True)
class ParsingRoute:
    """
    Immutable parsing route definition.

    A route maps a logical source/parser name to the parser
    and normalizer that must process the event.
    """

    name: str
    parser_name: str
    normalizer_name: str

    def __post_init__(self) -> None:
        """
        Validate route configuration at construction time.
        """

        for field_name, value in (
            ("name", self.name),
            ("parser_name", self.parser_name),
            ("normalizer_name", self.normalizer_name),
        ):
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string",
                )

            if not value.strip():
                raise ValueError(
                    f"{field_name} must not be empty",
                )


# =========================================================
# Parsing Router
# =========================================================


class ParsingRouter:
    """
    Deterministic router for production parsing.

    Responsibilities:
        - Register parsing routes.
        - Prevent duplicate route registration.
        - Resolve a route for a RawEvent.
        - Validate that referenced parser and normalizer
          components exist.
        - Execute the selected ParsingPipeline route.

    The router does not:
        - Parse events itself.
        - Normalize events itself.
        - Canonicalize events itself.
        - Register parser/normalizer implementations.
        - Persist events.
        - Execute detection.
        - Execute correlation.
        - Manage external infrastructure.

    Architecture:

        RawEvent
            |
            v
        ParsingRouter
            |
            +---- parser_name
            |
            +---- normalizer_name
            |
            v
        ParsingPipeline
            |
            v
        CanonicalSecurityEvent
    """

    def __init__(
        self,
        pipeline: ParsingPipeline,
    ) -> None:
        """
        Initialize the parsing router.

        Args:
            pipeline:
                Production or test ParsingPipeline instance.

        Raises:
            TypeError:
                If pipeline is not a ParsingPipeline.
        """

        if not isinstance(pipeline, ParsingPipeline):
            raise TypeError(
                "pipeline must be a ParsingPipeline",
            )

        self.pipeline = pipeline
        self._routes: dict[str, ParsingRoute] = {}

    # =====================================================
    # Registration
    # =====================================================

    def register(
        self,
        route: ParsingRoute,
    ) -> None:
        """
        Register a parsing route.

        Duplicate route names are rejected.

        Raises:
            TypeError:
                If route is not a ParsingRoute.

            ValueError:
                If a route with the same name already exists.
        """

        if not isinstance(route, ParsingRoute):
            raise TypeError(
                "route must be a ParsingRoute",
            )

        route_name = self._normalize_name(route.name)

        if route_name in self._routes:
            raise ValueError(
                f"parsing route already registered: {route_name}",
            )

        self._validate_components(route)

        self._routes[route_name] = route

    # =====================================================
    # Lookup
    # =====================================================

    def get(
        self,
        name: str,
    ) -> ParsingRoute:
        """
        Return a registered parsing route.

        Raises:
            ValueError:
                If the route name is invalid.

            KeyError:
                If the route is not registered.
        """

        route_name = self._normalize_name(name)

        try:
            return self._routes[route_name]
        except KeyError as exc:
            raise KeyError(
                f"parsing route not registered: {route_name}",
            ) from exc

    def names(self) -> tuple[str, ...]:
        """
        Return registered route names in deterministic order.
        """

        return tuple(sorted(self._routes))

    def contains(
        self,
        name: str,
    ) -> bool:
        """
        Check whether a parsing route exists.
        """

        route_name = self._normalize_name(name)
        return route_name in self._routes

    def count(self) -> int:
        """
        Return the number of registered parsing routes.
        """

        return len(self._routes)

    # =====================================================
    # Routing
    # =====================================================

    def route(
        self,
        event: RawEvent,
        *,
        route_name: str | None = None,
    ) -> ParsingRoute:
        """
        Resolve the parsing route for a RawEvent.

        Production callers should normally provide route_name
        explicitly through an upstream source-to-route mapping.

        If route_name is omitted, the event source is used as
        the logical route name.

        Example:

            event.source = "linux_auth"

        resolves:

            linux_auth -> parser=linux_auth
                       -> normalizer=linux_auth

        Raises:
            TypeError:
                If event is not a RawEvent.

            KeyError:
                If the resolved route does not exist.
        """

        if not isinstance(event, RawEvent):
            raise TypeError(
                "event must be a RawEvent",
            )

        resolved_name = (
            route_name
            if route_name is not None
            else event.source
        )

        return self.get(resolved_name)

    # =====================================================
    # Processing
    # =====================================================

    def process(
        self,
        event: RawEvent,
        *,
        route_name: str | None = None,
        canonical_fields: dict[str, object] | None = None,
        enricher_name: str | None = None,
    ):
        """
        Route and process a RawEvent through ParsingPipeline.

        Flow:

            RawEvent
                |
                v
            ParsingRouter
                |
                v
            ParsingRoute
                |
                +--> parser
                |
                +--> normalizer
                |
                v
            ParsingPipeline
                |
                v
            CanonicalSecurityEvent
                |
                v
            Optional EnrichedEvent

        Args:
            event:
                Raw event to process.

            route_name:
                Optional explicit parsing route.

                When omitted, event.source is used.

            canonical_fields:
                Optional canonical field overrides.

            enricher_name:
                Optional registered enricher.

        Returns:
            CanonicalSecurityEvent | EnrichedEvent

        Raises:
            TypeError:
                If event is not a RawEvent.

            KeyError:
                If the route or pipeline component is not
                registered.

            ValueError:
                If a parsing component violates its contract.
        """

        route = self.route(
            event,
            route_name=route_name,
        )

        return self.pipeline.process(
            event,
            parser_name=route.parser_name,
            normalizer_name=route.normalizer_name,
            canonical_fields=canonical_fields,
            enricher_name=enricher_name,
        )

    # =====================================================
    # Validation
    # =====================================================

    def validate(self) -> None:
        """
        Validate every registered route against the current
        parser and normalizer registries.

        This is useful during application bootstrap so invalid
        production configuration fails before event ingestion.

        Raises:
            KeyError:
                If any route references an unavailable parser
                or normalizer.
        """

        for route in self._routes.values():
            self._validate_components(route)

    def _validate_components(
        self,
        route: ParsingRoute,
    ) -> None:
        """
        Ensure a route references registered components.
        """

        try:
            self.pipeline.parsers.get(
                route.parser_name,
            )
        except KeyError as exc:
            raise KeyError(
                f"parsing route '{route.name}' references "
                f"unregistered parser: {route.parser_name}",
            ) from exc

        try:
            self.pipeline.normalizers.get(
                route.normalizer_name,
            )
        except KeyError as exc:
            raise KeyError(
                f"parsing route '{route.name}' references "
                f"unregistered normalizer: "
                f"{route.normalizer_name}",
            ) from exc

    # =====================================================
    # Lifecycle
    # =====================================================

    def clear(self) -> None:
        """
        Remove all registered parsing routes.
        """

        self._routes.clear()

    # =====================================================
    # Helpers
    # =====================================================

    @staticmethod
    def _normalize_name(
        name: str,
    ) -> str:
        """
        Normalize and validate a route name.
        """

        if not isinstance(name, str):
            raise TypeError(
                "parsing route name must be a string",
            )

        normalized = name.strip()

        if not normalized:
            raise ValueError(
                "parsing route name must not be empty",
            )

        return normalized


# =========================================================
# Public API
# =========================================================


__all__ = [
    "ParsingRoute",
    "ParsingRouter",
]
