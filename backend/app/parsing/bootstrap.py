from __future__ import annotations

from app.parsing.normalizers.generic_security import (
    normalize_generic_security,
)
from app.parsing.normalizers.linux_auth import (
    normalize_linux_auth,
)
from app.parsing.parsers.generic_security import (
    parse_generic_security,
)
from app.parsing.parsers.linux_auth import (
    parse_linux_auth,
)
from app.parsing.pipeline import ParsingPipeline
from app.parsing.registry import (
    EnricherRegistry,
    NormalizerRegistry,
    ParserRegistry,
)
from app.parsing.router import (
    ParsingRoute,
    ParsingRouter,
)


# ============================================================
# Parser Registry
# ============================================================


def create_parser_registry() -> ParserRegistry:
    """
    Create and populate the production parser registry.

    All production parser implementations must be registered
    through this bootstrap boundary.
    """

    registry = ParserRegistry()

    # --------------------------------------------------------
    # Linux authentication parser
    # --------------------------------------------------------

    registry.register(
        "linux_auth",
        parse_linux_auth,
    )

    # --------------------------------------------------------
    # Generic security-event parser
    # --------------------------------------------------------

    registry.register(
        "generic_security",
        parse_generic_security,
    )

    return registry


# ============================================================
# Normalizer Registry
# ============================================================


def create_normalizer_registry() -> NormalizerRegistry:
    """
    Create and populate the production normalizer registry.

    Every enabled parsing route must reference a registered
    normalizer.
    """

    registry = NormalizerRegistry()

    # --------------------------------------------------------
    # Linux authentication normalizer
    # --------------------------------------------------------

    registry.register(
        "linux_auth",
        normalize_linux_auth,
    )

    # --------------------------------------------------------
    # Generic security-event normalizer
    # --------------------------------------------------------

    registry.register(
        "generic_security",
        normalize_generic_security,
    )

    return registry


# ============================================================
# Enricher Registry
# ============================================================


def create_enricher_registry() -> EnricherRegistry:
    """
    Create the production enricher registry.

    No production parsing enrichers are currently enabled.

    The empty registry is intentional and provides the stable
    extension point for future enrichment components.
    """

    return EnricherRegistry()


# ============================================================
# Parsing Pipeline
# ============================================================


def create_parsing_pipeline() -> ParsingPipeline:
    """
    Build the production ParsingPipeline.

    Component registration is deliberately kept outside the
    pipeline so ParsingPipeline remains responsible only for
    orchestration and contract enforcement.
    """

    parser_registry = create_parser_registry()
    normalizer_registry = create_normalizer_registry()
    enricher_registry = create_enricher_registry()

    return ParsingPipeline(
        parser_registry=parser_registry,
        normalizer_registry=normalizer_registry,
        enricher_registry=enricher_registry,
    )


# ============================================================
# Parsing Router
# ============================================================


def create_parsing_router(
    pipeline: ParsingPipeline | None = None,
) -> ParsingRouter:
    """
    Build the production ParsingRouter.

    The router maps logical parsing routes to registered
    parser and normalizer components.

    Dependency injection is supported so tests and callers
    can provide an already configured ParsingPipeline.

    Raises:
        KeyError:
            If a route references a parser or normalizer that
            is not registered.
    """

    parsing_pipeline = (
        pipeline
        if pipeline is not None
        else create_parsing_pipeline()
    )

    router = ParsingRouter(
        parsing_pipeline,
    )

    # --------------------------------------------------------
    # Linux authentication route
    # --------------------------------------------------------

    router.register(
        ParsingRoute(
            name="linux_auth",
            parser_name="linux_auth",
            normalizer_name="linux_auth",
        ),
    )

    # --------------------------------------------------------
    # Generic security-event route
    # --------------------------------------------------------

    router.register(
        ParsingRoute(
            name="generic_security",
            parser_name="generic_security",
            normalizer_name="generic_security",
        ),
    )

    # --------------------------------------------------------
    # Fail fast during application bootstrap
    # --------------------------------------------------------

    router.validate()

    return router


# ============================================================
# Production Parsing Components
# ============================================================


def create_parsing_components() -> tuple[
    ParsingPipeline,
    ParsingRouter,
]:
    """
    Create the complete production parsing subsystem.

    Returns:
        (
            ParsingPipeline,
            ParsingRouter,
        )

    Architecture:

        ParserRegistry
               |
               +----------------------+
               |                      |
               v                      v
        linux_auth parser     generic_security parser
               |                      |
               v                      v
        linux_auth normalizer generic_security normalizer
               |                      |
               +----------+-----------+
                          |
                          v
                  EnricherRegistry
                          |
                          v
                  ParsingPipeline
                          |
                          v
                   ParsingRouter
    """

    pipeline = create_parsing_pipeline()

    router = create_parsing_router(
        pipeline,
    )

    return pipeline, router


# ============================================================
# Public API
# ============================================================


__all__ = [
    "create_enricher_registry",
    "create_normalizer_registry",
    "create_parser_registry",
    "create_parsing_components",
    "create_parsing_pipeline",
    "create_parsing_router",
]