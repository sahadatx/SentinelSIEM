from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.correlation.engine import CorrelationEngine
from app.correlation.registry import CorrelationRuleRegistry
from app.correlation.rules.loader import load_rules


@dataclass(slots=True)
class CorrelationRuntime:
    """
    Application-scoped correlation runtime.

    Runtime topology:

        CorrelationRuleRegistry
                  ↓
        CorrelationEngine
    """

    rule_registry: CorrelationRuleRegistry
    correlation_engine: CorrelationEngine


def build_correlation_runtime(
    *,
    rules_directory: Path,
) -> CorrelationRuntime:
    """
    Build the complete production correlation runtime.
    """

    if not isinstance(
        rules_directory,
        Path,
    ):
        raise TypeError(
            "rules_directory must be pathlib.Path",
        )

    if not rules_directory.exists():
        raise FileNotFoundError(
            "correlation rules directory does not exist: "
            f"{rules_directory}",
        )

    if not rules_directory.is_dir():
        raise NotADirectoryError(
            "correlation rules path is not a directory: "
            f"{rules_directory}",
        )

    rules = load_rules(
        rules_directory,
    )

    registry = CorrelationRuleRegistry(
        rules,
    )

    engine = CorrelationEngine(
        registry,
    )

    return CorrelationRuntime(
        rule_registry=registry,
        correlation_engine=engine,
    )


__all__ = [
    "CorrelationRuntime",
    "build_correlation_runtime",
]
