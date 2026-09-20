"""
Correlation engine package.
"""

from app.correlation.bootstrap import (
    CorrelationRuntime,
    build_correlation_runtime,
)
from app.correlation.engine import CorrelationEngine
from app.correlation.registry import CorrelationRuleRegistry
from app.correlation.result import CorrelationResult
from app.correlation.schema import CorrelationRule


__all__ = [
    "CorrelationEngine",
    "CorrelationResult",
    "CorrelationRule",
    "CorrelationRuleRegistry",
    "CorrelationRuntime",
    "build_correlation_runtime",
]