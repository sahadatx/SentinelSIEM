from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Any

_MAX_LABELS = 5
_MAX_LABEL_VALUE_LENGTH = 64

_DEFAULT_HISTOGRAM_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)


@dataclass(frozen=True, slots=True)
class MetricSample:
    name: str
    help_text: str
    metric_type: str
    labels: tuple[tuple[str, str], ...]
    value: float


@dataclass(slots=True)
class _HistogramState:
    buckets: tuple[float, ...]
    counts: list[int]
    count: int = 0
    total: float = 0.0


class MetricsRegistry:
    """
    Dependency-free Prometheus-compatible metrics registry.

    The registry enforces bounded label cardinality and bounded label
    value length to reduce accidental high-cardinality memory growth.
    """

    def __init__(self) -> None:
        self._lock = Lock()

        self._counters: dict[
            tuple[str, tuple[tuple[str, str], ...]],
            MetricSample,
        ] = {}

        self._gauges: dict[
            tuple[str, tuple[tuple[str, str], ...]],
            MetricSample,
        ] = {}

        self._histograms: dict[
            tuple[str, tuple[tuple[str, str], ...]],
            _HistogramState,
        ] = {}

        self._metadata: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name:
            raise ValueError("metric name cannot be empty")

        if not (name[0].isalpha() or name[0] == "_"):
            raise ValueError(f"invalid metric name: {name!r}")

        if not all(
            character.isalnum() or character == "_"
            for character in name
        ):
            raise ValueError(f"invalid metric name: {name!r}")

    @staticmethod
    def _validate_label_name(name: str) -> None:
        if not name:
            raise ValueError("metric label name cannot be empty")

        if not (name[0].isalpha() or name[0] == "_"):
            raise ValueError(
                f"invalid metric label name: {name!r}"
            )

        if not all(
            character.isalnum() or character == "_"
            for character in name
        ):
            raise ValueError(
                f"invalid metric label name: {name!r}"
            )

    @classmethod
    def _normalize_labels(
        cls,
        labels: dict[str, str] | None,
    ) -> tuple[tuple[str, str], ...]:
        if not labels:
            return ()

        if len(labels) > _MAX_LABELS:
            raise ValueError(
                f"metrics support at most {_MAX_LABELS} labels"
            )

        normalized: list[tuple[str, str]] = []

        for key, value in sorted(labels.items()):
            cls._validate_label_name(key)

            value_string = str(value)

            if len(value_string) > _MAX_LABEL_VALUE_LENGTH:
                raise ValueError(
                    "metric label values must be "
                    f"<= {_MAX_LABEL_VALUE_LENGTH} characters"
                )

            normalized.append((key, value_string))

        return tuple(normalized)

    @staticmethod
    def _escape_label_value(value: str) -> str:
        return (
            value
            .replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace('"', '\\"')
        )

    @classmethod
    def _format_labels(
        cls,
        labels: tuple[tuple[str, str], ...],
    ) -> str:
        if not labels:
            return ""

        rendered = ",".join(
            f'{name}="{cls._escape_label_value(value)}"'
            for name, value in labels
        )

        return f"{{{rendered}}}"

    def _register_metadata(
        self,
        name: str,
        help_text: str,
        metric_type: str,
    ) -> None:
        existing = self._metadata.get(name)

        if existing is None:
            self._metadata[name] = (
                help_text,
                metric_type,
            )
            return

        if existing != (help_text, metric_type):
            raise ValueError(
                f"metric {name!r} was registered "
                "with conflicting metadata"
            )

    def inc_counter(
        self,
        name: str,
        value: float = 1.0,
        *,
        help_text: str = "",
        labels: dict[str, str] | None = None,
    ) -> None:
        if value < 0:
            raise ValueError(
                "counter increments must be non-negative"
            )

        self._validate_name(name)

        normalized_labels = self._normalize_labels(labels)
        key = (name, normalized_labels)

        with self._lock:
            self._register_metadata(
                name,
                help_text,
                "counter",
            )

            current = self._counters.get(key)

            if current is None:
                self._counters[key] = MetricSample(
                    name=name,
                    help_text=help_text,
                    metric_type="counter",
                    labels=normalized_labels,
                    value=float(value),
                )
                return

            self._counters[key] = MetricSample(
                name=current.name,
                help_text=current.help_text,
                metric_type=current.metric_type,
                labels=current.labels,
                value=current.value + float(value),
            )

    def set_gauge(
        self,
        name: str,
        value: float,
        *,
        help_text: str = "",
        labels: dict[str, str] | None = None,
    ) -> None:
        self._validate_name(name)

        normalized_labels = self._normalize_labels(labels)
        key = (name, normalized_labels)

        with self._lock:
            self._register_metadata(
                name,
                help_text,
                "gauge",
            )

            self._gauges[key] = MetricSample(
                name=name,
                help_text=help_text,
                metric_type="gauge",
                labels=normalized_labels,
                value=float(value),
            )

    def observe(
        self,
        name: str,
        value: float,
        *,
        help_text: str = "",
        labels: dict[str, str] | None = None,
        buckets: Iterable[float] | None = None,
    ) -> None:
        self._validate_name(name)

        normalized_labels = self._normalize_labels(labels)
        key = (name, normalized_labels)

        configured_buckets = tuple(
            sorted(
                float(bucket)
                for bucket in (
                    buckets
                    if buckets is not None
                    else _DEFAULT_HISTOGRAM_BUCKETS
                )
            )
        )

        if not configured_buckets:
            raise ValueError(
                "histogram requires at least one bucket"
            )

        if any(
            bucket < 0
            for bucket in configured_buckets
        ):
            raise ValueError(
                "histogram buckets must be non-negative"
            )

        with self._lock:
            self._register_metadata(
                name,
                help_text,
                "histogram",
            )

            state = self._histograms.get(key)

            if state is None:
                state = _HistogramState(
                    buckets=configured_buckets,
                    counts=[0] * len(configured_buckets),
                )
                self._histograms[key] = state

            elif state.buckets != configured_buckets:
                raise ValueError(
                    f"histogram {name!r} uses "
                    "conflicting bucket definitions"
                )

            for index, upper_bound in enumerate(
                state.buckets
            ):
                if value <= upper_bound:
                    state.counts[index] += 1

            state.count += 1
            state.total += float(value)

    def snapshot(self) -> tuple[MetricSample, ...]:
        samples: list[MetricSample] = []

        with self._lock:
            samples.extend(self._counters.values())
            samples.extend(self._gauges.values())

            for (name, labels), state in self._histograms.items():
                help_text = self._metadata[name][0]

                for upper_bound, bucket_count in zip(
                    state.buckets,
                    state.counts,
                    strict=True,
                ):
                    samples.append(
                        MetricSample(
                            name=f"{name}_bucket",
                            help_text=help_text,
                            metric_type="histogram",
                            labels=(
                                *labels,
                                ("le", format(upper_bound, "g")),
                            ),
                            value=float(bucket_count),
                        )
                    )

                samples.append(
                    MetricSample(
                        name=f"{name}_bucket",
                        help_text=help_text,
                        metric_type="histogram",
                        labels=(
                            *labels,
                            ("le", "+Inf"),
                        ),
                        value=float(state.count),
                    )
                )

                samples.append(
                    MetricSample(
                        name=f"{name}_count",
                        help_text=help_text,
                        metric_type="histogram",
                        labels=labels,
                        value=float(state.count),
                    )
                )

                samples.append(
                    MetricSample(
                        name=f"{name}_sum",
                        help_text=help_text,
                        metric_type="histogram",
                        labels=labels,
                        value=float(state.total),
                    )
                )

        return tuple(samples)

    def render(self) -> str:
        lines: list[str] = []
        metadata_seen: set[tuple[str, str]] = set()

        for sample in self.snapshot():
            root_name = (
                sample.name
                .removesuffix("_bucket")
                .removesuffix("_count")
                .removesuffix("_sum")
            )

            metadata = (
                root_name,
                sample.metric_type,
            )

            if metadata not in metadata_seen:
                help_text = sample.help_text or root_name

                lines.append(
                    f"# HELP {root_name} {help_text}"
                )

                lines.append(
                    f"# TYPE {root_name} {sample.metric_type}"
                )

                metadata_seen.add(metadata)

            labels = self._format_labels(
                sample.labels
            )

            lines.append(
                f"{sample.name}{labels} "
                f"{sample.value:g}"
            )

        return (
            "\n".join(lines)
            + ("\n" if lines else "")
        )


class Timer:
    """Context manager for recording elapsed time in seconds."""

    def __init__(
        self,
        registry: MetricsRegistry,
        name: str,
        *,
        help_text: str,
        labels: dict[str, str] | None = None,
    ) -> None:
        self.registry = registry
        self.name = name
        self.help_text = help_text
        self.labels = labels
        self._started: float | None = None

    def __enter__(self) -> Timer:
        self._started = monotonic()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        if self._started is None:
            return

        elapsed = monotonic() - self._started

        self.registry.observe(
            self.name,
            elapsed,
            help_text=self.help_text,
            labels=self.labels,
        )


REGISTRY = MetricsRegistry()