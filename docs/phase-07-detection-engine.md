# Phase 07 — Detection Engine

## Objective

Implement a rule-driven, externalized detection engine that evaluates one canonical/enriched security event at a time and emits deterministic detection results.

## Scope

- Detection rule schema and semantic validation
- External YAML rule loading
- In-memory rule registry
- Single-event rule evaluation
- Detection result model
- Lightweight duplicate-match suppression
- Unit tests

## Architecture

```text
Canonical / Enriched Event
        |
        v
DetectionEngine
        |
        +--> DetectionRuleRegistry
        |
        +--> DetectionEvaluator
        |
        +--> DetectionSuppression
        |
        v
DetectionResult
```

Phase 07 deliberately does not implement multi-event correlation, persistent alert lifecycle, detector plugins, risk scoring, API routes, or dashboard functionality. Those belong to later roadmap phases.

## Rule format

Rules live under `rules/detection/*.yaml` and are validated before registration. The initial rules are intentionally event-level indicators. Thresholds, sequences, windows, and multi-event attack patterns belong to Phase 09 correlation.

## Validation

Run:

```bash
ruff check backend/app/detection backend/tests/unit/detection
mypy backend/app/detection
pytest -v backend/tests/unit/detection
python -m compileall backend/app/detection backend/tests/unit/detection
```
