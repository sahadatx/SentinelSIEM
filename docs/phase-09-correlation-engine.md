# Phase 09 — Correlation Engine

## Objective

Correlate multiple canonical/enriched security events inside bounded time windows to identify multi-event attack patterns.

## Flow

Canonical/Enriched Events -> Correlation Engine -> Rule Evaluation -> Correlation Result

## Supported capabilities

- Time-bounded windows
- Ordered sequences
- Thresholds
- Grouping keys
- In-memory correlation state
- Window expiration
- Evidence/event IDs
- Match consumption to prevent repeated emission from identical evidence
- Declarative external YAML rules
- Deterministic evaluation

## Scope boundary

Phase 09 does not implement:

- Risk scoring
- Alert lifecycle
- Incident management
- Threat intelligence
- MITRE mappings
- API/UI
- Production deployment
- Distributed persistent correlation state

Those belong to later phases.

## State model

Correlation state is currently process-local and intentionally bounded to the Phase 09 engine. Redis-backed/distributed state is a deployment/production concern and must not be introduced as an unscoped Phase 09 feature.

## Security considerations

- YAML is loaded with `yaml.safe_load`.
- Rules use strict Pydantic validation.
- Correlation windows are bounded to 24 hours.
- Group keys are explicit and deterministic.
- No regular-expression evaluation is used.
- Matched evidence is consumed to reduce duplicate correlation emissions.
