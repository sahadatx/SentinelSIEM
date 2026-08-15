# Phase 10 — Risk Scoring & Prioritization

## Objective

Calculate a configurable, explainable, testable and auditable risk score from detection/correlation evidence.

## Flow

Detection Result / Correlation Result
        ↓
Risk Input
        ↓
Risk Factors
        ↓
Weighted Risk Calculator
        ↓
Risk Score (0-100)
        ↓
Priority
        ↓
Risk Assessment

## Factors

- Severity
- Confidence
- Asset Criticality
- User Risk
- IOC Reputation
- Threat Intelligence
- Frequency
- Correlation Strength
- MITRE Technique
- Historical Context

## Design

Scores are normalized to 0-100 and calculated with deterministic weighted factors. The default factor weights are explicitly defined in `factors.py` and mirrored in `config/risk.yaml`.

The output includes the normalized factor values and an explanation so a downstream alert layer can audit why an item received its priority.

## Scope boundary

Phase 10 does not implement alert lifecycle, incident management, threat-intelligence ingestion, IOC management, or persistent risk history. Those belong to later phases.

## Security

- Strict Pydantic models reject unknown input fields.
- Factor values are bounded to 0..1.
- Score is bounded to 0..100.
- Unknown severity values use a conservative medium baseline.
- Calculation is deterministic and free of dynamic code execution.
