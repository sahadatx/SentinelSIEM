# Phase 08 — Detection Plugin System

## Objective

Provide a detector plugin lifecycle without hard-coded detector imports
inside the core detection engine.

## Lifecycle

Create Plugin → Metadata → Contract Validation → Auto Discovery →
Registry → Initialization → Enable / Configure → Execute

## Components

- `DetectorPlugin`: plugin contract.
- `DetectorMetadata`: plugin identity and capability metadata.
- `DetectorPluginDiscovery`: filesystem discovery.
- `DetectorPluginRegistry`: registration and enabled state.
- `DetectorPluginManager`: lifecycle orchestration.
- `DetectionEngine`: executes enabled plugins after Phase 07 rules.

## Plugin contract

Each plugin must:

1. subclass `DetectorPlugin`;
2. provide valid `DetectorMetadata`;
3. expose `create_plugin()`;
4. implement `initialize()`;
5. implement `detect()`.

## Security boundaries

- Discovery is restricted to the configured detector root.
- Plugin factories must return `DetectorPlugin`.
- Duplicate plugin IDs are rejected.
- Plugin enablement is registry-controlled.
- Configuration is passed explicitly during initialization.
- Plugins do not receive direct database clients.
- Plugin execution is limited to one event at a time.

## Phase boundary

Phase 08 intentionally does not implement correlation, multi-event
thresholds, time windows, correlation state, risk scoring, alert lifecycle,
incident management, threat intelligence, or MITRE mapping.
