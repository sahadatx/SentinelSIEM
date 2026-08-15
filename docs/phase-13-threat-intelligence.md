# Phase 13 — Threat Intelligence & IOC Management

## Scope

Phase 13 provides the IOC and threat-intelligence domain boundary required by the roadmap.

Supported IOC types:
- IPv4
- IPv6
- Domain
- URL
- Hash
- Email
- Hostname

## Lifecycle

IOC input -> normalization -> validation -> management -> matching -> enrichment

## IOC metadata

Each IOC carries:
- confidence
- source
- first seen
- last seen
- expiration
- feed
- reputation
- lifecycle status
- metadata

## Feed boundary

External feeds implement the `ThreatIntelFeed` protocol under
`backend/app/threat_intelligence/feeds/`. Feed transport, scheduling and
vendor-specific clients remain plugin concerns.

## Phase boundary

This phase does not implement:
- MITRE ATT&CK
- REST API / WebSocket
- dashboard
- authentication/RBAC
- production deployment

Those belong to later roadmap phases.
