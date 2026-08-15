# Threat Model

## 1. Scope

This threat model covers the SIEM data plane, control plane, storage, plugins, external intelligence, users, deployment infrastructure, and network boundaries.

## 2. Assets

- Security events
- Alerts
- Incidents
- IOC and threat-intelligence data
- Detection and correlation rules
- User accounts
- Roles and permissions
- Audit records
- Secrets and credentials
- PostgreSQL data
- OpenSearch data
- Redis state
- Plugin code
- System configuration

## 3. Threat Actors

- External attacker
- Malicious or compromised log source
- Compromised endpoint
- Faulty or malicious plugin
- Unauthorized analyst
- Compromised administrator
- Malicious insider
- Compromised threat-intelligence provider
- Network attacker
- Software supply-chain attacker

## 4. Attack Surfaces

- Log receivers
- HTTP API
- WebSocket
- CLI
- Dashboard
- Plugins
- Detection rules
- Correlation rules
- External threat-intelligence feeds
- PostgreSQL
- OpenSearch
- Redis
- Containers and orchestration
- Configuration and dependencies

## 5. Threat Register

| Threat | Impact | Primary Mitigations | Residual Risk |
|---|---|---|---|
| Malformed event flood | Availability | Input limits, backpressure, DLQ | Operational tuning required |
| Oversized event | Memory/resource exhaustion | Size limits, bounded buffers | Configuration dependent |
| Queue overload | Event delay/loss risk | Backpressure, monitoring, scaling | Capacity dependent |
| Malicious plugin | Code execution / integrity | Plugin contract, isolation, review, least privilege | Plugin trust remains important |
| API abuse | Data exposure / availability | Authentication, authorization, rate limiting, validation | Deployment dependent |
| Credential leakage | Account compromise | Secret handling, redaction, least privilege | Human/configuration risk |
| Storage compromise | Confidentiality/integrity | Network isolation, credentials, access control, encryption readiness | Infrastructure dependent |
| Retry storm | Availability | Bounded retries, backoff, idempotency | Dependency-specific |
| Search abuse | Resource exhaustion | Pagination, query limits, timeouts | Query design dependent |
| External TI compromise | Incorrect enrichment | Validation, provenance, confidence, expiration | Provider trust remains |
| Supply-chain compromise | Platform compromise | Dependency scanning, pinning strategy, image scanning | External dependency risk |

## 6. Security Assumptions

- Production infrastructure is administered securely.
- Secrets are supplied through secure deployment mechanisms.
- Network controls are configured according to deployment requirements.
- External intelligence is treated as untrusted input.
- Plugins are reviewed and sourced through controlled processes.

## 7. Residual Risk

Phase 01 establishes architectural mitigations. Implementation-specific risks must be re-evaluated in later phases as actual controls are implemented.
