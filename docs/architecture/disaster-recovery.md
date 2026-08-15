# Disaster Recovery

## 1. Objective

Provide a documented recovery strategy for critical SIEM data, configuration, rules, and services.

## 2. Critical Assets

- PostgreSQL control-plane data
- OpenSearch security-event data
- Redis state where operationally necessary
- Detection rules
- Correlation rules
- Configuration
- Plugin artifacts
- Audit data
- Deployment definitions

## 3. Backup Strategy

The production deployment must define:

- PostgreSQL backup frequency
- OpenSearch snapshot/retention strategy
- Configuration backup
- Rule backup
- Plugin artifact backup
- Backup encryption and access controls
- Backup retention

Exact operational values are deployment-specific and must be established before production use.

## 4. Restore Strategy

Recovery should be performed in dependency order:

```text
Infrastructure
    ↓
Configuration / Secrets
    ↓
PostgreSQL
    ↓
OpenSearch
    ↓
Redis
    ↓
Application / Workers
    ↓
Collectors / Plugins
    ↓
Validation
```

## 5. RPO

Recovery Point Objective must be selected according to deployment tier, event criticality, retention, and backup frequency.

## 6. RTO

Recovery Time Objective must be selected according to deployment tier and acceptable service interruption.

## 7. Recovery Verification

A backup is not considered reliable until restoration is periodically tested and verified.

## 8. Failure Scenarios

The recovery plan should cover:

- database loss
- search cluster loss
- Redis loss
- worker loss
- configuration loss
- rule loss
- plugin artifact loss
- host/container loss
- deployment environment loss

## 9. Security

Backups must receive access control, encryption where appropriate, retention controls, and auditability. Backup credentials must never be committed to source control.

## 10. Limitation

This document defines the architecture and requirements only. Actual backup/restore implementation and recovery testing belong to later delivery phases.
