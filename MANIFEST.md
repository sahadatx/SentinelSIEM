# Phase 17 Final Package Manifest

This ZIP is the final Phase 17 authentication/RBAC package.

## Core files

- `backend/app/auth/authentication.py` — login, token authentication, logout, session revocation
- `backend/app/auth/authorization.py` — centralized default-deny authorization and guards
- `backend/app/auth/password.py` — Argon2id hashing/verification
- `backend/app/auth/tokens.py` — strict JWT issuance/validation
- `backend/app/auth/sessions.py` — revocable session contract/reference adapter
- `backend/app/auth/permissions.py` — permission vocabulary
- `backend/app/auth/roles.py` — five least-privilege role definitions
- `backend/app/auth/policies.py` — default-deny policy
- `backend/app/auth/models.py` — identity, principal, session and audit models
- `backend/app/auth/audit.py` — audit sink contract/reference adapter
- `backend/app/storage/migrations/002_authentication.sql` — users, roles, permissions, mappings, sessions, audit + seed data

## Verification

`PYTHONPATH=backend pytest -q backend/tests/unit/auth backend/tests/security/test_phase17_security.py`

Result at packaging time: **13 passed**.

## Integration boundary

The package intentionally does not silently rewrite the existing Phase 15 route
files. The integration guide provides the exact centralized authentication and
permission boundary to wire into the existing API dependency container.
