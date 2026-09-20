"""
SentinelSIEM API v1 Router
==========================

Versioned HTTP API composition layer for SentinelSIEM.

API Version Boundary
--------------------

    /api/v1

Responsibilities
----------------

This module is responsible only for:

    - composing versioned API routers
    - maintaining the /api/v1 boundary
    - registering feature-specific routers
    - preserving feature-router ownership

This module MUST NOT implement:

    - authentication logic
    - authorization logic
    - database access
    - persistence logic
    - business logic
    - audit filtering
    - audit serialization
    - user-management logic
    - security policy


Architecture
------------

    /api/v1
        |
        +-- health
        +-- system
        +-- auth
        +-- events
        +-- alerts
        +-- incidents
        +-- iocs
        +-- detections
        +-- mitre
        +-- assets
        +-- users
        +-- audit


Audit Architecture
------------------

SentinelSIEM has two logically separate audit views.

Individual User Audit:

    /api/v1/users/{user_id}/audit

Owned by:

    app.api.routes.users

Global Audit:

    /api/v1/audit
    /api/v1/audit/{audit_id}
    /api/v1/audit/{audit_id}/related
    /api/v1/audit/export

Owned by:

    app.audit.routes

IMPORTANT
---------

Global Audit MUST NOT be imported from:

    app.api.routes.audit

The canonical Global Audit router is:

    app.audit.routes.router

Therefore:

    app.audit.routes
        |
        +--> Canonical Global Audit

while:

    app.api.routes.users
        |
        +--> User Management
        +--> Individual User Audit


MITRE ATT&CK Architecture
-------------------------

The MITRE router is registered here as a feature router.

This module does not implement MITRE business logic.

The MITRE API is responsible for exposing the read-only MITRE
ATT&CK knowledge domain and SentinelSIEM MITRE intelligence
endpoints according to the feature-level authorization rules.

Authoritative MITRE knowledge flow:

    enterprise-attack.json
            |
            v
        MITRE Importer
            |
            v
        PostgreSQL
            |
            v
      MitreRepository
            |
            v
       MitreService
            |
            v
        MITRE Router
            |
            v
       /api/v1/mitre/...

The MITRE knowledge UI is read-only.

There are no MITRE knowledge POST/PATCH/DELETE operations in
this composition layer.

SentinelSIEM Detection -> MITRE mappings remain a separate
operational concern and must not be confused with MITRE ATT&CK
knowledge ownership.


Security
--------

Security enforcement remains inside the feature routers.

This module does not:

    - add permission dependencies
    - bypass permission dependencies
    - authenticate users
    - authorize users

Router registration must never weaken feature-level authorization.


Transaction / Persistence Boundary
----------------------------------

No database session is created here.

No database transaction is created here.

No repository is accessed here.

Feature routers and their services own those responsibilities.


Router Ownership
----------------

    app.api.versioning.v1
        |
        +-- health_router
        +-- system_router
        +-- auth_router
        +-- events_router
        +-- alerts_router
        +-- incidents_router
        +-- iocs_router
        +-- detections_router
        +-- mitre_router
        +-- assets_router
        +-- users_router
        +-- audit_router

This module is the single registration point for these versioned
feature routers.

Individual feature routers must not be registered a second time
through app.api.router or app.main.


Public API
----------

This module exports:

    router
"""

from __future__ import annotations

from fastapi import APIRouter


# ============================================================================
# Platform / Health Routers
# ============================================================================

from app.api.routes.health import router as health_router
from app.api.routes.system import router as system_router


# ============================================================================
# Authentication Router
# ============================================================================

from app.api.routes.auth import router as auth_router


# ============================================================================
# Security Data Routers
# ============================================================================

from app.api.routes.events import router as events_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.iocs import router as iocs_router
from app.api.routes.detections import router as detections_router


# ============================================================================
# MITRE ATT&CK Router
# ============================================================================
#
# MITRE is registered exactly once through the versioned API boundary.
#
# This router owns the HTTP representation of:
#
#     /api/v1/mitre/...
#
# Feature-level authorization remains inside app.api.routes.mitre.
#
# ============================================================================

from app.api.routes.mitre import router as mitre_router


# ============================================================================
# Asset Management Router
# ============================================================================

from app.api.routes.assets import router as assets_router


# ============================================================================
# User Management Router
# ============================================================================

from app.api.routes.users import router as users_router


# ============================================================================
# Canonical Global Audit Router
# ============================================================================
#
# IMPORTANT:
#
# DO NOT import:
#
#     from app.api.routes.audit import router
#
# The canonical Global Audit router lives in:
#
#     backend/app/audit/routes.py
#
# Individual User Audit remains owned by:
#
#     app.api.routes.users
#
# Global Audit remains owned by:
#
#     app.audit.routes
#
# Global Audit endpoints:
#
#     GET /api/v1/audit
#     GET /api/v1/audit/export
#     GET /api/v1/audit/{audit_id}/related
#     GET /api/v1/audit/{audit_id}
#
# ============================================================================

from app.audit.routes import router as audit_router


# ============================================================================
# API v1 Router
# ============================================================================

router = APIRouter(
    prefix="/api/v1",
)


# ============================================================================
# Platform / Health
# ============================================================================

router.include_router(
    health_router,
)

router.include_router(
    system_router,
)


# ============================================================================
# Authentication
# ============================================================================

router.include_router(
    auth_router,
)


# ============================================================================
# Security Data APIs
# ============================================================================

router.include_router(
    events_router,
)

router.include_router(
    alerts_router,
)

router.include_router(
    incidents_router,
)

router.include_router(
    iocs_router,
)

router.include_router(
    detections_router,
)


# ============================================================================
# MITRE ATT&CK
# ============================================================================
#
# Canonical versioned boundary:
#
#     /api/v1/mitre/...
#
# The MITRE router is registered exactly once here.
#
# No individual MITRE endpoint is implemented in this module.
#
# No MITRE permission is added here.
#
# MITRE_READ authorization remains owned by the MITRE route/dependency
# layer.
#
# ============================================================================

router.include_router(
    mitre_router,
)


# ============================================================================
# Asset Management
# ============================================================================

router.include_router(
    assets_router,
)


# ============================================================================
# User Management
# ============================================================================
#
# This router owns:
#
#     /api/v1/users/...
#
# Including:
#
#     /api/v1/users/{user_id}/audit
#
# The Individual User Audit endpoint is intentionally kept inside
# the User Management router.
#
# ============================================================================

router.include_router(
    users_router,
)


# ============================================================================
# Global Audit
# ============================================================================
#
# Canonical router:
#
#     app.audit.routes.router
#
# Registered endpoints:
#
#     GET /api/v1/audit
#     GET /api/v1/audit/export
#     GET /api/v1/audit/{audit_id}/related
#     GET /api/v1/audit/{audit_id}
#
# Global Audit is intentionally registered separately from User Management.
#
# User Audit:
#
#     /api/v1/users/{user_id}/audit
#
# Global Audit:
#
#     /api/v1/audit
#
# Authorization remains owned by app.audit.routes.
#
# ============================================================================

router.include_router(
    audit_router,
)


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "router",
]