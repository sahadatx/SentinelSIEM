"""
SentinelSIEM Top-Level API Router
=================================

Top-level composition layer for SentinelSIEM HTTP and WebSocket APIs.

Responsibilities
----------------

This module is responsible only for:

    - composing the versioned HTTP API
    - composing application WebSocket routes
    - maintaining the top-level API registration boundary
    - preserving API versioning boundaries
    - preventing duplicate feature-router registration


HTTP Architecture
-----------------

    FastAPI Application
          |
          v
    app.api.router
          |
          v
    app.api.versioning.v1
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


Current HTTP API Boundary
-------------------------

    /api/v1/...

The v1 router owns all versioned feature-router registration.

This module MUST NOT directly register individual feature routers.


Audit Architecture
------------------

Global Audit:

    /api/v1/audit
    /api/v1/audit/export
    /api/v1/audit/{audit_id}/related
    /api/v1/audit/{audit_id}

Canonical owner:

    app.audit.routes


Individual User Audit:

    /api/v1/users/{user_id}/audit

Canonical owner:

    app.api.routes.users


Important
---------

This module does NOT directly import or register:

    app.audit.routes
    app.api.routes.audit
    app.api.routes.users
    app.api.routes.auth
    app.api.routes.events
    app.api.routes.alerts
    ...

All HTTP feature registration MUST happen through:

    app.api.versioning.v1


MITRE Architecture
------------------

MITRE ATT&CK knowledge and SentinelSIEM Detection -> MITRE
mappings are separate application concerns.

The MITRE feature router is registered only by the v1
composition layer:

    app.api.versioning.v1
            |
            +-- app.api.routes.mitre

This module does not import the MITRE router directly.

The authoritative MITRE knowledge flow is:

    enterprise-attack.json
            |
            v
        MITRE importer
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
       MITRE API
            |
            v
      Read-only UI

Operational SentinelSIEM Detection -> MITRE mappings remain
a separate runtime concern and are not composed here.


WebSocket Architecture
----------------------

WebSocket routes are composed separately from versioned HTTP routes.

    FastAPI Application
          |
          v
    app.api.router
          |
          v
    app.api.websocket.events


Security
--------

Authentication and authorization are owned by individual route
modules.

This module does NOT:

    - authenticate requests
    - authorize users
    - create database sessions
    - access repositories
    - access services
    - perform business logic
    - perform audit persistence
    - validate feature requests
    - modify application state


Dependency Injection
--------------------

Application dependencies remain owned by the application and
feature layers.

This module only composes already-defined routers.


Duplicate Registration Policy
-----------------------------

Feature routers MUST NOT be registered both here and inside v1.

For example, this module must NOT contain:

    api_router.include_router(users_router)

or:

    api_router.include_router(audit_router)

or:

    api_router.include_router(mitre_router)

because those routers are already registered by:

    app.api.versioning.v1


Canonical Composition
---------------------

    app.api.router
          |
          +--> v1_router
          |      |
          |      +--> users_router
          |      |      |
          |      |      +--> /api/v1/users/...
          |      |      +--> /api/v1/users/{user_id}/audit
          |      |
          |      +--> audit_router
          |      |      |
          |      |      +--> /api/v1/audit
          |      |      +--> /api/v1/audit/export
          |      |      +--> /api/v1/audit/{audit_id}/related
          |      |      +--> /api/v1/audit/{audit_id}
          |      |
          |      +--> mitre_router
          |             |
          |             +--> /api/v1/mitre/...
          |
          +--> websocket_router


Testing
-------

Keeping this module composition-only allows deterministic tests for:

    - router imports
    - API version registration
    - feature registration
    - duplicate registration
    - WebSocket registration
    - final route paths


Public API
----------

This module exports:

    api_router
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.versioning.v1 import router as v1_router
from app.api.websocket.events import router as websocket_router


# ============================================================================
# Main API Router
# ============================================================================

api_router = APIRouter(
    tags=["API"],
)


# ============================================================================
# Versioned HTTP API
# ============================================================================
#
# All HTTP feature routes are registered exclusively through v1_router.
#
# Current API boundary:
#
#     /api/v1/...
#
# This module intentionally does NOT import individual feature routers.
#
# Feature ownership remains inside:
#
#     app.api.versioning.v1
#
# This includes:
#
#     - Authentication
#     - Users
#     - Audit
#     - Assets
#     - Events
#     - Alerts
#     - Incidents
#     - IOCs
#     - Detections
#     - MITRE
#     - System
#     - Health-related versioned APIs
#
# ============================================================================

api_router.include_router(
    v1_router,
)


# ============================================================================
# WebSocket API
# ============================================================================
#
# WebSocket routes are application-level routes and intentionally remain
# outside the versioned HTTP API composition.
#
# The WebSocket router owns:
#
#     - WebSocket endpoint registration
#     - WebSocket authentication
#     - WebSocket authorization
#     - WebSocket lifecycle handling
#
# ============================================================================

api_router.include_router(
    websocket_router,
)


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "api_router",
]