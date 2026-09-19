-- ============================================================================
-- SentinelSIEM
-- Migration: 003_finalize_rbac.sql
-- Phase: Final RBAC Matrix
--
-- FINAL RBAC CONTRACT
--
-- Roles:
--   ADMIN
--   SECURITY_ANALYST
--   SOC_ANALYST
--   INVESTIGATOR
--   VIEWER
--
-- Permission counts:
--   ADMIN              = 18
--   SECURITY_ANALYST   = 14
--   SOC_ANALYST        = 12
--   INVESTIGATOR       = 8
--   VIEWER             = 6
--
-- Total permissions:
--   18
--
-- Audit:
--   No dedicated audit permission exists.
--
--   Audit access is controlled through:
--
--       users:read
--
--   Only ADMIN receives users:read.
--
-- Therefore:
--
--   ADMIN              -> Audit access
--   SECURITY_ANALYST   -> No Audit access
--   SOC_ANALYST        -> No Audit access
--   INVESTIGATOR       -> No Audit access
--   VIEWER             -> No Audit access
--
-- This migration is the database representation of the centralized
-- application RBAC contract defined in:
--
--   backend/app/auth/permissions.py
--   backend/app/auth/roles.py
--
-- IMPORTANT:
--   Do not introduce audit:read or audit:export.
-- ============================================================================


BEGIN;


-- ============================================================================
-- 1. FINAL PERMISSION SET
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Remove obsolete dedicated audit permissions.
--
-- Audit is intentionally controlled through users:read.
-- ---------------------------------------------------------------------------

DELETE FROM siem_role_permissions
WHERE permission_name IN (
    'audit:read',
    'audit:export'
);


DELETE FROM siem_permissions
WHERE permission_name IN (
    'audit:read',
    'audit:export'
);


-- ---------------------------------------------------------------------------
-- Ensure the exact final permissions exist.
-- ---------------------------------------------------------------------------

INSERT INTO siem_permissions (permission_name)
VALUES
    ('events:read'),

    ('alerts:read'),
    ('alerts:manage'),

    ('incidents:read'),
    ('incidents:manage'),

    ('iocs:read'),
    ('iocs:manage'),

    ('mitre:read'),

    ('dashboard:read'),

    ('users:read'),
    ('users:manage'),

    ('roles:read'),
    ('roles:manage'),

    ('detections:read'),
    ('detections:manage'),

    ('assets:read'),
    ('assets:manage'),

    ('system:read')
ON CONFLICT (permission_name) DO NOTHING;


-- ============================================================================
-- 2. RESET FINAL ROLE MAPPINGS
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Remove all existing mappings for the five final application roles.
--
-- Permission definitions themselves remain intact.
-- ---------------------------------------------------------------------------

DELETE FROM siem_role_permissions
WHERE role_name IN (
    'ADMIN',
    'SECURITY_ANALYST',
    'SOC_ANALYST',
    'INVESTIGATOR',
    'VIEWER'
);


-- ============================================================================
-- 3. ADMIN
-- ============================================================================
--
-- Full SentinelSIEM platform administration.
--
-- Permissions: 18
--
-- Includes:
--   - security operations
--   - user management
--   - role management
--   - detection management
--   - asset management
--   - system access
--   - audit access through users:read
-- ============================================================================

INSERT INTO siem_role_permissions (
    role_name,
    permission_name
)
VALUES
    ('ADMIN', 'events:read'),

    ('ADMIN', 'alerts:read'),
    ('ADMIN', 'alerts:manage'),

    ('ADMIN', 'incidents:read'),
    ('ADMIN', 'incidents:manage'),

    ('ADMIN', 'iocs:read'),
    ('ADMIN', 'iocs:manage'),

    ('ADMIN', 'mitre:read'),

    ('ADMIN', 'dashboard:read'),

    ('ADMIN', 'users:read'),
    ('ADMIN', 'users:manage'),

    ('ADMIN', 'roles:read'),
    ('ADMIN', 'roles:manage'),

    ('ADMIN', 'detections:read'),
    ('ADMIN', 'detections:manage'),

    ('ADMIN', 'assets:read'),
    ('ADMIN', 'assets:manage'),

    ('ADMIN', 'system:read');


-- ============================================================================
-- 4. SECURITY_ANALYST
-- ============================================================================
--
-- Advanced security operations.
--
-- Permissions: 14
--
-- Can:
--   - read events
--   - read/manage alerts
--   - read/manage incidents
--   - read/manage IOCs
--   - read MITRE
--   - read dashboard
--   - read/manage detections
--   - read/manage assets
--   - read system information
--
-- Cannot:
--   - read/manage users
--   - read/manage roles
--   - access global audit logs
-- ============================================================================

INSERT INTO siem_role_permissions (
    role_name,
    permission_name
)
VALUES
    ('SECURITY_ANALYST', 'events:read'),

    ('SECURITY_ANALYST', 'alerts:read'),
    ('SECURITY_ANALYST', 'alerts:manage'),

    ('SECURITY_ANALYST', 'incidents:read'),
    ('SECURITY_ANALYST', 'incidents:manage'),

    ('SECURITY_ANALYST', 'iocs:read'),
    ('SECURITY_ANALYST', 'iocs:manage'),

    ('SECURITY_ANALYST', 'mitre:read'),

    ('SECURITY_ANALYST', 'dashboard:read'),

    ('SECURITY_ANALYST', 'detections:read'),
    ('SECURITY_ANALYST', 'detections:manage'),

    ('SECURITY_ANALYST', 'assets:read'),
    ('SECURITY_ANALYST', 'assets:manage'),

    ('SECURITY_ANALYST', 'system:read');


-- ============================================================================
-- 5. SOC_ANALYST
-- ============================================================================
--
-- SOC monitoring and response.
--
-- Permissions: 12
--
-- Can:
--   - read events
--   - read/manage alerts
--   - read/manage incidents
--   - read IOCs
--   - read MITRE
--   - read dashboard
--   - read/manage detections
--   - read assets
--   - read system information
--
-- Cannot:
--   - manage IOCs
--   - manage assets
--   - manage users
--   - manage roles
--   - access global audit logs
-- ============================================================================

INSERT INTO siem_role_permissions (
    role_name,
    permission_name
)
VALUES
    ('SOC_ANALYST', 'events:read'),

    ('SOC_ANALYST', 'alerts:read'),
    ('SOC_ANALYST', 'alerts:manage'),

    ('SOC_ANALYST', 'incidents:read'),
    ('SOC_ANALYST', 'incidents:manage'),

    ('SOC_ANALYST', 'iocs:read'),

    ('SOC_ANALYST', 'mitre:read'),

    ('SOC_ANALYST', 'dashboard:read'),

    ('SOC_ANALYST', 'detections:read'),
    ('SOC_ANALYST', 'detections:manage'),

    ('SOC_ANALYST', 'assets:read'),

    ('SOC_ANALYST', 'system:read');


-- ============================================================================
-- 6. INVESTIGATOR
-- ============================================================================
--
-- Investigation-focused access.
--
-- Permissions: 8
--
-- Can:
--   - read events
--   - read/manage incidents
--   - read/manage IOCs
--   - read MITRE
--   - read dashboard
--   - read assets
--
-- Cannot:
--   - access alerts
--   - access detection management
--   - access system management
--   - manage users
--   - manage roles
--   - access global audit logs
-- ============================================================================

INSERT INTO siem_role_permissions (
    role_name,
    permission_name
)
VALUES
    ('INVESTIGATOR', 'events:read'),

    ('INVESTIGATOR', 'incidents:read'),
    ('INVESTIGATOR', 'incidents:manage'),

    ('INVESTIGATOR', 'iocs:read'),
    ('INVESTIGATOR', 'iocs:manage'),

    ('INVESTIGATOR', 'mitre:read'),

    ('INVESTIGATOR', 'dashboard:read'),

    ('INVESTIGATOR', 'assets:read');


-- ============================================================================
-- 7. VIEWER
-- ============================================================================
--
-- Strict read-only operational visibility.
--
-- Permissions: 6
--
-- Can:
--   - read events
--   - read incidents
--   - read IOCs
--   - read MITRE
--   - read dashboard
--   - read assets
--
-- Cannot:
--   - access alerts
--   - manage any resource
--   - manage users
--   - manage roles
--   - access system administration
--   - access global audit logs
-- ============================================================================

INSERT INTO siem_role_permissions (
    role_name,
    permission_name
)
VALUES
    ('VIEWER', 'events:read'),
    ('VIEWER', 'incidents:read'),
    ('VIEWER', 'iocs:read'),
    ('VIEWER', 'mitre:read'),
    ('VIEWER', 'dashboard:read'),
    ('VIEWER', 'assets:read');


-- ============================================================================
-- 8. FINAL RBAC INTEGRITY CHECKS
-- ============================================================================
--
-- These checks intentionally fail the migration if the final contract
-- is violated.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- Verify exactly 18 final permissions exist.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    permission_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO permission_count
    FROM siem_permissions
    WHERE permission_name IN (
        'events:read',

        'alerts:read',
        'alerts:manage',

        'incidents:read',
        'incidents:manage',

        'iocs:read',
        'iocs:manage',

        'mitre:read',

        'dashboard:read',

        'users:read',
        'users:manage',

        'roles:read',
        'roles:manage',

        'detections:read',
        'detections:manage',

        'assets:read',
        'assets:manage',

        'system:read'
    );

    IF permission_count <> 18 THEN
        RAISE EXCEPTION
            'Final RBAC permission count mismatch: expected 18, found %',
            permission_count;
    END IF;
END
$$;


-- ---------------------------------------------------------------------------
-- Verify exactly 5 final roles exist.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    role_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO role_count
    FROM siem_roles
    WHERE role_name IN (
        'ADMIN',
        'SECURITY_ANALYST',
        'SOC_ANALYST',
        'INVESTIGATOR',
        'VIEWER'
    );

    IF role_count <> 5 THEN
        RAISE EXCEPTION
            'Final RBAC role count mismatch: expected 5, found %',
            role_count;
    END IF;
END
$$;


-- ---------------------------------------------------------------------------
-- Verify exact permission counts per role.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    admin_count INTEGER;
    security_analyst_count INTEGER;
    soc_analyst_count INTEGER;
    investigator_count INTEGER;
    viewer_count INTEGER;
BEGIN

    SELECT COUNT(*)
    INTO admin_count
    FROM siem_role_permissions
    WHERE role_name = 'ADMIN';


    SELECT COUNT(*)
    INTO security_analyst_count
    FROM siem_role_permissions
    WHERE role_name = 'SECURITY_ANALYST';


    SELECT COUNT(*)
    INTO soc_analyst_count
    FROM siem_role_permissions
    WHERE role_name = 'SOC_ANALYST';


    SELECT COUNT(*)
    INTO investigator_count
    FROM siem_role_permissions
    WHERE role_name = 'INVESTIGATOR';


    SELECT COUNT(*)
    INTO viewer_count
    FROM siem_role_permissions
    WHERE role_name = 'VIEWER';


    IF admin_count <> 18 THEN
        RAISE EXCEPTION
            'ADMIN permission count mismatch: expected 18, found %',
            admin_count;
    END IF;


    IF security_analyst_count <> 14 THEN
        RAISE EXCEPTION
            'SECURITY_ANALYST permission count mismatch: expected 14, found %',
            security_analyst_count;
    END IF;


    IF soc_analyst_count <> 12 THEN
        RAISE EXCEPTION
            'SOC_ANALYST permission count mismatch: expected 12, found %',
            soc_analyst_count;
    END IF;


    IF investigator_count <> 8 THEN
        RAISE EXCEPTION
            'INVESTIGATOR permission count mismatch: expected 8, found %',
            investigator_count;
    END IF;


    IF viewer_count <> 6 THEN
        RAISE EXCEPTION
            'VIEWER permission count mismatch: expected 6, found %',
            viewer_count;
    END IF;

END
$$;


-- ---------------------------------------------------------------------------
-- Verify dedicated audit permissions do not exist.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    audit_permission_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO audit_permission_count
    FROM siem_permissions
    WHERE permission_name IN (
        'audit:read',
        'audit:export'
    );

    IF audit_permission_count <> 0 THEN
        RAISE EXCEPTION
            'Dedicated audit permissions must not exist.';
    END IF;
END
$$;


-- ---------------------------------------------------------------------------
-- Verify only ADMIN has users:read.
--
-- users:read is the locked Audit access boundary.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    users_read_non_admin_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO users_read_non_admin_count
    FROM siem_role_permissions
    WHERE permission_name = 'users:read'
      AND role_name <> 'ADMIN';

    IF users_read_non_admin_count <> 0 THEN
        RAISE EXCEPTION
            'users:read must be granted to ADMIN only.';
    END IF;
END
$$;


-- ---------------------------------------------------------------------------
-- Verify ADMIN has users:read.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    admin_users_read_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO admin_users_read_count
    FROM siem_role_permissions
    WHERE role_name = 'ADMIN'
      AND permission_name = 'users:read';

    IF admin_users_read_count <> 1 THEN
        RAISE EXCEPTION
            'ADMIN must have users:read for Audit access.';
    END IF;
END
$$;


-- ============================================================================
-- 9. FINAL CONTRACT COMPLETE
-- ============================================================================

COMMIT;