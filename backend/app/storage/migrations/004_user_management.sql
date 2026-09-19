-- ============================================================================
-- SentinelSIEM
-- Migration: 004_user_management.sql
-- Phase: User Management
--
-- Purpose:
--   Extend the existing authentication user model for the finalized
--   Admin-controlled user-management lifecycle.
--
-- Design:
--   - Public signup is NOT introduced.
--   - User creation remains ADMIN-controlled.
--   - Existing RBAC tables remain unchanged.
--   - Existing authentication/session/audit tables remain authoritative.
--   - Existing audit history remains in siem_auth_audit.
--   - User activity is correlated through actor_user_id / target_user_id.
--
-- User-management capabilities supported by this migration:
--   - Display name
--   - Force password change
--   - Password changed timestamp
--   - Last login timestamp
--   - Per-user activity history indexes
-- ============================================================================

BEGIN;

-- ============================================================================
-- USER PROFILE
-- ============================================================================

ALTER TABLE siem_users
    ADD COLUMN IF NOT EXISTS display_name VARCHAR(150);


-- ============================================================================
-- PASSWORD LIFECYCLE
-- ============================================================================

ALTER TABLE siem_users
    ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN
        NOT NULL
        DEFAULT FALSE;

ALTER TABLE siem_users
    ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;


-- ============================================================================
-- AUTHENTICATION ACTIVITY
-- ============================================================================

ALTER TABLE siem_users
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;


-- ============================================================================
-- USER TABLE INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS ix_siem_users_display_name
    ON siem_users(display_name);

CREATE INDEX IF NOT EXISTS ix_siem_users_active
    ON siem_users(is_active);

CREATE INDEX IF NOT EXISTS ix_siem_users_locked
    ON siem_users(is_locked);

CREATE INDEX IF NOT EXISTS ix_siem_users_last_login
    ON siem_users(last_login_at DESC);


-- ============================================================================
-- AUDIT / ACTIVITY HISTORY INDEXES
--
-- Admin User Details flow:
--
--   Users
--      ↓
--   Username click
--      ↓
--   User Details
--      ↓
--   Full Activity / Audit History
--
-- target_user_id:
--   Activities performed ON the selected user.
--
-- actor_user_id:
--   Activities PERFORMED BY the selected user.
-- ============================================================================

CREATE INDEX IF NOT EXISTS ix_siem_auth_audit_target_created
    ON siem_auth_audit(
        target_user_id,
        created_at DESC
    );

CREATE INDEX IF NOT EXISTS ix_siem_auth_audit_actor_created
    ON siem_auth_audit(
        actor_user_id,
        created_at DESC
    );

CREATE INDEX IF NOT EXISTS ix_siem_auth_audit_action_created
    ON siem_auth_audit(
        action,
        created_at DESC
    );


-- ============================================================================
-- COMPLETE
-- ============================================================================

COMMIT;