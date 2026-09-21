-- ============================================================================
-- SentinelSIEM
-- Migration: 005_cleanup_duplicate_auth_audit_index.sql
-- Phase: Authentication / Database Cleanup
--
-- Purpose:
--   Remove the legacy duplicate actor index from siem_auth_audit.
--
-- Design:
--   - Keep ix_siem_auth_audit_actor_created as the canonical actor-history
--     index introduced by migration 004.
--   - Do not modify or delete audit records.
--   - Do not change audit action names.
--   - Do not modify authentication behavior.
-- ============================================================================

BEGIN;

-- ============================================================================
-- DUPLICATE ACTOR AUDIT INDEX
-- ============================================================================
--
-- Legacy index:
--   ix_siem_auth_audit_actor
--   (actor_user_id, created_at DESC)
--
-- Canonical index:
--   ix_siem_auth_audit_actor_created
--   (actor_user_id, created_at DESC)
--
-- Both indexes provide the same access path. Keep the canonical 004 index
-- and remove only the redundant legacy index.

DROP INDEX IF EXISTS ix_siem_auth_audit_actor;

-- ============================================================================
-- COMPLETE
-- ============================================================================

COMMIT;
