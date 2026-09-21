-- ============================================================================
-- SentinelSIEM
-- Migration: 007_assets_schema_upgrade.sql
-- Phase: Asset Management
--
-- Purpose:
--   Upgrade the existing legacy siem_assets table to the
--   authoritative Asset Management schema.
--
-- Important:
--   This migration preserves existing asset records.
--   No asset table is dropped.
-- ============================================================================

BEGIN;


-- ============================================================================
-- ADD NEW COLUMNS
-- ============================================================================

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS mac_address VARCHAR(17);

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS risk VARCHAR(32);

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR(32);

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS operational_status VARCHAR(32);

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS location VARCHAR(255);

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS tags JSONB;

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ;

ALTER TABLE siem_assets
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;


-- ============================================================================
-- MIGRATE LEGACY STATUS
--
-- Legacy:
--   active
--   inactive
--   maintenance
--
-- New lifecycle:
--   ENABLED
--   DISABLED
--
-- New operational:
--   ONLINE
--   OFFLINE
--   UNKNOWN
--   MAINTENANCE
-- ============================================================================

UPDATE siem_assets
SET lifecycle_status =
    CASE
        WHEN lower(status) = 'inactive'
            THEN 'DISABLED'
        ELSE 'ENABLED'
    END
WHERE lifecycle_status IS NULL;


UPDATE siem_assets
SET operational_status =
    CASE
        WHEN lower(status) = 'maintenance'
            THEN 'MAINTENANCE'

        WHEN lower(status) = 'active'
            THEN 'UNKNOWN'

        WHEN lower(status) = 'inactive'
            THEN 'UNKNOWN'

        ELSE 'UNKNOWN'
    END
WHERE operational_status IS NULL;


-- ============================================================================
-- DEFAULT VALUES
-- ============================================================================

UPDATE siem_assets
SET risk = 'INFORMATIONAL'
WHERE risk IS NULL;


UPDATE siem_assets
SET tags = '[]'::jsonb
WHERE tags IS NULL;


-- ============================================================================
-- NORMALIZE INVALID / NULL VALUES
-- ============================================================================

UPDATE siem_assets
SET lifecycle_status = 'ENABLED'
WHERE lifecycle_status IS NULL;


UPDATE siem_assets
SET operational_status = 'UNKNOWN'
WHERE operational_status IS NULL;


-- ============================================================================
-- MAKE NEW REQUIRED COLUMNS NON-NULL
-- ============================================================================

ALTER TABLE siem_assets
    ALTER COLUMN risk SET DEFAULT 'INFORMATIONAL';

ALTER TABLE siem_assets
    ALTER COLUMN risk SET NOT NULL;


ALTER TABLE siem_assets
    ALTER COLUMN lifecycle_status SET DEFAULT 'ENABLED';

ALTER TABLE siem_assets
    ALTER COLUMN lifecycle_status SET NOT NULL;


ALTER TABLE siem_assets
    ALTER COLUMN operational_status SET DEFAULT 'UNKNOWN';

ALTER TABLE siem_assets
    ALTER COLUMN operational_status SET NOT NULL;


ALTER TABLE siem_assets
    ALTER COLUMN tags SET DEFAULT '[]'::jsonb;

ALTER TABLE siem_assets
    ALTER COLUMN tags SET NOT NULL;


-- ============================================================================
-- REMOVE LEGACY STATUS CONSTRAINTS
-- ============================================================================

ALTER TABLE siem_assets
    DROP CONSTRAINT IF EXISTS ck_siem_assets_status_valid;

ALTER TABLE siem_assets
    DROP CONSTRAINT IF EXISTS ck_siem_assets_status_not_empty;


-- ============================================================================
-- NEW CHECK CONSTRAINTS
-- ============================================================================

ALTER TABLE siem_assets
    DROP CONSTRAINT IF EXISTS ck_siem_assets_risk_valid;

ALTER TABLE siem_assets
    ADD CONSTRAINT ck_siem_assets_risk_valid
    CHECK (
        risk IN (
            'CRITICAL',
            'HIGH',
            'MEDIUM',
            'LOW',
            'INFORMATIONAL'
        )
    );


ALTER TABLE siem_assets
    DROP CONSTRAINT IF EXISTS ck_siem_assets_lifecycle_status_valid;

ALTER TABLE siem_assets
    ADD CONSTRAINT ck_siem_assets_lifecycle_status_valid
    CHECK (
        lifecycle_status IN (
            'ENABLED',
            'DISABLED'
        )
    );


ALTER TABLE siem_assets
    DROP CONSTRAINT IF EXISTS ck_siem_assets_operational_status_valid;

ALTER TABLE siem_assets
    ADD CONSTRAINT ck_siem_assets_operational_status_valid
    CHECK (
        operational_status IN (
            'ONLINE',
            'OFFLINE',
            'UNKNOWN',
            'MAINTENANCE'
        )
    );


ALTER TABLE siem_assets
    DROP CONSTRAINT IF EXISTS ck_siem_assets_tags_array;

ALTER TABLE siem_assets
    ADD CONSTRAINT ck_siem_assets_tags_array
    CHECK (
        jsonb_typeof(tags) = 'array'
    );


ALTER TABLE siem_assets
    DROP CONSTRAINT IF EXISTS ck_siem_assets_mac_address_format;

ALTER TABLE siem_assets
    ADD CONSTRAINT ck_siem_assets_mac_address_format
    CHECK (
        mac_address IS NULL
        OR mac_address ~* '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'
    );


-- ============================================================================
-- NEW INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS ix_siem_assets_mac_address
    ON siem_assets(mac_address);

CREATE INDEX IF NOT EXISTS ix_siem_assets_operating_system
    ON siem_assets(operating_system);

CREATE INDEX IF NOT EXISTS ix_siem_assets_risk
    ON siem_assets(risk);

CREATE INDEX IF NOT EXISTS ix_siem_assets_lifecycle_status
    ON siem_assets(lifecycle_status);

CREATE INDEX IF NOT EXISTS ix_siem_assets_operational_status
    ON siem_assets(operational_status);

CREATE INDEX IF NOT EXISTS ix_siem_assets_location
    ON siem_assets(location);

CREATE INDEX IF NOT EXISTS ix_siem_assets_first_seen
    ON siem_assets(first_seen DESC);

CREATE INDEX IF NOT EXISTS ix_siem_assets_last_seen
    ON siem_assets(last_seen DESC);


-- ============================================================================
-- COMPLETE
-- ============================================================================

COMMIT;
