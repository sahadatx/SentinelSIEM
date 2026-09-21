-- ============================================================================
-- SentinelSIEM
-- Migration: 006_assets.sql
-- Phase: Asset Management
--
-- Purpose:
--   Introduce the authoritative asset inventory for SentinelSIEM.
--
-- Design:
--   - Assets are first-class SIEM entities.
--   - Asset identity is independent from authentication users.
--   - Lifecycle status and operational status are separate concepts.
--   - Asset risk is stored explicitly.
--   - Network identity includes IP and MAC address.
--   - Ownership and location are stored structurally.
--   - Tags are stored as a JSON array.
--   - Extensible metadata remains available as a JSON object.
--   - RBAC remains controlled by the existing permissions:
--       assets:read
--       assets:manage
--   - No authentication tables are modified.
--   - No asset deletion is provided by this module.
-- ============================================================================

BEGIN;


-- ============================================================================
-- ASSETS
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_assets (

    -- ------------------------------------------------------------------------
    -- Stable asset identity
    -- ------------------------------------------------------------------------

    asset_id UUID PRIMARY KEY,


    -- ------------------------------------------------------------------------
    -- Human-readable identity
    -- ------------------------------------------------------------------------

    name VARCHAR(255) NOT NULL,

    hostname VARCHAR(255),

    ip_address INET,

    mac_address VARCHAR(17),


    -- ------------------------------------------------------------------------
    -- Classification
    -- ------------------------------------------------------------------------

    asset_type VARCHAR(64) NOT NULL,

    operating_system VARCHAR(128),

    environment VARCHAR(64),


    -- ------------------------------------------------------------------------
    -- Security risk
    -- ------------------------------------------------------------------------

    risk VARCHAR(32) NOT NULL DEFAULT 'INFORMATIONAL',


    -- ------------------------------------------------------------------------
    -- Lifecycle status
    --
    -- ENABLED / DISABLED
    --
    -- This is intentionally separate from operational_status.
    -- ------------------------------------------------------------------------

    lifecycle_status VARCHAR(32) NOT NULL DEFAULT 'ENABLED',


    -- ------------------------------------------------------------------------
    -- Operational status
    --
    -- ONLINE / OFFLINE / UNKNOWN / MAINTENANCE
    -- ------------------------------------------------------------------------

    operational_status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',


    -- ------------------------------------------------------------------------
    -- Ownership / physical or logical location
    -- ------------------------------------------------------------------------

    owner VARCHAR(255),

    location VARCHAR(255),


    -- ------------------------------------------------------------------------
    -- Tags
    --
    -- Must always be a JSON array.
    -- ------------------------------------------------------------------------

    tags JSONB NOT NULL DEFAULT '[]'::jsonb,


    -- ------------------------------------------------------------------------
    -- Free-form description
    -- ------------------------------------------------------------------------

    description TEXT,


    -- ------------------------------------------------------------------------
    -- Extensible structured metadata
    --
    -- Must always be a JSON object.
    -- ------------------------------------------------------------------------

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,


    -- ------------------------------------------------------------------------
    -- Asset discovery timestamps
    -- ------------------------------------------------------------------------

    first_seen TIMESTAMPTZ,

    last_seen TIMESTAMPTZ,


    -- ------------------------------------------------------------------------
    -- Audit timestamps
    -- ------------------------------------------------------------------------

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),


    -- ========================================================================
    -- REQUIRED FIELD VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_name_not_empty
        CHECK (length(trim(name)) > 0),

    CONSTRAINT ck_siem_assets_asset_type_not_empty
        CHECK (length(trim(asset_type)) > 0),


    -- ========================================================================
    -- RISK VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_risk_valid
        CHECK (
            risk IN (
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW',
                'INFORMATIONAL'
            )
        ),


    -- ========================================================================
    -- LIFECYCLE STATUS VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_lifecycle_status_valid
        CHECK (
            lifecycle_status IN (
                'ENABLED',
                'DISABLED'
            )
        ),


    -- ========================================================================
    -- OPERATIONAL STATUS VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_operational_status_valid
        CHECK (
            operational_status IN (
                'ONLINE',
                'OFFLINE',
                'UNKNOWN',
                'MAINTENANCE'
            )
        ),


    -- ========================================================================
    -- OPTIONAL STRING VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_hostname_not_empty
        CHECK (
            hostname IS NULL
            OR length(trim(hostname)) > 0
        ),

    CONSTRAINT ck_siem_assets_mac_address_not_empty
        CHECK (
            mac_address IS NULL
            OR length(trim(mac_address)) > 0
        ),

    CONSTRAINT ck_siem_assets_environment_not_empty
        CHECK (
            environment IS NULL
            OR length(trim(environment)) > 0
        ),

    CONSTRAINT ck_siem_assets_owner_not_empty
        CHECK (
            owner IS NULL
            OR length(trim(owner)) > 0
        ),

    CONSTRAINT ck_siem_assets_location_not_empty
        CHECK (
            location IS NULL
            OR length(trim(location)) > 0
        ),


    -- ========================================================================
    -- MAC ADDRESS VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_mac_address_format
        CHECK (
            mac_address IS NULL
            OR mac_address ~* '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'
        ),


    -- ========================================================================
    -- TAG VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_tags_array
        CHECK (
            jsonb_typeof(tags) = 'array'
        ),


    -- ========================================================================
    -- METADATA VALIDATION
    -- ========================================================================

    CONSTRAINT ck_siem_assets_metadata_object
        CHECK (
            jsonb_typeof(metadata) = 'object'
        )

);


-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS ix_siem_assets_name
    ON siem_assets(name);

CREATE INDEX IF NOT EXISTS ix_siem_assets_hostname
    ON siem_assets(hostname);

CREATE INDEX IF NOT EXISTS ix_siem_assets_ip_address
    ON siem_assets(ip_address);

CREATE INDEX IF NOT EXISTS ix_siem_assets_mac_address
    ON siem_assets(mac_address);

CREATE INDEX IF NOT EXISTS ix_siem_assets_asset_type
    ON siem_assets(asset_type);

CREATE INDEX IF NOT EXISTS ix_siem_assets_operating_system
    ON siem_assets(operating_system);

CREATE INDEX IF NOT EXISTS ix_siem_assets_environment
    ON siem_assets(environment);

CREATE INDEX IF NOT EXISTS ix_siem_assets_risk
    ON siem_assets(risk);

CREATE INDEX IF NOT EXISTS ix_siem_assets_lifecycle_status
    ON siem_assets(lifecycle_status);

CREATE INDEX IF NOT EXISTS ix_siem_assets_operational_status
    ON siem_assets(operational_status);

CREATE INDEX IF NOT EXISTS ix_siem_assets_owner
    ON siem_assets(owner);

CREATE INDEX IF NOT EXISTS ix_siem_assets_location
    ON siem_assets(location);

CREATE INDEX IF NOT EXISTS ix_siem_assets_first_seen
    ON siem_assets(first_seen DESC);

CREATE INDEX IF NOT EXISTS ix_siem_assets_last_seen
    ON siem_assets(last_seen DESC);

CREATE INDEX IF NOT EXISTS ix_siem_assets_created_at
    ON siem_assets(created_at DESC);

CREATE INDEX IF NOT EXISTS ix_siem_assets_updated_at
    ON siem_assets(updated_at DESC);


-- ============================================================================
-- COMPLETE
-- ============================================================================

COMMIT;