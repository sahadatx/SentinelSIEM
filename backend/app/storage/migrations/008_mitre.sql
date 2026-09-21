-- ============================================================================
-- SentinelSIEM
-- Migration 008: MITRE ATT&CK Knowledge Base
-- ============================================================================
--
-- Purpose:
--   Store the official MITRE ATT&CK knowledge imported from the Enterprise
--   ATT&CK STIX/JSON dataset.
--
-- Architecture:
--
--   enterprise-attack.json
--          │
--          ▼
--      MITRE Importer
--          │
--          ▼
--      PostgreSQL
--          │
--          ├── tactics
--          ├── techniques
--          ├── platforms
--          ├── relationships
--          └── references
--
-- Detection → MITRE mappings remain a SentinelSIEM application concern and
-- are intentionally NOT duplicated in this migration.
--
-- Migration is designed to be safe to run once through the SentinelSIEM
-- migration runner.
-- ============================================================================


-- ============================================================================
-- 1. MITRE TACTICS
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_tactics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    external_id VARCHAR(32) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_siem_mitre_tactics_external_id
        UNIQUE (external_id),

    CONSTRAINT chk_siem_mitre_tactics_external_id
        CHECK (external_id ~ '^TA[0-9]{4}$'),

    CONSTRAINT chk_siem_mitre_tactics_name
        CHECK (length(btrim(name)) > 0)
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_tactics_name
    ON siem_mitre_tactics (name);


-- ============================================================================
-- 2. MITRE PLATFORMS
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_platforms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    external_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_siem_mitre_platforms_external_id
        UNIQUE (external_id),

    CONSTRAINT chk_siem_mitre_platforms_external_id
        CHECK (length(btrim(external_id)) > 0),

    CONSTRAINT chk_siem_mitre_platforms_name
        CHECK (length(btrim(name)) > 0)
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_platforms_name
    ON siem_mitre_platforms (name);


-- ============================================================================
-- 3. MITRE TECHNIQUES
-- ============================================================================
--
-- Both top-level techniques and sub-techniques are represented here.
--
-- Examples:
--
--   T1059
--   T1059.001
--
-- type:
--   TECHNIQUE
--   SUB_TECHNIQUE
--
-- parent_id:
--   NULL for top-level techniques
--   References the parent technique for sub-techniques
--
-- This intentionally keeps the hierarchy in one authoritative table.
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_techniques (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    external_id VARCHAR(32) NOT NULL,
    name VARCHAR(255) NOT NULL,

    description TEXT NOT NULL DEFAULT '',

    type VARCHAR(32) NOT NULL,

    parent_id UUID NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_siem_mitre_techniques_external_id
        UNIQUE (external_id),

    CONSTRAINT chk_siem_mitre_techniques_external_id
        CHECK (
            external_id ~ '^T[0-9]{4}$'
            OR external_id ~ '^T[0-9]{4}\.[0-9]{3}$'
        ),

    CONSTRAINT chk_siem_mitre_techniques_name
        CHECK (length(btrim(name)) > 0),

    CONSTRAINT chk_siem_mitre_techniques_type
        CHECK (type IN ('TECHNIQUE', 'SUB_TECHNIQUE')),

    CONSTRAINT chk_siem_mitre_techniques_parent
        CHECK (
            (
                type = 'TECHNIQUE'
                AND parent_id IS NULL
            )
            OR
            (
                type = 'SUB_TECHNIQUE'
                AND parent_id IS NOT NULL
            )
        ),

    CONSTRAINT fk_siem_mitre_techniques_parent
        FOREIGN KEY (parent_id)
        REFERENCES siem_mitre_techniques (id)
        ON DELETE RESTRICT
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_techniques_name
    ON siem_mitre_techniques (name);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_techniques_type
    ON siem_mitre_techniques (type);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_techniques_parent
    ON siem_mitre_techniques (parent_id);


-- ============================================================================
-- 4. TECHNIQUE ↔ TACTIC
-- ============================================================================
--
-- A technique can belong to multiple tactics.
-- A tactic contains multiple techniques.
--
-- Example:
--
--   T1059 ──────── TA0002
--        └──────── TA0005
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_technique_tactics (
    technique_id UUID NOT NULL,
    tactic_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (technique_id, tactic_id),

    CONSTRAINT fk_siem_mitre_technique_tactics_technique
        FOREIGN KEY (technique_id)
        REFERENCES siem_mitre_techniques (id)
        ON DELETE CASCADE,

    CONSTRAINT fk_siem_mitre_technique_tactics_tactic
        FOREIGN KEY (tactic_id)
        REFERENCES siem_mitre_tactics (id)
        ON DELETE CASCADE
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_technique_tactics_tactic
    ON siem_mitre_technique_tactics (tactic_id);


-- ============================================================================
-- 5. TECHNIQUE ↔ PLATFORM
-- ============================================================================
--
-- A technique may apply to multiple platforms.
-- A platform may contain multiple techniques.
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_technique_platforms (
    technique_id UUID NOT NULL,
    platform_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (technique_id, platform_id),

    CONSTRAINT fk_siem_mitre_technique_platforms_technique
        FOREIGN KEY (technique_id)
        REFERENCES siem_mitre_techniques (id)
        ON DELETE CASCADE,

    CONSTRAINT fk_siem_mitre_technique_platforms_platform
        FOREIGN KEY (platform_id)
        REFERENCES siem_mitre_platforms (id)
        ON DELETE CASCADE
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_technique_platforms_platform
    ON siem_mitre_technique_platforms (platform_id);


-- ============================================================================
-- 6. MITRE REFERENCES
-- ============================================================================
--
-- References are kept separately because one ATT&CK object can have many
-- external references.
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_references (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    technique_id UUID NOT NULL,

    source_name VARCHAR(255) NOT NULL,

    url TEXT NULL,

    external_id VARCHAR(255) NULL,

    description TEXT NOT NULL DEFAULT '',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_siem_mitre_references_technique
        FOREIGN KEY (technique_id)
        REFERENCES siem_mitre_techniques (id)
        ON DELETE CASCADE,

    CONSTRAINT chk_siem_mitre_references_source_name
        CHECK (length(btrim(source_name)) > 0)
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_references_technique
    ON siem_mitre_references (technique_id);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_references_external_id
    ON siem_mitre_references (external_id);


-- ============================================================================
-- 7. GENERAL MITRE RELATIONSHIPS
-- ============================================================================
--
-- Stores ATT&CK relationships that do not fit the normalized tactic/platform
-- join tables.
--
-- Examples that can be represented here:
--
--   technique → sub-technique
--   technique → mitigation
--   technique → software
--   technique → group
--   technique → campaign
--
-- The importer may populate this table as supported by the dataset.
--
-- relationship_external_id is the STIX relationship object's ID and provides
-- idempotent import/upsert behavior.
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    relationship_external_id VARCHAR(255) NOT NULL,

    relationship_type VARCHAR(100) NOT NULL,

    source_external_id VARCHAR(255) NOT NULL,

    target_external_id VARCHAR(255) NOT NULL,

    description TEXT NOT NULL DEFAULT '',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_siem_mitre_relationships_external_id
        UNIQUE (relationship_external_id),

    CONSTRAINT chk_siem_mitre_relationships_type
        CHECK (length(btrim(relationship_type)) > 0),

    CONSTRAINT chk_siem_mitre_relationships_source
        CHECK (length(btrim(source_external_id)) > 0),

    CONSTRAINT chk_siem_mitre_relationships_target
        CHECK (length(btrim(target_external_id)) > 0)
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_relationships_source
    ON siem_mitre_relationships (source_external_id);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_relationships_target
    ON siem_mitre_relationships (target_external_id);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_relationships_type
    ON siem_mitre_relationships (relationship_type);


-- ============================================================================
-- 8. IMPORT METADATA
-- ============================================================================
--
-- Keeps track of the dataset currently imported into PostgreSQL.
--
-- This is deliberately separate from siem_schema_migrations:
--
--   siem_schema_migrations
--       = database schema version
--
--   siem_mitre_imports
--       = ATT&CK dataset/import version
--
-- This allows a new ATT&CK dataset to be imported without creating a new
-- database schema migration.
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_mitre_imports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    dataset_name VARCHAR(255) NOT NULL,

    dataset_version VARCHAR(100) NULL,

    source_path TEXT NULL,

    object_count INTEGER NOT NULL DEFAULT 0,

    tactic_count INTEGER NOT NULL DEFAULT 0,

    technique_count INTEGER NOT NULL DEFAULT 0,

    subtechnique_count INTEGER NOT NULL DEFAULT 0,

    platform_count INTEGER NOT NULL DEFAULT 0,

    relationship_count INTEGER NOT NULL DEFAULT 0,

    reference_count INTEGER NOT NULL DEFAULT 0,

    imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',

    error_message TEXT NULL,

    CONSTRAINT chk_siem_mitre_imports_object_count
        CHECK (object_count >= 0),

    CONSTRAINT chk_siem_mitre_imports_tactic_count
        CHECK (tactic_count >= 0),

    CONSTRAINT chk_siem_mitre_imports_technique_count
        CHECK (technique_count >= 0),

    CONSTRAINT chk_siem_mitre_imports_subtechnique_count
        CHECK (subtechnique_count >= 0),

    CONSTRAINT chk_siem_mitre_imports_platform_count
        CHECK (platform_count >= 0),

    CONSTRAINT chk_siem_mitre_imports_relationship_count
        CHECK (relationship_count >= 0),

    CONSTRAINT chk_siem_mitre_imports_reference_count
        CHECK (reference_count >= 0),

    CONSTRAINT chk_siem_mitre_imports_status
        CHECK (
            status IN (
                'RUNNING',
                'SUCCESS',
                'FAILED'
            )
        ),

    CONSTRAINT chk_siem_mitre_imports_dataset_name
        CHECK (length(btrim(dataset_name)) > 0)
);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_imports_imported_at
    ON siem_mitre_imports (imported_at DESC);


CREATE INDEX IF NOT EXISTS idx_siem_mitre_imports_status
    ON siem_mitre_imports (status);


-- ============================================================================
-- 9. COMMENTS
-- ============================================================================

COMMENT ON TABLE siem_mitre_tactics IS
    'MITRE ATT&CK tactics imported from the official ATT&CK dataset.';

COMMENT ON TABLE siem_mitre_techniques IS
    'MITRE ATT&CK techniques and sub-techniques imported from the official dataset.';

COMMENT ON TABLE siem_mitre_platforms IS
    'MITRE ATT&CK platforms imported from the official ATT&CK dataset.';

COMMENT ON TABLE siem_mitre_technique_tactics IS
    'Many-to-many relationship between ATT&CK techniques and tactics.';

COMMENT ON TABLE siem_mitre_technique_platforms IS
    'Many-to-many relationship between ATT&CK techniques and platforms.';

COMMENT ON TABLE siem_mitre_references IS
    'External references associated with MITRE ATT&CK techniques.';

COMMENT ON TABLE siem_mitre_relationships IS
    'General MITRE ATT&CK STIX relationships preserved from imported datasets.';

COMMENT ON TABLE siem_mitre_imports IS
    'MITRE ATT&CK dataset import history and dataset version metadata.';


-- ============================================================================
-- END MIGRATION 008
-- ============================================================================
