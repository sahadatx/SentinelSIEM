-- SentinelSIEM Phase 17: Authentication / Authorization / RBAC
-- PostgreSQL 14+ compatible.
-- Apply using the project's migration runner.

CREATE TABLE IF NOT EXISTS siem_users (
    user_id UUID PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(320) NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_siem_users_username UNIQUE (username),
    CONSTRAINT uq_siem_users_email UNIQUE (email)
);

CREATE TABLE IF NOT EXISTS siem_roles (
    role_name VARCHAR(64) PRIMARY KEY,
    description VARCHAR(255) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS siem_permissions (
    permission_name VARCHAR(128) PRIMARY KEY,
    description VARCHAR(255) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS siem_user_roles (
    user_id UUID NOT NULL REFERENCES siem_users(user_id) ON DELETE CASCADE,
    role_name VARCHAR(64) NOT NULL REFERENCES siem_roles(role_name) ON DELETE RESTRICT,
    PRIMARY KEY (user_id, role_name)
);

CREATE TABLE IF NOT EXISTS siem_role_permissions (
    role_name VARCHAR(64) NOT NULL REFERENCES siem_roles(role_name) ON DELETE CASCADE,
    permission_name VARCHAR(128) NOT NULL REFERENCES siem_permissions(permission_name) ON DELETE CASCADE,
    PRIMARY KEY (role_name, permission_name)
);

CREATE TABLE IF NOT EXISTS siem_sessions (
    session_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES siem_users(user_id) ON DELETE CASCADE,
    token_id VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    ip_address INET NULL,
    user_agent VARCHAR(512) NULL
);

CREATE INDEX IF NOT EXISTS ix_siem_sessions_user_id ON siem_sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_siem_sessions_expires_at ON siem_sessions(expires_at);

CREATE TABLE IF NOT EXISTS siem_auth_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    action VARCHAR(128) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    actor_user_id UUID NULL REFERENCES siem_users(user_id) ON DELETE SET NULL,
    target_user_id UUID NULL REFERENCES siem_users(user_id) ON DELETE SET NULL,
    session_id UUID NULL,
    request_id VARCHAR(128) NULL,
    source_ip INET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_siem_auth_audit_created_at ON siem_auth_audit(created_at DESC);
CREATE INDEX IF NOT EXISTS ix_siem_auth_audit_actor ON siem_auth_audit(actor_user_id, created_at DESC);

INSERT INTO siem_roles (role_name, description) VALUES
    ('ADMIN', 'Full administrative access'),
    ('SOC_ANALYST', 'SOC monitoring and response access'),
    ('SECURITY_ANALYST', 'Detection, IOC, and investigation access'),
    ('INVESTIGATOR', 'Incident investigation access'),
    ('VIEWER', 'Read-only SOC access')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO siem_permissions (permission_name, description) VALUES
    ('events:read', 'Read security events'),
    ('alerts:read', 'Read alerts'),
    ('alerts:manage', 'Acknowledge, investigate, escalate, resolve and close alerts'),
    ('incidents:read', 'Read incidents'),
    ('incidents:manage', 'Manage incident lifecycle'),
    ('iocs:read', 'Read indicators of compromise'),
    ('iocs:manage', 'Manage indicators of compromise'),
    ('mitre:read', 'Read MITRE ATT&CK coverage'),
    ('dashboard:read', 'Read SOC dashboard'),
    ('users:read', 'Read users'),
    ('users:manage', 'Manage users'),
    ('roles:read', 'Read roles'),
    ('roles:manage', 'Manage roles and assignments'),
    ('detections:read', 'Read detections'),
    ('detections:manage', 'Manage detection rules'),
    ('assets:read', 'Read assets'),
    ('assets:manage', 'Manage assets'),
    ('system:read', 'Read system status')
ON CONFLICT (permission_name) DO NOTHING;

-- Seed role mappings from the Phase 17 application registry.
INSERT INTO siem_role_permissions (role_name, permission_name)
SELECT 'ADMIN', permission_name FROM siem_permissions
ON CONFLICT DO NOTHING;

INSERT INTO siem_role_permissions (role_name, permission_name) VALUES
    ('SOC_ANALYST', 'events:read'), ('SOC_ANALYST', 'alerts:read'), ('SOC_ANALYST', 'alerts:manage'),
    ('SOC_ANALYST', 'incidents:read'), ('SOC_ANALYST', 'incidents:manage'), ('SOC_ANALYST', 'iocs:read'),
    ('SOC_ANALYST', 'mitre:read'), ('SOC_ANALYST', 'dashboard:read'), ('SOC_ANALYST', 'detections:read'),
    ('SOC_ANALYST', 'assets:read'), ('SOC_ANALYST', 'system:read'),
    ('SECURITY_ANALYST', 'events:read'), ('SECURITY_ANALYST', 'alerts:read'), ('SECURITY_ANALYST', 'alerts:manage'),
    ('SECURITY_ANALYST', 'incidents:read'), ('SECURITY_ANALYST', 'incidents:manage'), ('SECURITY_ANALYST', 'iocs:read'),
    ('SECURITY_ANALYST', 'iocs:manage'), ('SECURITY_ANALYST', 'mitre:read'), ('SECURITY_ANALYST', 'dashboard:read'),
    ('SECURITY_ANALYST', 'detections:read'), ('SECURITY_ANALYST', 'detections:manage'), ('SECURITY_ANALYST', 'assets:read'),
    ('SECURITY_ANALYST', 'system:read'),
    ('INVESTIGATOR', 'events:read'), ('INVESTIGATOR', 'alerts:read'), ('INVESTIGATOR', 'incidents:read'),
    ('INVESTIGATOR', 'incidents:manage'), ('INVESTIGATOR', 'iocs:read'), ('INVESTIGATOR', 'iocs:manage'),
    ('INVESTIGATOR', 'mitre:read'), ('INVESTIGATOR', 'dashboard:read'), ('INVESTIGATOR', 'assets:read'),
    ('VIEWER', 'events:read'), ('VIEWER', 'alerts:read'), ('VIEWER', 'incidents:read'), ('VIEWER', 'iocs:read'),
    ('VIEWER', 'mitre:read'), ('VIEWER', 'dashboard:read'), ('VIEWER', 'assets:read'), ('VIEWER', 'system:read')
ON CONFLICT DO NOTHING;
