-- OpenScanProxy Database Initialization
-- Executed automatically on first PostgreSQL container startup

CREATE TABLE IF NOT EXISTS policy_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    policy_mode         TEXT NOT NULL DEFAULT 'fail-open',
    suspicious_action   TEXT NOT NULL DEFAULT 'log',
    default_access_action TEXT NOT NULL DEFAULT 'allow',
    scan_upload         BOOLEAN NOT NULL DEFAULT true,
    scan_download       BOOLEAN NOT NULL DEFAULT true,
    max_scan_file_size  INTEGER NOT NULL DEFAULT 5242880,
    scan_timeout_ms     INTEGER NOT NULL DEFAULT 5000
);

CREATE TABLE IF NOT EXISTS policy_lists (
    id          SERIAL PRIMARY KEY,
    list_type   TEXT NOT NULL,
    value       TEXT NOT NULL,
    UNIQUE (list_type, value)
);

CREATE INDEX IF NOT EXISTS idx_policy_lists_type ON policy_lists (list_type);

CREATE TABLE IF NOT EXISTS access_rules (
    id                      SERIAL PRIMARY KEY,
    rule_order              INTEGER NOT NULL,
    name                    TEXT NOT NULL DEFAULT '',
    domain_whitelist        JSONB NOT NULL DEFAULT '[]',
    domain_blacklist        JSONB NOT NULL DEFAULT '[]',
    url_whitelist           JSONB NOT NULL DEFAULT '[]',
    url_blacklist           JSONB NOT NULL DEFAULT '[]',
    url_category_whitelist  JSONB NOT NULL DEFAULT '[]',
    url_category_blacklist  JSONB NOT NULL DEFAULT '[]',
    users                   JSONB NOT NULL DEFAULT '[]',
    groups                  JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_access_rules_order ON access_rules (rule_order);

CREATE TABLE IF NOT EXISTS auth_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    enable_proxy_auth   BOOLEAN NOT NULL DEFAULT false,
    proxy_auth_mode     TEXT NOT NULL DEFAULT 'basic',
    enable_https_mitm   BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS proxy_users (
    username    TEXT PRIMARY KEY,
    password    TEXT NOT NULL,
    email       TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT 'user',
    groups      JSONB NOT NULL DEFAULT '[]'
);

-- Seed default policy_config (idempotent via ON CONFLICT DO NOTHING)
INSERT INTO policy_config (id, policy_mode, suspicious_action, default_access_action,
                           scan_upload, scan_download, max_scan_file_size, scan_timeout_ms)
VALUES (1, 'fail-open', 'log', 'allow', true, true, 5242880, 5000)
ON CONFLICT (id) DO NOTHING;

-- Seed default auth_config (Docker deployment: MITM enabled)
INSERT INTO auth_config (id, enable_proxy_auth, proxy_auth_mode, enable_https_mitm)
VALUES (1, false, 'basic', true)
ON CONFLICT (id) DO NOTHING;
