-- Beacon initial schema (Postgres / future SaaS)
-- Mirrors the SQLite schema with Postgres-native types.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS targets (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    domain     TEXT         NOT NULL UNIQUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id             UUID         NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    domain                TEXT         NOT NULL,
    scan_type             TEXT         NOT NULL,
    modules               JSONB        NOT NULL DEFAULT '[]',
    status                TEXT         NOT NULL,
    started_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at          TIMESTAMPTZ,
    finding_count         INTEGER      NOT NULL DEFAULT 0,
    error                 TEXT,
    discovery_duration_ms INTEGER      NOT NULL DEFAULT 0,
    scan_duration_ms      INTEGER      NOT NULL DEFAULT 0,
    asset_count           INTEGER      NOT NULL DEFAULT 0,
    discovery_sources     JSONB        NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_domain ON scan_runs(domain);
CREATE INDEX IF NOT EXISTS idx_scan_runs_target ON scan_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs(started_at);

CREATE TABLE IF NOT EXISTS findings (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID         NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    check_id      TEXT         NOT NULL,
    module        TEXT         NOT NULL,
    scanner       TEXT         NOT NULL,
    severity      TEXT         NOT NULL,
    title         TEXT         NOT NULL,
    description   TEXT         NOT NULL,
    asset         TEXT         NOT NULL,
    evidence      JSONB        NOT NULL DEFAULT '{}',
    deep_only     BOOLEAN      NOT NULL DEFAULT FALSE,
    discovered_at TIMESTAMPTZ  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_run ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check_id ON findings(check_id);

CREATE TABLE IF NOT EXISTS enriched_findings (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID         NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    finding_id    UUID         NOT NULL REFERENCES findings(id),
    explanation   TEXT         NOT NULL DEFAULT '',
    impact        TEXT         NOT NULL DEFAULT '',
    remediation   TEXT         NOT NULL DEFAULT '',
    enriched_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enriched_scan_run ON enriched_findings(scan_run_id);

CREATE TABLE IF NOT EXISTS reports (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID         NOT NULL UNIQUE REFERENCES scan_runs(id) ON DELETE CASCADE,
    domain        TEXT         NOT NULL,
    html_content  TEXT         NOT NULL,
    summary       TEXT         NOT NULL DEFAULT '',
    emailed_to    TEXT,
    emailed_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_executions (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id          UUID         NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset                TEXT         NOT NULL,
    evidence_json        JSONB        NOT NULL DEFAULT '{}',
    matched_playbooks    JSONB        NOT NULL DEFAULT '[]',
    scanners_run         JSONB        NOT NULL DEFAULT '[]',
    nuclei_tags_run      JSONB        NOT NULL DEFAULT '[]',
    dirbust_paths_run    JSONB        NOT NULL DEFAULT '[]',
    dirbust_paths_found  JSONB        NOT NULL DEFAULT '[]',
    findings_count       INTEGER      NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_exec_scan_run ON asset_executions(scan_run_id);

CREATE TABLE IF NOT EXISTS unmatched_assets (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID         NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    fingerprint   TEXT         NOT NULL,
    asset         TEXT         NOT NULL,
    evidence_json JSONB        NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_unmatched_fingerprint ON unmatched_assets(fingerprint);
CREATE INDEX IF NOT EXISTS idx_unmatched_assets_scan_run ON unmatched_assets(scan_run_id);

CREATE TABLE IF NOT EXISTS playbook_suggestions (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    type             TEXT         NOT NULL,
    target_playbook  TEXT         NOT NULL,
    suggested_yaml   TEXT         NOT NULL DEFAULT '',
    reasoning        TEXT         NOT NULL DEFAULT '',
    pr_url           TEXT,
    status           TEXT         NOT NULL DEFAULT 'pending',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_suggestions_status ON playbook_suggestions(status);

CREATE TABLE IF NOT EXISTS enrichment_cache (
    check_id     TEXT         PRIMARY KEY,
    explanation  TEXT         NOT NULL DEFAULT '',
    impact       TEXT         NOT NULL DEFAULT '',
    remediation  TEXT         NOT NULL DEFAULT '',
    cached_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS correlation_findings (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id         UUID         NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    domain              TEXT         NOT NULL,
    title               TEXT         NOT NULL,
    severity            TEXT         NOT NULL,
    description         TEXT         NOT NULL DEFAULT '',
    affected_assets     JSONB        NOT NULL DEFAULT '[]',
    contributing_checks JSONB        NOT NULL DEFAULT '[]',
    remediation         TEXT         NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_correlations_scan_run ON correlation_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_correlations_domain ON correlation_findings(domain);

CREATE TABLE IF NOT EXISTS finding_suppressions (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    domain     TEXT         NOT NULL,
    check_id   TEXT         NOT NULL,
    asset      TEXT         NOT NULL DEFAULT '',
    status     TEXT         NOT NULL,
    note       TEXT         NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suppressions_key
    ON finding_suppressions(domain, check_id, asset);
CREATE INDEX IF NOT EXISTS idx_suppressions_domain ON finding_suppressions(domain);

CREATE TABLE IF NOT EXISTS scanner_metrics (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id        UUID         NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset              TEXT         NOT NULL,
    scanner_name       TEXT         NOT NULL,
    duration_ms        INTEGER      NOT NULL DEFAULT 0,
    findings_critical  INTEGER      NOT NULL DEFAULT 0,
    findings_high      INTEGER      NOT NULL DEFAULT 0,
    findings_medium    INTEGER      NOT NULL DEFAULT 0,
    findings_low       INTEGER      NOT NULL DEFAULT 0,
    findings_info      INTEGER      NOT NULL DEFAULT 0,
    error_count        INTEGER      NOT NULL DEFAULT 0,
    skipped            BOOLEAN      NOT NULL DEFAULT FALSE,
    skip_reason        TEXT         NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scanner_metrics_scan_run ON scanner_metrics(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_scanner_metrics_name ON scanner_metrics(scanner_name);

CREATE TABLE IF NOT EXISTS discovery_audit (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id UUID         NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset       TEXT         NOT NULL,
    source      TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_discovery_audit_scan ON discovery_audit(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_discovery_audit_run_source ON discovery_audit(scan_run_id, source);

CREATE TABLE IF NOT EXISTS sanitized_scanner_metrics (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scanner_name      TEXT         NOT NULL,
    tech_category     TEXT         NOT NULL DEFAULT '',
    playbook_name     TEXT         NOT NULL DEFAULT '',
    duration_ms       INTEGER      NOT NULL DEFAULT 0,
    findings_critical INTEGER      NOT NULL DEFAULT 0,
    findings_high     INTEGER      NOT NULL DEFAULT 0,
    findings_medium   INTEGER      NOT NULL DEFAULT 0,
    findings_low      INTEGER      NOT NULL DEFAULT 0,
    findings_info     INTEGER      NOT NULL DEFAULT 0,
    error_count       INTEGER      NOT NULL DEFAULT 0,
    skipped           BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sanitized_metrics_scanner ON sanitized_scanner_metrics(scanner_name);
CREATE INDEX IF NOT EXISTS idx_sanitized_metrics_tech ON sanitized_scanner_metrics(tech_category);

CREATE TABLE IF NOT EXISTS fingerprint_rules (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_type  TEXT         NOT NULL,
    signal_key   TEXT         NOT NULL DEFAULT '',
    signal_value TEXT         NOT NULL,
    field        TEXT         NOT NULL,
    value        TEXT         NOT NULL,
    source       TEXT         NOT NULL DEFAULT 'builtin',
    status       TEXT         NOT NULL DEFAULT 'active',
    confidence   REAL         NOT NULL DEFAULT 1.0,
    seen_count   INTEGER      NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(signal_type, signal_key, signal_value, field)
);

CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_status ON fingerprint_rules(status);

CREATE TABLE IF NOT EXISTS asset_graphs (
    scan_run_id UUID PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
    graph_json  BYTEA NOT NULL
);
