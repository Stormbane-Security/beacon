-- Beacon initial schema (SQLite)
-- Compatible with future Postgres migration (see 0001_postgres.sql).

CREATE TABLE IF NOT EXISTS targets (
    id         TEXT      PRIMARY KEY,
    domain     TEXT      NOT NULL UNIQUE,
    created_at DATETIME  NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                    TEXT      PRIMARY KEY,
    target_id             TEXT      NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    domain                TEXT      NOT NULL,
    scan_type             TEXT      NOT NULL,  -- 'surface' | 'deep'
    modules               TEXT      NOT NULL DEFAULT '[]',  -- JSON array of module names
    status                TEXT      NOT NULL,  -- 'pending' | 'running' | 'completed' | 'failed'
    started_at            DATETIME  NOT NULL,
    completed_at          DATETIME,
    finding_count         INTEGER   NOT NULL DEFAULT 0,
    error                 TEXT,
    discovery_duration_ms INTEGER   NOT NULL DEFAULT 0,
    scan_duration_ms      INTEGER   NOT NULL DEFAULT 0,
    asset_count           INTEGER   NOT NULL DEFAULT 0,
    discovery_sources     TEXT      NOT NULL DEFAULT '{}'  -- JSON object map[string]int
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_domain ON scan_runs(domain);
CREATE INDEX IF NOT EXISTS idx_scan_runs_target ON scan_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs(started_at);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    check_id      TEXT      NOT NULL,
    module        TEXT      NOT NULL,
    scanner       TEXT      NOT NULL,
    severity      TEXT      NOT NULL,
    title         TEXT      NOT NULL,
    description   TEXT      NOT NULL,
    asset         TEXT      NOT NULL,
    evidence      TEXT      NOT NULL DEFAULT '{}',  -- JSON
    deep_only     INTEGER   NOT NULL DEFAULT 0,     -- boolean
    discovered_at DATETIME  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_run ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check_id ON findings(check_id);

CREATE TABLE IF NOT EXISTS enriched_findings (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    finding_id    TEXT      NOT NULL REFERENCES findings(id),
    explanation   TEXT      NOT NULL DEFAULT '',
    impact        TEXT      NOT NULL DEFAULT '',
    remediation   TEXT      NOT NULL DEFAULT '',
    enriched_at   DATETIME  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enriched_scan_run ON enriched_findings(scan_run_id);

CREATE TABLE IF NOT EXISTS reports (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL UNIQUE REFERENCES scan_runs(id) ON DELETE CASCADE,
    domain        TEXT      NOT NULL,
    html_content  TEXT      NOT NULL,
    summary       TEXT      NOT NULL DEFAULT '',
    emailed_to    TEXT,
    emailed_at    DATETIME,
    created_at    DATETIME  NOT NULL
);

-- Scan audit log: what was attempted and found per asset per scan
CREATE TABLE IF NOT EXISTS asset_executions (
    id                 TEXT     PRIMARY KEY,
    scan_run_id        TEXT     NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset              TEXT     NOT NULL,
    evidence_json      TEXT     NOT NULL DEFAULT '{}',
    matched_playbooks  TEXT     NOT NULL DEFAULT '[]',
    scanners_run       TEXT     NOT NULL DEFAULT '[]',
    nuclei_tags_run      TEXT     NOT NULL DEFAULT '[]',
    dirbust_paths_run    TEXT     NOT NULL DEFAULT '[]',
    dirbust_paths_found  TEXT     NOT NULL DEFAULT '[]',
    findings_count       INTEGER  NOT NULL DEFAULT 0,
    created_at           DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_exec_scan_run ON asset_executions(scan_run_id);

-- Unmatched assets: no targeted playbook matched, feed for batch analysis
CREATE TABLE IF NOT EXISTS unmatched_assets (
    id           TEXT     PRIMARY KEY,
    scan_run_id  TEXT     NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    fingerprint  TEXT     NOT NULL,
    asset        TEXT     NOT NULL,
    evidence_json TEXT    NOT NULL DEFAULT '{}',
    created_at   DATETIME NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_unmatched_fingerprint ON unmatched_assets(fingerprint);
CREATE INDEX IF NOT EXISTS idx_unmatched_assets_scan_run ON unmatched_assets(scan_run_id);

-- Playbook suggestions: output of batch analysis job
CREATE TABLE IF NOT EXISTS playbook_suggestions (
    id               TEXT     PRIMARY KEY,
    type             TEXT     NOT NULL,
    target_playbook  TEXT     NOT NULL,
    suggested_yaml   TEXT     NOT NULL DEFAULT '',
    reasoning        TEXT     NOT NULL DEFAULT '',
    pr_url           TEXT,
    status           TEXT     NOT NULL DEFAULT 'pending',
    created_at       DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_suggestions_status ON playbook_suggestions(status);

-- Enrichment cache: avoid re-calling Claude for known check types
CREATE TABLE IF NOT EXISTS enrichment_cache (
    check_id     TEXT     PRIMARY KEY,
    explanation  TEXT     NOT NULL DEFAULT '',
    impact       TEXT     NOT NULL DEFAULT '',
    remediation  TEXT     NOT NULL DEFAULT '',
    cached_at    DATETIME NOT NULL
);

-- Correlation findings: cross-asset attack chains from batch analysis
CREATE TABLE IF NOT EXISTS correlation_findings (
    id                  TEXT      PRIMARY KEY,
    scan_run_id         TEXT      NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    domain              TEXT      NOT NULL,
    title               TEXT      NOT NULL,
    severity            TEXT      NOT NULL,
    description         TEXT      NOT NULL DEFAULT '',
    affected_assets     TEXT      NOT NULL DEFAULT '[]',
    contributing_checks TEXT      NOT NULL DEFAULT '[]',
    remediation         TEXT      NOT NULL DEFAULT '',
    created_at          DATETIME  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_correlations_scan_run ON correlation_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_correlations_domain ON correlation_findings(domain);

-- Finding suppressions: false-positive / accepted-risk management
CREATE TABLE IF NOT EXISTS finding_suppressions (
    id         TEXT     PRIMARY KEY,
    domain     TEXT     NOT NULL,
    check_id   TEXT     NOT NULL,
    asset      TEXT     NOT NULL DEFAULT '',
    status     TEXT     NOT NULL,
    note       TEXT     NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suppressions_key
    ON finding_suppressions(domain, check_id, asset);
CREATE INDEX IF NOT EXISTS idx_suppressions_domain ON finding_suppressions(domain);

-- Scanner metrics: per-scanner timing + findings for ROI / cost analysis
CREATE TABLE IF NOT EXISTS scanner_metrics (
    id                 TEXT     PRIMARY KEY,
    scan_run_id        TEXT     NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset              TEXT     NOT NULL,
    scanner_name       TEXT     NOT NULL,
    duration_ms        INTEGER  NOT NULL DEFAULT 0,
    findings_critical  INTEGER  NOT NULL DEFAULT 0,
    findings_high      INTEGER  NOT NULL DEFAULT 0,
    findings_medium    INTEGER  NOT NULL DEFAULT 0,
    findings_low       INTEGER  NOT NULL DEFAULT 0,
    findings_info      INTEGER  NOT NULL DEFAULT 0,
    error_count        INTEGER  NOT NULL DEFAULT 0,
    skipped            INTEGER  NOT NULL DEFAULT 0,
    skip_reason        TEXT     NOT NULL DEFAULT '',
    created_at         DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scanner_metrics_scan_run ON scanner_metrics(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_scanner_metrics_name ON scanner_metrics(scanner_name);

-- Discovery audit: which tool found which asset (for source effectiveness analysis)
CREATE TABLE IF NOT EXISTS discovery_audit (
    id          TEXT     PRIMARY KEY,
    scan_run_id TEXT     NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset       TEXT     NOT NULL,
    source      TEXT     NOT NULL,
    created_at  DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_discovery_audit_scan ON discovery_audit(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_discovery_audit_run_source ON discovery_audit(scan_run_id, source);

-- Sanitized cross-domain scanner metrics: no domain/hostname/IP stored.
-- Used to learn scanner effectiveness patterns across all customers without PII.
CREATE TABLE IF NOT EXISTS sanitized_scanner_metrics (
    id                TEXT     PRIMARY KEY,
    scanner_name      TEXT     NOT NULL,
    tech_category     TEXT     NOT NULL DEFAULT '',
    playbook_name     TEXT     NOT NULL DEFAULT '',
    duration_ms       INTEGER  NOT NULL DEFAULT 0,
    findings_critical INTEGER  NOT NULL DEFAULT 0,
    findings_high     INTEGER  NOT NULL DEFAULT 0,
    findings_medium   INTEGER  NOT NULL DEFAULT 0,
    findings_low      INTEGER  NOT NULL DEFAULT 0,
    findings_info     INTEGER  NOT NULL DEFAULT 0,
    error_count       INTEGER  NOT NULL DEFAULT 0,
    skipped           INTEGER  NOT NULL DEFAULT 0,
    created_at        DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sanitized_metrics_scanner ON sanitized_scanner_metrics(scanner_name);
CREATE INDEX IF NOT EXISTS idx_sanitized_metrics_tech ON sanitized_scanner_metrics(tech_category);

-- Fingerprint rules: data-driven tech detection patterns.
CREATE TABLE IF NOT EXISTS fingerprint_rules (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    signal_type  TEXT     NOT NULL,
    signal_key   TEXT     NOT NULL DEFAULT '',
    signal_value TEXT     NOT NULL,
    field        TEXT     NOT NULL,
    value        TEXT     NOT NULL,
    source       TEXT     NOT NULL DEFAULT 'builtin',
    status       TEXT     NOT NULL DEFAULT 'active',
    confidence   REAL     NOT NULL DEFAULT 1.0,
    seen_count   INTEGER  NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(signal_type, signal_key, signal_value, field)
);

CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_status ON fingerprint_rules(status);

CREATE TABLE IF NOT EXISTS asset_graphs (
    scan_run_id TEXT PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
    graph_json  BLOB NOT NULL
);
