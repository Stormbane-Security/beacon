-- Beacon initial schema (SQLite)
-- Compatible with future Postgres migration (see 0001_postgres.sql).

CREATE TABLE IF NOT EXISTS targets (
    id         TEXT      PRIMARY KEY,
    domain     TEXT      NOT NULL UNIQUE,
    created_at DATETIME  NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id             TEXT      PRIMARY KEY,
    target_id      TEXT      NOT NULL REFERENCES targets(id),
    domain         TEXT      NOT NULL,
    scan_type      TEXT      NOT NULL,  -- 'surface' | 'deep'
    modules        TEXT      NOT NULL DEFAULT '[]',  -- JSON array of module names
    status         TEXT      NOT NULL,  -- 'pending' | 'running' | 'completed' | 'failed'
    started_at     DATETIME  NOT NULL,
    completed_at   DATETIME,
    finding_count  INTEGER   NOT NULL DEFAULT 0,
    error          TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_domain ON scan_runs(domain);
CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL REFERENCES scan_runs(id),
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

CREATE TABLE IF NOT EXISTS enriched_findings (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL REFERENCES scan_runs(id),
    finding_id    TEXT      NOT NULL REFERENCES findings(id),
    explanation   TEXT      NOT NULL DEFAULT '',
    impact        TEXT      NOT NULL DEFAULT '',
    remediation   TEXT      NOT NULL DEFAULT '',
    enriched_at   DATETIME  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enriched_scan_run ON enriched_findings(scan_run_id);

CREATE TABLE IF NOT EXISTS reports (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL UNIQUE REFERENCES scan_runs(id),
    domain        TEXT      NOT NULL,
    html_content  TEXT      NOT NULL,
    summary       TEXT      NOT NULL DEFAULT '',
    emailed_to    TEXT,
    emailed_at    DATETIME,
    created_at    DATETIME  NOT NULL
);
