-- Beacon initial schema (Postgres / future SaaS)
-- Mirrors the SQLite schema with Postgres-native types.

CREATE TABLE IF NOT EXISTS targets (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    domain     TEXT         NOT NULL UNIQUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id      UUID         NOT NULL REFERENCES targets(id),
    domain         TEXT         NOT NULL,
    scan_type      TEXT         NOT NULL,
    modules        JSONB        NOT NULL DEFAULT '[]',
    status         TEXT         NOT NULL,
    started_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at   TIMESTAMPTZ,
    finding_count  INTEGER      NOT NULL DEFAULT 0,
    error          TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_domain ON scan_runs(domain);
CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);

CREATE TABLE IF NOT EXISTS findings (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID         NOT NULL REFERENCES scan_runs(id),
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

CREATE TABLE IF NOT EXISTS enriched_findings (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID         NOT NULL REFERENCES scan_runs(id),
    finding_id    UUID         NOT NULL REFERENCES findings(id),
    explanation   TEXT         NOT NULL DEFAULT '',
    impact        TEXT         NOT NULL DEFAULT '',
    remediation   TEXT         NOT NULL DEFAULT '',
    enriched_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enriched_scan_run ON enriched_findings(scan_run_id);

CREATE TABLE IF NOT EXISTS reports (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID         NOT NULL UNIQUE REFERENCES scan_runs(id),
    domain        TEXT         NOT NULL,
    html_content  TEXT         NOT NULL,
    summary       TEXT         NOT NULL DEFAULT '',
    emailed_to    TEXT,
    emailed_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
