// Package sqlite provides a SQLite-backed Store for the Beacon CLI.
// The database is created at ~/.beacon/beacon.db on first use.
// The schema is embedded and applied automatically at Open time.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

const schema = `
CREATE TABLE IF NOT EXISTS targets (
    id         TEXT      PRIMARY KEY,
    domain     TEXT      NOT NULL UNIQUE,
    created_at DATETIME  NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id             TEXT      PRIMARY KEY,
    target_id      TEXT      NOT NULL,
    domain         TEXT      NOT NULL,
    scan_type      TEXT      NOT NULL,
    modules        TEXT      NOT NULL DEFAULT '[]',
    status         TEXT      NOT NULL,
    started_at     DATETIME  NOT NULL,
    completed_at   DATETIME,
    finding_count  INTEGER   NOT NULL DEFAULT 0,
    error          TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_domain ON scan_runs(domain);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL,
    check_id      TEXT      NOT NULL,
    module        TEXT      NOT NULL,
    scanner       TEXT      NOT NULL,
    severity      TEXT      NOT NULL,
    title         TEXT      NOT NULL,
    description   TEXT      NOT NULL,
    asset         TEXT      NOT NULL,
    evidence      TEXT      NOT NULL DEFAULT '{}',
    deep_only     INTEGER   NOT NULL DEFAULT 0,
    discovered_at DATETIME  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_run ON findings(scan_run_id);

CREATE TABLE IF NOT EXISTS enriched_findings (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL,
    finding_id    TEXT      NOT NULL,
    explanation   TEXT      NOT NULL DEFAULT '',
    impact        TEXT      NOT NULL DEFAULT '',
    remediation   TEXT      NOT NULL DEFAULT '',
    enriched_at   DATETIME  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enriched_scan_run ON enriched_findings(scan_run_id);

CREATE TABLE IF NOT EXISTS reports (
    id            TEXT      PRIMARY KEY,
    scan_run_id   TEXT      NOT NULL UNIQUE,
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
    scan_run_id        TEXT     NOT NULL,
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
    scan_run_id  TEXT     NOT NULL,
    fingerprint  TEXT     NOT NULL,
    asset        TEXT     NOT NULL,
    evidence_json TEXT    NOT NULL DEFAULT '{}',
    created_at   DATETIME NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_unmatched_fingerprint ON unmatched_assets(fingerprint);

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
    scan_run_id         TEXT      NOT NULL,
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
    scan_run_id        TEXT     NOT NULL,
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
    scan_run_id TEXT     NOT NULL,
    asset       TEXT     NOT NULL,
    source      TEXT     NOT NULL,
    created_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_discovery_audit_scan ON discovery_audit(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_discovery_audit_domain ON discovery_audit(scan_run_id, source);

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
-- Rules map HTTP signals (headers, body, paths, cookies, CNAMEs, etc.) to
-- structured Evidence fields. Replaces hardcoded fingerprintTech() rules over time.
-- Source: builtin (seeded from code), ai (discovered by Claude), user (manually added).
-- Status: active (applied in scans), pending (awaiting review), rejected.
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
`

// Store is a SQLite-backed implementation of store.Store.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and applies
// the schema. Creates parent directories if they don't exist.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite doesn't handle concurrent writers

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	// Idempotent migrations — ADD COLUMN is a no-op if the column already exists
	// (SQLite returns an error for duplicate columns; we ignore it).
	migrations := []string{
		`ALTER TABLE asset_executions ADD COLUMN dirbust_paths_run   TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE asset_executions ADD COLUMN dirbust_paths_found TEXT NOT NULL DEFAULT '[]'`,
		// Replaces the broken finding_id JOIN with a self-contained finding snapshot.
		// The old JOIN on check_id produced Cartesian products when the same check
		// fired on multiple assets within the same scan run.
		`ALTER TABLE enriched_findings ADD COLUMN finding_json TEXT NOT NULL DEFAULT '{}'`,
		// Records the actual error message, not just a boolean error_count flag.
		// Enables diagnosis of scanner failures from stored metrics alone.
		`ALTER TABLE scanner_metrics ADD COLUMN error_message TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scan_runs ADD COLUMN discovery_duration_ms INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE scan_runs ADD COLUMN scan_duration_ms INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE scan_runs ADD COLUMN asset_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE scan_runs ADD COLUMN discovery_sources TEXT NOT NULL DEFAULT '{}'`,
		`ALTER TABLE asset_executions ADD COLUMN classify_duration_ms INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE asset_executions ADD COLUMN expanded_from TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE playbook_suggestions ADD COLUMN suggestion_kind TEXT NOT NULL DEFAULT 'playbook'`,
		`ALTER TABLE playbook_suggestions ADD COLUMN code_snippet TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE playbook_suggestions ADD COLUMN priority TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE playbook_suggestions ADD COLUMN affected_domains TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE fingerprint_rules ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`,
		// Dedup index so per-asset incremental saves + final save don't produce duplicates.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup ON findings(scan_run_id, check_id, asset, title)`,
	}
	for _, m := range migrations {
		_, _ = db.Exec(m) // ignore "duplicate column" errors
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// --- Targets ---

func (s *Store) UpsertTarget(_ context.Context, domain string) (*store.Target, error) {
	id := uuid.NewString()
	now := time.Now().UTC()

	_, err := s.db.Exec(`
		INSERT INTO targets (id, domain, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO NOTHING`,
		id, domain, now)
	if err != nil {
		return nil, err
	}

	return s.GetTarget(context.Background(), domain)
}

func (s *Store) GetTarget(_ context.Context, domain string) (*store.Target, error) {
	row := s.db.QueryRow(`SELECT id, domain, created_at FROM targets WHERE domain = ?`, domain)
	t := &store.Target{}
	if err := row.Scan(&t.ID, &t.Domain, &t.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("target not found: %s", domain)
		}
		return nil, err
	}
	return t, nil
}

func (s *Store) ListTargets(_ context.Context) ([]store.Target, error) {
	rows, err := s.db.Query(`SELECT id, domain, created_at FROM targets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.Target
	for rows.Next() {
		var t store.Target
		if err := rows.Scan(&t.ID, &t.Domain, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- Scan runs ---

func (s *Store) CreateScanRun(_ context.Context, run *store.ScanRun) error {
	if run.ID == "" {
		run.ID = uuid.NewString()
	}

	mods, _ := json.Marshal(run.Modules)
	discSources, _ := json.Marshal(run.DiscoverySources)

	_, err := s.db.Exec(`
		INSERT INTO scan_runs (id, target_id, domain, scan_type, modules, status, started_at, finding_count, error,
		                       discovery_duration_ms, scan_duration_ms, asset_count, discovery_sources)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.TargetID, run.Domain, string(run.ScanType), string(mods),
		string(run.Status), run.StartedAt, run.FindingCount, run.Error,
		run.DiscoveryDurationMs, run.ScanDurationMs, run.AssetCount, string(discSources))
	return err
}

func (s *Store) UpdateScanRun(_ context.Context, run *store.ScanRun) error {
	mods, _ := json.Marshal(run.Modules)
	discSources, _ := json.Marshal(run.DiscoverySources)

	_, err := s.db.Exec(`
		UPDATE scan_runs
		SET status=?, completed_at=?, finding_count=?, modules=?, error=?,
		    discovery_duration_ms=?, scan_duration_ms=?, asset_count=?, discovery_sources=?
		WHERE id=?`,
		string(run.Status), run.CompletedAt, run.FindingCount, string(mods), run.Error,
		run.DiscoveryDurationMs, run.ScanDurationMs, run.AssetCount, string(discSources),
		run.ID)
	return err
}

func (s *Store) GetScanRun(_ context.Context, id string) (*store.ScanRun, error) {
	row := s.db.QueryRow(`
		SELECT id, target_id, domain, scan_type, modules, status,
		       started_at, completed_at, finding_count, error
		FROM scan_runs WHERE id = ?`, id)

	return scanRun(row)
}

func (s *Store) ListScanRuns(_ context.Context, domain string) ([]store.ScanRun, error) {
	rows, err := s.db.Query(`
		SELECT id, target_id, domain, scan_type, modules, status,
		       started_at, completed_at, finding_count, error
		FROM scan_runs WHERE domain = ? ORDER BY started_at DESC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.ScanRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// DeleteScanRun removes a scan run and all associated data in a single transaction.
func (s *Store) DeleteScanRun(_ context.Context, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	tables := []string{
		"findings",
		"enriched_findings",
		"reports",
		"asset_executions",
		"unmatched_assets",
		"scanner_metrics",
		"discovery_audit",
		"correlation_findings",
	}
	for _, tbl := range tables {
		if _, err := tx.Exec(`DELETE FROM `+tbl+` WHERE scan_run_id = ?`, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM scan_runs WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// PurgeOrphanedRuns deletes failed, stopped, and orphaned scan runs started
// before olderThan. Running and pending scans that are older than 2 hours are
// also deleted — they are orphaned (no live goroutine backing them).
func (s *Store) PurgeOrphanedRuns(_ context.Context, olderThan time.Time) (int, error) {
	orphanThreshold := olderThan.Add(-2 * time.Hour)
	rows, err := s.db.Query(
		`SELECT id FROM scan_runs WHERE
			(status NOT IN ('completed', 'running', 'pending') AND started_at < ?)
			OR (status IN ('running', 'pending') AND started_at < ?)`,
		olderThan, orphanThreshold,
	)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	ctx := context.Background()
	for _, id := range ids {
		if err := s.DeleteScanRun(ctx, id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

// scanRun scans a single scan_runs row from either *sql.Row or *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanRun(row scanner) (*store.ScanRun, error) {
	var r store.ScanRun
	var modsJSON string
	var completedAt sql.NullTime
	var errStr sql.NullString

	if err := row.Scan(
		&r.ID, &r.TargetID, &r.Domain, &r.ScanType, &modsJSON,
		&r.Status, &r.StartedAt, &completedAt, &r.FindingCount, &errStr,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan run not found")
		}
		return nil, err
	}

	_ = json.Unmarshal([]byte(modsJSON), &r.Modules)
	if completedAt.Valid {
		r.CompletedAt = &completedAt.Time
	}
	r.Error = errStr.String

	return &r, nil
}

// --- Raw findings ---

func (s *Store) SaveFindings(_ context.Context, scanRunID string, findings []finding.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO findings (id, scan_run_id, check_id, module, scanner, severity,
		                                title, description, asset, evidence, deep_only, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		ev, _ := json.Marshal(f.Evidence)
		deepOnly := 0
		if f.DeepOnly {
			deepOnly = 1
		}
		if _, err := stmt.Exec(
			uuid.NewString(), scanRunID,
			string(f.CheckID), f.Module, f.Scanner, f.Severity.String(),
			f.Title, f.Description, f.Asset, string(ev), deepOnly, f.DiscoveredAt,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) GetFindings(_ context.Context, scanRunID string) ([]finding.Finding, error) {
	rows, err := s.db.Query(`
		SELECT check_id, module, scanner, severity, title, description,
		       asset, evidence, deep_only, discovered_at
		FROM findings WHERE scan_run_id = ?
		ORDER BY discovered_at`, scanRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []finding.Finding
	for rows.Next() {
		var f finding.Finding
		var sevStr, evJSON string
		var deepOnly int
		if err := rows.Scan(
			&f.CheckID, &f.Module, &f.Scanner, &sevStr,
			&f.Title, &f.Description, &f.Asset, &evJSON, &deepOnly, &f.DiscoveredAt,
		); err != nil {
			return nil, err
		}
		f.Severity = finding.ParseSeverity(sevStr)
		_ = json.Unmarshal([]byte(evJSON), &f.Evidence)
		f.DeepOnly = deepOnly == 1
		out = append(out, f)
	}
	return out, rows.Err()
}

// --- Enriched findings ---

func (s *Store) SaveEnrichedFindings(_ context.Context, scanRunID string, efs []enrichment.EnrichedFinding) error {
	if len(efs) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Delete any previous enrichment for this scan run (idempotent re-enrichment)
	if _, err := tx.Exec(`DELETE FROM enriched_findings WHERE scan_run_id = ?`, scanRunID); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO enriched_findings (id, scan_run_id, finding_id, finding_json, explanation, impact, remediation, enriched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, ef := range efs {
		fJSON, _ := json.Marshal(ef.Finding)
		if _, err := stmt.Exec(
			uuid.NewString(), scanRunID,
			string(ef.Finding.CheckID), // kept for backward compat with old rows
			string(fJSON),
			ef.Explanation, ef.Impact, ef.Remediation, now,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) GetEnrichedFindings(_ context.Context, scanRunID string) ([]enrichment.EnrichedFinding, error) {
	// Read finding_json directly — no JOIN. The old approach joined on check_id
	// which produced Cartesian products when the same check fired on multiple assets.
	rows, err := s.db.Query(`
		SELECT finding_json, explanation, impact, remediation
		FROM enriched_findings
		WHERE scan_run_id = ?
		ORDER BY enriched_at`, scanRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []enrichment.EnrichedFinding
	for rows.Next() {
		var ef enrichment.EnrichedFinding
		var fJSON string
		if err := rows.Scan(&fJSON, &ef.Explanation, &ef.Impact, &ef.Remediation); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(fJSON), &ef.Finding)
		out = append(out, ef)
	}
	return out, rows.Err()
}

func (s *Store) GetPreviousEnrichedFindings(_ context.Context, domain, currentScanRunID string) ([]enrichment.EnrichedFinding, error) {
	// Find the most recent completed scan run for this domain that isn't the current one
	var prevRunID string
	err := s.db.QueryRow(`
		SELECT id FROM scan_runs
		WHERE domain = ? AND id != ? AND status = 'completed'
		ORDER BY completed_at DESC LIMIT 1`, domain, currentScanRunID).Scan(&prevRunID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Reuse the existing GetEnrichedFindings logic - just call it with the prev run ID
	return s.GetEnrichedFindings(context.Background(), prevRunID)
}

// --- Reports ---

func (s *Store) SaveReport(_ context.Context, r *store.Report) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}

	_, err := s.db.Exec(`
		INSERT INTO reports (id, scan_run_id, domain, html_content, summary, emailed_to, emailed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_run_id) DO UPDATE SET
		    html_content=excluded.html_content,
		    summary=excluded.summary,
		    emailed_to=excluded.emailed_to,
		    emailed_at=excluded.emailed_at`,
		r.ID, r.ScanRunID, r.Domain, r.HTMLContent, r.Summary,
		nullString(r.EmailedTo), nullTime(r.EmailedAt), r.CreatedAt)
	return err
}

func (s *Store) GetReport(_ context.Context, scanRunID string) (*store.Report, error) {
	row := s.db.QueryRow(`
		SELECT id, scan_run_id, domain, html_content, summary,
		       COALESCE(emailed_to,''), emailed_at, created_at
		FROM reports WHERE scan_run_id = ?`, scanRunID)

	var r store.Report
	var emailedAt sql.NullTime
	if err := row.Scan(
		&r.ID, &r.ScanRunID, &r.Domain, &r.HTMLContent, &r.Summary,
		&r.EmailedTo, &emailedAt, &r.CreatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("report not found for scan run: %s", scanRunID)
		}
		return nil, err
	}
	if emailedAt.Valid {
		r.EmailedAt = &emailedAt.Time
	}
	return &r, nil
}

// --- Asset executions ---

func (s *Store) SaveAssetExecution(_ context.Context, e *store.AssetExecution) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	evJSON, _ := json.Marshal(e.Evidence)
	playbooks, _ := json.Marshal(e.MatchedPlaybooks)
	scanners, _ := json.Marshal(e.ScannersRun)
	tags, _ := json.Marshal(e.NucleiTagsRun)
	dbRun, _ := json.Marshal(e.DirbustPathsRun)
	dbFound, _ := json.Marshal(e.DirbustPathsFound)

	_, err := s.db.Exec(`
		INSERT INTO asset_executions
		  (id, scan_run_id, asset, evidence_json, matched_playbooks, scanners_run,
		   nuclei_tags_run, dirbust_paths_run, dirbust_paths_found, findings_count,
		   classify_duration_ms, expanded_from, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.ScanRunID, e.Asset,
		string(evJSON), string(playbooks), string(scanners), string(tags),
		string(dbRun), string(dbFound),
		e.FindingsCount, e.ClassifyDurationMs, e.ExpandedFrom, e.CreatedAt)
	return err
}

func (s *Store) ListAssetExecutions(_ context.Context, scanRunID string) ([]store.AssetExecution, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_run_id, asset, evidence_json, matched_playbooks,
		       scanners_run, nuclei_tags_run, dirbust_paths_run, dirbust_paths_found,
		       findings_count, created_at
		FROM asset_executions WHERE scan_run_id = ?
		ORDER BY created_at`, scanRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.AssetExecution
	for rows.Next() {
		var e store.AssetExecution
		var evJSON, playbooks, scanners, tags, dbRun, dbFound string
		if err := rows.Scan(
			&e.ID, &e.ScanRunID, &e.Asset, &evJSON,
			&playbooks, &scanners, &tags, &dbRun, &dbFound,
			&e.FindingsCount, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(evJSON), &e.Evidence)
		_ = json.Unmarshal([]byte(playbooks), &e.MatchedPlaybooks)
		_ = json.Unmarshal([]byte(scanners), &e.ScannersRun)
		_ = json.Unmarshal([]byte(tags), &e.NucleiTagsRun)
		_ = json.Unmarshal([]byte(dbRun), &e.DirbustPathsRun)
		_ = json.Unmarshal([]byte(dbFound), &e.DirbustPathsFound)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- Unmatched assets ---

func (s *Store) SaveUnmatchedAsset(_ context.Context, u *store.UnmatchedAsset) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	evJSON, _ := json.Marshal(u.Evidence)
	_, err := s.db.Exec(`
		INSERT INTO unmatched_assets (id, scan_run_id, fingerprint, asset, evidence_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO NOTHING`,
		u.ID, u.ScanRunID, u.Fingerprint, u.Asset, string(evJSON), u.CreatedAt)
	return err
}

func (s *Store) FingerprintExists(_ context.Context, fingerprint string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM unmatched_assets WHERE fingerprint = ?`, fingerprint).Scan(&count)
	return count > 0, err
}

func (s *Store) ListUnmatchedAssets(_ context.Context) ([]store.UnmatchedAsset, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_run_id, fingerprint, asset, evidence_json, created_at
		FROM unmatched_assets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.UnmatchedAsset
	for rows.Next() {
		var u store.UnmatchedAsset
		var evJSON string
		if err := rows.Scan(&u.ID, &u.ScanRunID, &u.Fingerprint, &u.Asset, &evJSON, &u.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(evJSON), &u.Evidence)
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- Playbook suggestions ---

func (s *Store) SavePlaybookSuggestion(_ context.Context, sg *store.PlaybookSuggestion) error {
	if sg.ID == "" {
		sg.ID = uuid.NewString()
	}
	if sg.CreatedAt.IsZero() {
		sg.CreatedAt = time.Now().UTC()
	}
	if sg.Status == "" {
		sg.Status = "pending"
	}
	affectedDomains, _ := json.Marshal(sg.AffectedDomains)
	_, err := s.db.Exec(`
		INSERT INTO playbook_suggestions
		  (id, type, target_playbook, suggested_yaml, reasoning, pr_url, status,
		   suggestion_kind, code_snippet, priority, affected_domains, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sg.ID, sg.Type, sg.TargetPlaybook, sg.SuggestedYAML,
		sg.Reasoning, nullString(sg.PRURL), sg.Status,
		sg.SuggestionKind, sg.CodeSnippet, sg.Priority, string(affectedDomains),
		sg.CreatedAt)
	return err
}

func (s *Store) ListPlaybookSuggestions(_ context.Context, status string) ([]store.PlaybookSuggestion, error) {
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = s.db.Query(`
			SELECT id, type, target_playbook, suggested_yaml, reasoning,
			       COALESCE(pr_url,''), status,
			       COALESCE(suggestion_kind,''), COALESCE(code_snippet,''),
			       COALESCE(priority,''), COALESCE(affected_domains,'[]'),
			       created_at
			FROM playbook_suggestions ORDER BY created_at DESC`)
	} else {
		rows, err = s.db.Query(`
			SELECT id, type, target_playbook, suggested_yaml, reasoning,
			       COALESCE(pr_url,''), status,
			       COALESCE(suggestion_kind,''), COALESCE(code_snippet,''),
			       COALESCE(priority,''), COALESCE(affected_domains,'[]'),
			       created_at
			FROM playbook_suggestions WHERE status = ? ORDER BY created_at DESC`, status)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.PlaybookSuggestion
	for rows.Next() {
		var sg store.PlaybookSuggestion
		var affectedDomainsJSON string
		if err := rows.Scan(
			&sg.ID, &sg.Type, &sg.TargetPlaybook, &sg.SuggestedYAML,
			&sg.Reasoning, &sg.PRURL, &sg.Status,
			&sg.SuggestionKind, &sg.CodeSnippet, &sg.Priority, &affectedDomainsJSON,
			&sg.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(affectedDomainsJSON), &sg.AffectedDomains)
		out = append(out, sg)
	}
	return out, rows.Err()
}

func (s *Store) UpdatePlaybookSuggestion(_ context.Context, sg *store.PlaybookSuggestion) error {
	_, err := s.db.Exec(`
		UPDATE playbook_suggestions SET status=?, pr_url=? WHERE id=?`,
		sg.Status, nullString(sg.PRURL), sg.ID)
	return err
}

// --- Enrichment cache ---

func (s *Store) GetEnrichmentCache(_ context.Context, checkID finding.CheckID) (explanation, impact, remediation string, found bool) {
	err := s.db.QueryRow(`
		SELECT explanation, impact, remediation FROM enrichment_cache WHERE check_id = ?`,
		string(checkID)).Scan(&explanation, &impact, &remediation)
	if err != nil {
		return "", "", "", false
	}
	return explanation, impact, remediation, true
}

func (s *Store) SaveEnrichmentCache(_ context.Context, checkID finding.CheckID, explanation, impact, remediation string) error {
	_, err := s.db.Exec(`
		INSERT INTO enrichment_cache (check_id, explanation, impact, remediation, cached_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(check_id) DO UPDATE SET
		    explanation=excluded.explanation,
		    impact=excluded.impact,
		    remediation=excluded.remediation,
		    cached_at=excluded.cached_at`,
		string(checkID), explanation, impact, remediation, time.Now().UTC())
	return err
}

// --- Correlation findings ---

func (s *Store) SaveCorrelationFindings(_ context.Context, findings []store.CorrelationFinding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(`
		INSERT INTO correlation_findings
		  (id, scan_run_id, domain, title, severity, description, affected_assets, contributing_checks, remediation, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range findings {
		f := &findings[i]
		if f.ID == "" {
			f.ID = uuid.NewString()
		}
		if f.CreatedAt.IsZero() {
			f.CreatedAt = time.Now().UTC()
		}
		assets, _ := json.Marshal(f.AffectedAssets)
		checks, _ := json.Marshal(f.ContributingChecks)
		if _, err := stmt.Exec(
			f.ID, f.ScanRunID, f.Domain, f.Title, f.Severity.String(),
			f.Description, string(assets), string(checks), f.Remediation, f.CreatedAt,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) ListCorrelationFindings(_ context.Context, domain string) ([]store.CorrelationFinding, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_run_id, domain, title, severity, description,
		       affected_assets, contributing_checks, remediation, created_at
		FROM correlation_findings WHERE domain = ?
		ORDER BY created_at DESC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.CorrelationFinding
	for rows.Next() {
		var f store.CorrelationFinding
		var sevStr, assetsJSON, checksJSON string
		if err := rows.Scan(
			&f.ID, &f.ScanRunID, &f.Domain, &f.Title, &sevStr,
			&f.Description, &assetsJSON, &checksJSON, &f.Remediation, &f.CreatedAt,
		); err != nil {
			return nil, err
		}
		f.Severity = finding.ParseSeverity(sevStr)
		_ = json.Unmarshal([]byte(assetsJSON), &f.AffectedAssets)
		_ = json.Unmarshal([]byte(checksJSON), &f.ContributingChecks)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) ListRecentScanRuns(_ context.Context, limit int) ([]store.ScanRun, error) {
	rows, err := s.db.Query(`
		SELECT id, target_id, domain, scan_type, modules, status,
		       started_at, completed_at, finding_count, error
		FROM scan_runs
		ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.ScanRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// --- Finding suppressions ---

func (s *Store) UpsertSuppression(_ context.Context, sup *store.FindingSuppression) error {
	if sup.ID == "" {
		sup.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO finding_suppressions (id, domain, check_id, asset, status, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain, check_id, asset) DO UPDATE SET
			status=excluded.status, note=excluded.note`,
		sup.ID, sup.Domain, sup.CheckID, sup.Asset, string(sup.Status), sup.Note, now)
	return err
}

func (s *Store) ListSuppressions(_ context.Context, domain string) ([]store.FindingSuppression, error) {
	rows, err := s.db.Query(`
		SELECT id, domain, check_id, asset, status, note, created_at
		FROM finding_suppressions WHERE domain = ? ORDER BY created_at DESC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.FindingSuppression
	for rows.Next() {
		var sup store.FindingSuppression
		var status string
		if err := rows.Scan(&sup.ID, &sup.Domain, &sup.CheckID, &sup.Asset, &status, &sup.Note, &sup.CreatedAt); err != nil {
			return nil, err
		}
		sup.Status = store.SuppressionStatus(status)
		out = append(out, sup)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSuppression(_ context.Context, id string) error {
	_, err := s.db.Exec(`DELETE FROM finding_suppressions WHERE id = ?`, id)
	return err
}

// helpers

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// --- Scanner Metrics ---

func (s *Store) SaveScannerMetric(_ context.Context, m *store.ScannerMetric) error {
	_, err := s.db.Exec(`
		INSERT INTO scanner_metrics
			(id, scan_run_id, asset, scanner_name, duration_ms,
			 findings_critical, findings_high, findings_medium, findings_low, findings_info,
			 error_count, error_message, skipped, skip_reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), m.ScanRunID, m.Asset, m.ScannerName, m.DurationMs,
		m.FindingsCritical, m.FindingsHigh, m.FindingsMedium, m.FindingsLow, m.FindingsInfo,
		m.ErrorCount, m.ErrorMessage, boolToInt(m.Skipped), m.SkipReason, m.CreatedAt.UTC(),
	)
	return err
}

func (s *Store) ListScannerMetrics(_ context.Context, scanRunID string) ([]store.ScannerMetric, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_run_id, asset, scanner_name, duration_ms,
		       findings_critical, findings_high, findings_medium, findings_low, findings_info,
		       error_count, error_message, skipped, skip_reason, created_at
		FROM scanner_metrics WHERE scan_run_id = ? ORDER BY created_at ASC`, scanRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.ScannerMetric
	for rows.Next() {
		var m store.ScannerMetric
		var skipped int
		if err := rows.Scan(
			&m.ID, &m.ScanRunID, &m.Asset, &m.ScannerName, &m.DurationMs,
			&m.FindingsCritical, &m.FindingsHigh, &m.FindingsMedium, &m.FindingsLow, &m.FindingsInfo,
			&m.ErrorCount, &m.ErrorMessage, &skipped, &m.SkipReason, &m.CreatedAt,
		); err != nil {
			return nil, err
		}
		m.Skipped = skipped != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetScannerROI aggregates scanner_metrics across all completed scan runs for
// a domain, returning per-scanner ROI statistics for the AI batch analysis job.
func (s *Store) GetScannerROI(_ context.Context, domain string) ([]store.ScannerROISummary, error) {
	rows, err := s.db.Query(`
		SELECT
			sm.scanner_name,
			COUNT(*)                                          AS run_count,
			AVG(sm.duration_ms)                              AS avg_duration_ms,
			SUM(sm.findings_critical + sm.findings_high +
			    sm.findings_medium + sm.findings_low + sm.findings_info) AS total_findings,
			SUM(sm.findings_critical)                        AS critical_findings,
			SUM(sm.findings_high)                            AS high_findings,
			AVG(CASE WHEN sm.error_count > 0 THEN 1.0 ELSE 0.0 END) AS error_rate,
			AVG(CASE WHEN sm.skipped = 1 THEN 1.0 ELSE 0.0 END)     AS skip_rate
		FROM scanner_metrics sm
		JOIN scan_runs sr ON sr.id = sm.scan_run_id
		WHERE sr.domain = ? AND sr.status = 'completed'
		GROUP BY sm.scanner_name
		ORDER BY total_findings DESC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.ScannerROISummary
	for rows.Next() {
		var r store.ScannerROISummary
		if err := rows.Scan(
			&r.ScannerName, &r.RunCount, &r.AvgDurationMs,
			&r.TotalFindings, &r.CriticalFindings, &r.HighFindings,
			&r.ErrorRate, &r.SkipRate,
		); err != nil {
			return nil, err
		}
		if r.AvgDurationMs > 0 {
			r.FindingsPerMin = float64(r.TotalFindings) / (float64(r.AvgDurationMs) / 60000.0)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- Discovery audit ---

func (s *Store) SaveDiscoveryAudit(_ context.Context, audits []store.DiscoveryAudit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`INSERT INTO discovery_audit (id, scan_run_id, asset, source, created_at) VALUES (?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range audits {
		if _, err := stmt.Exec(a.ID, a.ScanRunID, a.Asset, a.Source, a.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetDiscoverySourceSummary(_ context.Context, domain string) ([]store.DiscoverySourceSummary, error) {
	rows, err := s.db.Query(`
		SELECT da.source, COUNT(*) as cnt
		FROM discovery_audit da
		JOIN scan_runs sr ON da.scan_run_id = sr.id
		WHERE sr.domain = ?
		GROUP BY da.source
		ORDER BY cnt DESC
	`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.DiscoverySourceSummary
	for rows.Next() {
		var s store.DiscoverySourceSummary
		if err := rows.Scan(&s.Source, &s.AssetCount); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Store) GetDiscoverySourcesByRun(_ context.Context, scanRunID string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT asset, source FROM discovery_audit WHERE scan_run_id = ?`, scanRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var asset, source string
		if err := rows.Scan(&asset, &source); err != nil {
			return nil, err
		}
		out[asset] = source
	}
	return out, rows.Err()
}

func (s *Store) GetFalsePositivePatterns(_ context.Context, domain string) ([]string, error) {
	// Returns check_ids that appear in findings for this domain but whose enriched
	// explanations contain "no actionable" or "not applicable" or similar dismissals.
	// This signals checks that consistently produce false positives for this tech stack.
	rows, err := s.db.Query(`
		SELECT DISTINCT f.check_id
		FROM findings f
		JOIN enriched_findings ef ON ef.scan_run_id = f.scan_run_id
		JOIN scan_runs sr ON sr.id = f.scan_run_id
		WHERE sr.domain = ?
		  AND f.asset = json_extract(ef.finding_json, '$.asset')
		  AND f.check_id = json_extract(ef.finding_json, '$.check_id')
		  AND (
		    LOWER(ef.explanation) LIKE '%no actionable%'
		    OR LOWER(ef.explanation) LIKE '%not applicable%'
		    OR LOWER(ef.explanation) LIKE '%false positive%'
		    OR LOWER(ef.explanation) LIKE '%expected behavior%'
		  )
	`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var checks []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		checks = append(checks, c)
	}
	return checks, rows.Err()
}

// --- Sanitized cross-domain metrics ---

func (s *Store) SaveSanitizedMetrics(_ context.Context, metrics []store.SanitizedScannerMetric) error {
	if len(metrics) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`
		INSERT INTO sanitized_scanner_metrics
		  (id, scanner_name, tech_category, playbook_name, duration_ms,
		   findings_critical, findings_high, findings_medium, findings_low, findings_info,
		   error_count, skipped, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, m := range metrics {
		skipped := 0
		if m.Skipped {
			skipped = 1
		}
		if _, err := stmt.Exec(
			m.ID, m.ScannerName, m.TechCategory, m.PlaybookName, m.DurationMs,
			m.FindingsCritical, m.FindingsHigh, m.FindingsMedium, m.FindingsLow, m.FindingsInfo,
			m.ErrorCount, skipped, m.CreatedAt,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetCrossDomainScannerSummary(_ context.Context) ([]store.CrossDomainScannerSummary, error) {
	rows, err := s.db.Query(`
		SELECT
			scanner_name,
			tech_category,
			COUNT(*)                                              AS run_count,
			CAST(AVG(duration_ms) AS INTEGER)                    AS avg_duration_ms,
			SUM(findings_critical+findings_high+findings_medium+findings_low+findings_info) AS total_findings,
			SUM(findings_critical)                               AS critical_findings,
			SUM(findings_high)                                   AS high_findings,
			CAST(SUM(CASE WHEN error_count > 0 THEN 1 ELSE 0 END) AS REAL) / COUNT(*) AS error_rate,
			CAST(SUM(skipped) AS REAL) / COUNT(*)                AS skip_rate
		FROM sanitized_scanner_metrics
		GROUP BY scanner_name, tech_category
		ORDER BY total_findings DESC, scanner_name, tech_category
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.CrossDomainScannerSummary
	for rows.Next() {
		var r store.CrossDomainScannerSummary
		if err := rows.Scan(
			&r.ScannerName, &r.TechCategory,
			&r.RunCount, &r.AvgDurationMs, &r.TotalFindings,
			&r.CriticalFindings, &r.HighFindings,
			&r.ErrorRate, &r.SkipRate,
		); err != nil {
			return nil, err
		}
		if r.AvgDurationMs > 0 {
			r.FindingsPerMin = float64(r.TotalFindings) / (float64(r.AvgDurationMs) / 60000.0)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Fingerprint Rules ---

func (s *Store) GetFingerprintRules(ctx context.Context, status string) ([]store.FingerprintRule, error) {
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT id, signal_type, signal_key, signal_value, field, value, source, status, confidence, seen_count, created_at FROM fingerprint_rules WHERE status = 'active' ORDER BY seen_count DESC, id ASC`)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, signal_type, signal_key, signal_value, field, value, source, status, confidence, seen_count, created_at FROM fingerprint_rules WHERE status = ? ORDER BY seen_count DESC, id ASC`, status)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []store.FingerprintRule
	for rows.Next() {
		var r store.FingerprintRule
		if err := rows.Scan(&r.ID, &r.SignalType, &r.SignalKey, &r.SignalValue, &r.Field, &r.Value, &r.Source, &r.Status, &r.Confidence, &r.SeenCount, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) UpsertFingerprintRule(ctx context.Context, r *store.FingerprintRule) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fingerprint_rules (signal_type, signal_key, signal_value, field, value, source, status, confidence, seen_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(signal_type, signal_key, signal_value, field) DO UPDATE SET
			value = excluded.value,
			source = CASE WHEN source = 'builtin' THEN source ELSE excluded.source END,
			status = CASE WHEN status = 'rejected' THEN status ELSE excluded.status END,
			confidence = MAX(confidence, excluded.confidence),
			seen_count = seen_count + 1`,
		r.SignalType, r.SignalKey, r.SignalValue, r.Field, r.Value,
		r.Source, r.Status, r.Confidence, r.SeenCount, time.Now())
	return err
}

func (s *Store) DeleteFingerprintRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fingerprint_rules WHERE id = ?`, id)
	return err
}

func (s *Store) IncrementFingerprintRuleSeen(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE fingerprint_rules SET seen_count = seen_count + 1 WHERE id = ?`, id)
	return err
}

// ScanType needs to be stored as its string value.
// Ensure the module.ScanType type satisfies sql.Scanner / driver.Valuer
// by casting through string — no separate methods needed.
var _ store.Store = (*Store)(nil)

