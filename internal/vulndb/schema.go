// Package vulndb provides a local vulnerability database backed by SQLite.
// It stores CVE entries, verified exploit payloads, service fingerprints,
// and scan results. Data can be ingested from OSV, NVD, or Nuclei templates.
package vulndb

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database with vulndb-specific operations.
type DB struct {
	db *sql.DB
}

// CVEEntry represents a single vulnerability record.
type CVEEntry struct {
	ID                 string    `json:"id"`
	Summary            string    `json:"summary"`
	Severity           string    `json:"severity"`
	CVSSScore          float64   `json:"cvss_score"`
	VulnClass          string    `json:"vuln_class"`
	AffectedProduct    string    `json:"affected_product"`
	AffectedEcosystem  string    `json:"affected_ecosystem"`
	VersionRange       string    `json:"version_range"`
	FixedVersion       string    `json:"fixed_version"`
	DetectionEndpoint  string    `json:"detection_endpoint"`
	DetectionParam     string    `json:"detection_param"`
	DetectionPattern   string    `json:"detection_pattern"`
	NucleiTemplateID   string    `json:"nuclei_template_id"`
	Source             string    `json:"source"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// VerifiedPayload is a confirmed working exploit payload for a service+version.
type VerifiedPayload struct {
	ID           int64     `json:"id"`
	Service      string    `json:"service"`
	Version      string    `json:"version"`
	VulnClass    string    `json:"vuln_class"`
	CVEID        string    `json:"cve_id"`
	Payload      string    `json:"payload"`
	ProofCommand string    `json:"proof_command"`
	Evidence     string    `json:"evidence"` // JSON
	Confidence   string    `json:"confidence"`
	VerifyCount  int       `json:"verify_count"`
	LastVerified time.Time `json:"last_verified"`
}

// ServiceFingerprint records what is running on a given domain.
type ServiceFingerprint struct {
	ID          int64     `json:"id"`
	Domain      string    `json:"domain"`
	Service     string    `json:"service"`
	Version     string    `json:"version"`
	TechStack   string    `json:"tech_stack"` // JSON array
	AuthSystem  string    `json:"auth_system"`
	WAFDetected string    `json:"waf_detected"`
	LastSeen    time.Time `json:"last_seen"`
}

// ScanResult stores an entire scan run for a domain.
type ScanResult struct {
	ID           int64     `json:"id"`
	Domain       string    `json:"domain"`
	ScanType     string    `json:"scan_type"`
	FindingCount int       `json:"finding_count"`
	Findings     string    `json:"findings"` // JSON array
	DurationMS   int64     `json:"duration_ms"`
	ScannedAt    time.Time `json:"scanned_at"`
}

// DBStats holds aggregate counts for the /api/stats endpoint.
type DBStats struct {
	CVECount         int `json:"cve_count"`
	PayloadCount     int `json:"payload_count"`
	FingerprintCount int `json:"fingerprint_count"`
	ScanResultCount  int `json:"scan_result_count"`
}

const schema = `
CREATE TABLE IF NOT EXISTS cve_entries (
    id TEXT PRIMARY KEY,
    summary TEXT,
    severity TEXT,
    cvss_score REAL,
    vuln_class TEXT,
    affected_product TEXT,
    affected_ecosystem TEXT,
    version_range TEXT,
    fixed_version TEXT,
    detection_endpoint TEXT,
    detection_param TEXT,
    detection_pattern TEXT,
    nuclei_template_id TEXT,
    source TEXT,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS verified_payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT,
    version TEXT,
    vuln_class TEXT,
    cve_id TEXT,
    payload TEXT,
    proof_command TEXT,
    evidence TEXT,
    confidence TEXT,
    verify_count INTEGER DEFAULT 1,
    last_verified TIMESTAMP,
    UNIQUE(service, version, cve_id)
);

CREATE TABLE IF NOT EXISTS service_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    service TEXT,
    version TEXT,
    tech_stack TEXT,
    auth_system TEXT,
    waf_detected TEXT,
    last_seen TIMESTAMP,
    UNIQUE(domain, service)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    scan_type TEXT,
    finding_count INTEGER,
    findings TEXT,
    duration_ms INTEGER,
    scanned_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_entries(affected_product);
CREATE INDEX IF NOT EXISTS idx_cve_ecosystem ON cve_entries(affected_ecosystem);
CREATE INDEX IF NOT EXISTS idx_payloads_service ON verified_payloads(service, version);
CREATE INDEX IF NOT EXISTS idx_fingerprints_domain ON service_fingerprints(domain);
CREATE INDEX IF NOT EXISTS idx_scan_results_domain ON scan_results(domain);
`

// Open creates or opens a SQLite database at the given path and ensures the
// schema is applied. Use ":memory:" for an in-memory database (tests).
func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("vulndb: open %s: %w", path, err)
	}
	// WAL mode for concurrent readers.
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("vulndb: set WAL: %w", err)
	}
	if _, err := sqlDB.Exec(schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("vulndb: migrate: %w", err)
	}
	return &DB{db: sqlDB}, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error { return d.db.Close() }

// --- CVE operations ---

// UpsertCVE inserts or updates a CVE entry.
func (d *DB) UpsertCVE(c CVEEntry) error {
	_, err := d.db.Exec(`
		INSERT INTO cve_entries (id, summary, severity, cvss_score, vuln_class,
			affected_product, affected_ecosystem, version_range, fixed_version,
			detection_endpoint, detection_param, detection_pattern,
			nuclei_template_id, source, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			summary=excluded.summary, severity=excluded.severity,
			cvss_score=excluded.cvss_score, vuln_class=excluded.vuln_class,
			affected_product=excluded.affected_product,
			affected_ecosystem=excluded.affected_ecosystem,
			version_range=excluded.version_range, fixed_version=excluded.fixed_version,
			detection_endpoint=excluded.detection_endpoint,
			detection_param=excluded.detection_param,
			detection_pattern=excluded.detection_pattern,
			nuclei_template_id=excluded.nuclei_template_id,
			source=excluded.source, updated_at=excluded.updated_at`,
		c.ID, c.Summary, c.Severity, c.CVSSScore, c.VulnClass,
		c.AffectedProduct, c.AffectedEcosystem, c.VersionRange, c.FixedVersion,
		c.DetectionEndpoint, c.DetectionParam, c.DetectionPattern,
		c.NucleiTemplateID, c.Source, c.UpdatedAt)
	return err
}

// QueryCVEs returns CVEs matching a product name and optional version.
func (d *DB) QueryCVEs(product, version string) ([]CVEEntry, error) {
	q := `SELECT id, summary, severity, cvss_score, vuln_class,
		affected_product, affected_ecosystem, version_range, fixed_version,
		detection_endpoint, detection_param, detection_pattern,
		nuclei_template_id, source, updated_at
		FROM cve_entries WHERE affected_product LIKE ?`
	args := []any{"%" + product + "%"}
	if version != "" {
		q += " AND (version_range LIKE ? OR fixed_version LIKE ?)"
		args = append(args, "%"+version+"%", "%"+version+"%")
	}
	q += " ORDER BY cvss_score DESC"
	return d.scanCVEs(q, args...)
}

// QueryCVEsByEcosystem returns CVEs for a specific ecosystem + package + version.
func (d *DB) QueryCVEsByEcosystem(ecosystem, pkg, version string) ([]CVEEntry, error) {
	q := `SELECT id, summary, severity, cvss_score, vuln_class,
		affected_product, affected_ecosystem, version_range, fixed_version,
		detection_endpoint, detection_param, detection_pattern,
		nuclei_template_id, source, updated_at
		FROM cve_entries WHERE affected_ecosystem = ? AND affected_product LIKE ?`
	args := []any{ecosystem, "%" + pkg + "%"}
	if version != "" {
		q += " AND (version_range LIKE ? OR fixed_version LIKE ?)"
		args = append(args, "%"+version+"%", "%"+version+"%")
	}
	q += " ORDER BY cvss_score DESC"
	return d.scanCVEs(q, args...)
}

func (d *DB) scanCVEs(query string, args ...any) ([]CVEEntry, error) {
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CVEEntry
	for rows.Next() {
		var c CVEEntry
		if err := rows.Scan(&c.ID, &c.Summary, &c.Severity, &c.CVSSScore,
			&c.VulnClass, &c.AffectedProduct, &c.AffectedEcosystem,
			&c.VersionRange, &c.FixedVersion, &c.DetectionEndpoint,
			&c.DetectionParam, &c.DetectionPattern, &c.NucleiTemplateID,
			&c.Source, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- Payload operations ---

// UpsertPayload inserts or updates a verified payload.
func (d *DB) UpsertPayload(p VerifiedPayload) error {
	_, err := d.db.Exec(`
		INSERT INTO verified_payloads (service, version, vuln_class, cve_id,
			payload, proof_command, evidence, confidence, verify_count, last_verified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(service, version, cve_id) DO UPDATE SET
			vuln_class=excluded.vuln_class, payload=excluded.payload,
			proof_command=excluded.proof_command, evidence=excluded.evidence,
			confidence=excluded.confidence,
			verify_count=verified_payloads.verify_count+1,
			last_verified=excluded.last_verified`,
		p.Service, p.Version, p.VulnClass, p.CVEID,
		p.Payload, p.ProofCommand, p.Evidence, p.Confidence,
		p.VerifyCount, p.LastVerified)
	return err
}

// QueryPayloads returns verified payloads for a service+version.
func (d *DB) QueryPayloads(service, version string) ([]VerifiedPayload, error) {
	rows, err := d.db.Query(`
		SELECT id, service, version, vuln_class, cve_id, payload,
			proof_command, evidence, confidence, verify_count, last_verified
		FROM verified_payloads WHERE service LIKE ? AND version LIKE ?
		ORDER BY verify_count DESC`,
		"%"+service+"%", "%"+version+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VerifiedPayload
	for rows.Next() {
		var p VerifiedPayload
		if err := rows.Scan(&p.ID, &p.Service, &p.Version, &p.VulnClass,
			&p.CVEID, &p.Payload, &p.ProofCommand, &p.Evidence,
			&p.Confidence, &p.VerifyCount, &p.LastVerified); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- Fingerprint operations ---

// UpsertFingerprint inserts or updates a service fingerprint.
func (d *DB) UpsertFingerprint(f ServiceFingerprint) error {
	_, err := d.db.Exec(`
		INSERT INTO service_fingerprints (domain, service, version, tech_stack,
			auth_system, waf_detected, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain, service) DO UPDATE SET
			version=excluded.version, tech_stack=excluded.tech_stack,
			auth_system=excluded.auth_system, waf_detected=excluded.waf_detected,
			last_seen=excluded.last_seen`,
		f.Domain, f.Service, f.Version, f.TechStack,
		f.AuthSystem, f.WAFDetected, f.LastSeen)
	return err
}

// QueryFingerprints returns fingerprints for a domain.
func (d *DB) QueryFingerprints(domain string) ([]ServiceFingerprint, error) {
	rows, err := d.db.Query(`
		SELECT id, domain, service, version, tech_stack, auth_system,
			waf_detected, last_seen
		FROM service_fingerprints WHERE domain = ?`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceFingerprint
	for rows.Next() {
		var f ServiceFingerprint
		if err := rows.Scan(&f.ID, &f.Domain, &f.Service, &f.Version,
			&f.TechStack, &f.AuthSystem, &f.WAFDetected, &f.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// --- Scan result operations ---

// InsertScanResult stores a completed scan run.
func (d *DB) InsertScanResult(r ScanResult) error {
	_, err := d.db.Exec(`
		INSERT INTO scan_results (domain, scan_type, finding_count, findings,
			duration_ms, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		r.Domain, r.ScanType, r.FindingCount, r.Findings,
		r.DurationMS, r.ScannedAt)
	return err
}

// --- Stats ---

// Stats returns aggregate counts across all tables.
func (d *DB) Stats() (DBStats, error) {
	var s DBStats
	for _, q := range []struct {
		query string
		dest  *int
	}{
		{"SELECT COUNT(*) FROM cve_entries", &s.CVECount},
		{"SELECT COUNT(*) FROM verified_payloads", &s.PayloadCount},
		{"SELECT COUNT(*) FROM service_fingerprints", &s.FingerprintCount},
		{"SELECT COUNT(*) FROM scan_results", &s.ScanResultCount},
	} {
		if err := d.db.QueryRow(q.query).Scan(q.dest); err != nil {
			return s, err
		}
	}
	return s, nil
}
