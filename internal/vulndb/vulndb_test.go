package vulndb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenAndStats(t *testing.T) {
	db := testDB(t)
	s, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.CVECount != 0 || s.PayloadCount != 0 {
		t.Fatalf("expected empty db, got %+v", s)
	}
}

func TestCVEUpsertAndQuery(t *testing.T) {
	db := testDB(t)
	cve := CVEEntry{
		ID:                "CVE-2023-44487",
		Summary:           "HTTP/2 Rapid Reset",
		Severity:          "high",
		CVSSScore:         7.5,
		VulnClass:         "dos",
		AffectedProduct:   "nginx",
		AffectedEcosystem: "server",
		VersionRange:      "< 1.25.3",
		FixedVersion:      "1.25.3",
		Source:            "nvd",
		UpdatedAt:         time.Now(),
	}
	if err := db.UpsertCVE(cve); err != nil {
		t.Fatal(err)
	}

	// Query by product.
	results, err := db.QueryCVEs("nginx", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != "CVE-2023-44487" {
		t.Fatalf("expected 1 CVE, got %d", len(results))
	}

	// Query with version filter.
	results, err = db.QueryCVEs("nginx", "1.25")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 CVE with version filter, got %d", len(results))
	}

	// Upsert (update) should not duplicate.
	cve.Summary = "HTTP/2 Rapid Reset Attack"
	if err := db.UpsertCVE(cve); err != nil {
		t.Fatal(err)
	}
	results, err = db.QueryCVEs("nginx", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Summary != "HTTP/2 Rapid Reset Attack" {
		t.Fatalf("upsert did not update: %+v", results)
	}

	// Stats reflect the insert.
	s, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.CVECount != 1 {
		t.Fatalf("expected 1 CVE in stats, got %d", s.CVECount)
	}
}

func TestCVEByEcosystem(t *testing.T) {
	db := testDB(t)
	if err := db.UpsertCVE(CVEEntry{
		ID:                "CVE-2021-44228",
		Summary:           "Log4Shell",
		Severity:          "critical",
		CVSSScore:         10.0,
		AffectedProduct:   "log4j-core",
		AffectedEcosystem: "Maven",
		VersionRange:      ">= 2.0, < 2.17.0",
		FixedVersion:      "2.17.0",
		Source:            "osv",
		UpdatedAt:         time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	results, err := db.QueryCVEsByEcosystem("Maven", "log4j", "2.17")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestPayloadUpsert(t *testing.T) {
	db := testDB(t)
	p := VerifiedPayload{
		Service:      "apache",
		Version:      "2.4.49",
		VulnClass:    "lfi",
		CVEID:        "CVE-2021-41773",
		Payload:      "GET /cgi-bin/.%2e/%2e%2e/etc/passwd",
		ProofCommand: "curl -s 'http://TARGET/cgi-bin/.%2e/%2e%2e/etc/passwd'",
		Evidence:     `{"status":200,"body_contains":"root:"}`,
		Confidence:   "high",
		VerifyCount:  1,
		LastVerified: time.Now(),
	}
	if err := db.UpsertPayload(p); err != nil {
		t.Fatal(err)
	}
	// Second upsert bumps verify_count.
	if err := db.UpsertPayload(p); err != nil {
		t.Fatal(err)
	}
	results, err := db.QueryPayloads("apache", "2.4.49")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(results))
	}
	if results[0].VerifyCount != 2 {
		t.Fatalf("expected verify_count=2, got %d", results[0].VerifyCount)
	}
}

func TestFingerprintUpsert(t *testing.T) {
	db := testDB(t)
	f := ServiceFingerprint{
		Domain:      "example.com",
		Service:     "nginx",
		Version:     "1.24.0",
		TechStack:   `["php","wordpress"]`,
		AuthSystem:  "basic",
		WAFDetected: "cloudflare",
		LastSeen:    time.Now(),
	}
	if err := db.UpsertFingerprint(f); err != nil {
		t.Fatal(err)
	}
	results, err := db.QueryFingerprints("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Service != "nginx" {
		t.Fatalf("unexpected: %+v", results)
	}
}

func TestScanResult(t *testing.T) {
	db := testDB(t)
	if err := db.InsertScanResult(ScanResult{
		Domain:       "example.com",
		ScanType:     "surface",
		FindingCount: 3,
		Findings:     `[{"check_id":"CORS-01"},{"check_id":"TLS-01"},{"check_id":"DNS-01"}]`,
		DurationMS:   1234,
		ScannedAt:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	s, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.ScanResultCount != 1 {
		t.Fatalf("expected 1 scan result, got %d", s.ScanResultCount)
	}
}

// --- API tests ---

func testServer(t *testing.T) (*DB, *httptest.Server) {
	t.Helper()
	db := testDB(t)
	srv := NewServer(db, 0)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return db, ts
}

func TestAPIGetCVEs(t *testing.T) {
	db, ts := testServer(t)
	_ = db.UpsertCVE(CVEEntry{
		ID: "CVE-2023-0001", AffectedProduct: "nginx",
		Severity: "high", CVSSScore: 7.5, UpdatedAt: time.Now(),
	})

	resp, err := http.Get(ts.URL + "/api/cves?service=nginx")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var cves []CVEEntry
	_ = json.NewDecoder(resp.Body).Decode(&cves)
	if len(cves) != 1 {
		t.Fatalf("expected 1 cve, got %d", len(cves))
	}
}

func TestAPIGetCVEsBadRequest(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/api/cves")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIGetPayloads(t *testing.T) {
	db, ts := testServer(t)
	_ = db.UpsertPayload(VerifiedPayload{
		Service: "apache", Version: "2.4.49", CVEID: "CVE-2021-41773",
		Payload: "test", LastVerified: time.Now(),
	})
	resp, err := http.Get(ts.URL + "/api/payloads?service=apache&version=2.4.49")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var payloads []VerifiedPayload
	_ = json.NewDecoder(resp.Body).Decode(&payloads)
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
}

func TestAPIPostFindings(t *testing.T) {
	db, ts := testServer(t)
	body := `{"domain":"example.com","scan_type":"surface","findings":[{"check_id":"TEST-01"}]}`
	resp, err := http.Post(ts.URL+"/api/findings", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	s, _ := db.Stats()
	if s.ScanResultCount != 1 {
		t.Fatalf("expected 1 scan result after post, got %d", s.ScanResultCount)
	}
}

func TestAPIPostPayload(t *testing.T) {
	_, ts := testServer(t)
	body := `{"service":"nginx","version":"1.24","cve_id":"CVE-2023-0001","payload":"GET /","confidence":"high"}`
	resp, err := http.Post(ts.URL+"/api/payloads", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestAPIStats(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var stats DBStats
	_ = json.NewDecoder(resp.Body).Decode(&stats)
	if stats.CVECount != 0 {
		t.Fatalf("expected 0 CVEs, got %d", stats.CVECount)
	}
}

func TestAPIFingerprints(t *testing.T) {
	db, ts := testServer(t)
	_ = db.UpsertFingerprint(ServiceFingerprint{
		Domain: "test.com", Service: "nginx", Version: "1.24",
		LastSeen: time.Now(),
	})
	resp, err := http.Get(ts.URL + "/api/fingerprints?domain=test.com")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var fps []ServiceFingerprint
	_ = json.NewDecoder(resp.Body).Decode(&fps)
	if len(fps) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(fps))
	}
}

// --- Client tests (client -> test server -> real db) ---

func TestClientRoundTrip(t *testing.T) {
	db, ts := testServer(t)
	client := NewClient(ts.URL)

	// Seed data.
	_ = db.UpsertCVE(CVEEntry{
		ID: "CVE-2023-9999", AffectedProduct: "redis",
		Severity: "critical", CVSSScore: 9.8, UpdatedAt: time.Now(),
	})
	_ = db.UpsertPayload(VerifiedPayload{
		Service: "redis", Version: "6.0", CVEID: "CVE-2023-9999",
		Payload: "AUTH test", LastVerified: time.Now(),
	})

	// QueryCVEs
	cves, err := client.QueryCVEs("redis", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 {
		t.Fatalf("client QueryCVEs: expected 1, got %d", len(cves))
	}

	// QueryPayloads
	payloads, err := client.QueryPayloads("redis", "6.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("client QueryPayloads: expected 1, got %d", len(payloads))
	}

	// SavePayload
	if err := client.SavePayload(VerifiedPayload{
		Service: "mysql", Version: "8.0", CVEID: "CVE-2024-0001",
		Payload: "test", LastVerified: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// UploadFindings
	if err := client.UploadFindings("example.com", []byte(`[{"check_id":"T-01"}]`)); err != nil {
		t.Fatal(err)
	}

	// Stats
	stats, err := client.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.CVECount != 1 || stats.PayloadCount != 2 || stats.ScanResultCount != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
