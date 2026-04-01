package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryBatch_SingleVuln(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if len(req.Queries) != 1 {
			t.Fatalf("expected 1 query, got %d", len(req.Queries))
		}
		if req.Queries[0].Package.Ecosystem != "npm" {
			t.Errorf("ecosystem = %q, want npm", req.Queries[0].Package.Ecosystem)
		}

		resp := batchResponse{
			Results: []batchResultEntry{
				{
					Vulns: []osvVuln{
						{
							ID:      "GHSA-rv95-896h-c2vc",
							Aliases: []string{"CVE-2024-29041"},
							Summary: "Express.js open redirect vulnerability",
							Affected: []osvAffected{
								{
									Ranges: []osvRange{
										{
											Type: "SEMVER",
											Events: []osvEvent{
												{Introduced: "0"},
												{Fixed: "4.19.2"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewWithHTTPClient(srv.Client(), srv.URL)
	results, err := client.QueryBatch(context.Background(), []PackageQuery{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d", len(results))
	}
	if results[0].Error != "" {
		t.Fatalf("unexpected error: %s", results[0].Error)
	}
	if len(results[0].Vulnerabilities) != 1 {
		t.Fatalf("len(vulns) = %d", len(results[0].Vulnerabilities))
	}

	vuln := results[0].Vulnerabilities[0]
	if vuln.ID != "GHSA-rv95-896h-c2vc" {
		t.Errorf("ID = %q", vuln.ID)
	}
	cves := vuln.CVEIDs()
	if len(cves) != 1 || cves[0] != "CVE-2024-29041" {
		t.Errorf("CVEIDs = %v", cves)
	}
	if vuln.FixedVersion != "4.19.2" {
		t.Errorf("FixedVersion = %q", vuln.FixedVersion)
	}
	if vuln.Summary != "Express.js open redirect vulnerability" {
		t.Errorf("Summary = %q", vuln.Summary)
	}
}

func TestQueryBatch_NoVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := batchResponse{
			Results: []batchResultEntry{
				{Vulns: nil},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewWithHTTPClient(srv.Client(), srv.URL)
	results, err := client.QueryBatch(context.Background(), []PackageQuery{
		{Name: "express", Version: "5.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d", len(results))
	}
	if len(results[0].Vulnerabilities) != 0 {
		t.Errorf("expected no vulns, got %d", len(results[0].Vulnerabilities))
	}
}

func TestQueryBatch_MultiplePackages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := batchResponse{
			Results: make([]batchResultEntry, len(req.Queries)),
		}
		// Only the second package has a vulnerability.
		resp.Results[1] = batchResultEntry{
			Vulns: []osvVuln{
				{
					ID:      "GHSA-test-1234-5678",
					Aliases: []string{"CVE-2023-12345"},
					Summary: "Test vulnerability",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewWithHTTPClient(srv.Client(), srv.URL)
	results, err := client.QueryBatch(context.Background(), []PackageQuery{
		{Name: "safe-pkg", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "vuln-pkg", Version: "2.0.0", Ecosystem: "npm"},
		{Name: "another-safe", Version: "3.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("len(results) = %d", len(results))
	}
	if len(results[0].Vulnerabilities) != 0 {
		t.Errorf("results[0] should have no vulns")
	}
	if len(results[1].Vulnerabilities) != 1 {
		t.Fatalf("results[1] should have 1 vuln, got %d", len(results[1].Vulnerabilities))
	}
	if results[1].Vulnerabilities[0].ID != "GHSA-test-1234-5678" {
		t.Errorf("vuln ID = %q", results[1].Vulnerabilities[0].ID)
	}
	if len(results[2].Vulnerabilities) != 0 {
		t.Errorf("results[2] should have no vulns")
	}
}

func TestQueryBatch_Empty(t *testing.T) {
	client := New()
	results, err := client.QueryBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for empty input")
	}
}

func TestQueryBatch_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	client := NewWithHTTPClient(srv.Client(), srv.URL)
	results, err := client.QueryBatch(context.Background(), []PackageQuery{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("QueryBatch should not return error, got: %v", err)
	}
	// Errors are per-query, not global.
	if len(results) != 1 {
		t.Fatalf("len(results) = %d", len(results))
	}
	if results[0].Error == "" {
		t.Error("expected per-query error")
	}
}

func TestEcosystemName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"npm", "npm"},
		{"pypi", "PyPI"},
		{"go", "Go"},
		{"ruby", "RubyGems"},
		{"composer", "Packagist"},
		{"unknown", "unknown"},
	}
	for _, tc := range cases {
		if got := EcosystemName(tc.in); got != tc.want {
			t.Errorf("EcosystemName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestVulnerability_CVEIDs(t *testing.T) {
	v := Vulnerability{
		ID:      "GHSA-abc",
		Aliases: []string{"CVE-2024-12345", "PYSEC-2024-100", "CVE-2024-67890"},
	}
	cves := v.CVEIDs()
	if len(cves) != 2 {
		t.Fatalf("len(CVEIDs) = %d, want 2", len(cves))
	}
	if cves[0] != "CVE-2024-12345" {
		t.Errorf("cves[0] = %q", cves[0])
	}
	if cves[1] != "CVE-2024-67890" {
		t.Errorf("cves[1] = %q", cves[1])
	}
}

func TestVulnerability_CVEIDs_None(t *testing.T) {
	v := Vulnerability{
		ID:      "GHSA-abc",
		Aliases: []string{"PYSEC-2024-100"},
	}
	cves := v.CVEIDs()
	if len(cves) != 0 {
		t.Errorf("expected no CVEs, got %v", cves)
	}
}

func TestConvertVuln_TruncateSummary(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}

	v := convertVuln(osvVuln{
		ID:      "GHSA-long",
		Summary: string(long),
	})
	if len(v.Summary) > 500 {
		t.Errorf("summary should be truncated, got len=%d", len(v.Summary))
	}
	if v.Summary[len(v.Summary)-3:] != "..." {
		t.Error("truncated summary should end with ...")
	}
}
