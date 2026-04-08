package classify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/osv"
	"github.com/stormbane-security/beacon/internal/playbook"
)

// ── extractServiceAndVersion ────────────────────────────────────────────────

func TestExtractServiceAndVersion_Apache(t *testing.T) {
	name, ver := extractServiceAndVersion("web_server", "Apache/2.4.51 (Ubuntu)")
	if name != "apache" || ver != "2.4.51" {
		t.Errorf("got (%q, %q), want (apache, 2.4.51)", name, ver)
	}
}

func TestExtractServiceAndVersion_Nginx(t *testing.T) {
	name, ver := extractServiceAndVersion("web_server", "nginx/1.18.0")
	if name != "nginx" || ver != "1.18.0" {
		t.Errorf("got (%q, %q), want (nginx, 1.18.0)", name, ver)
	}
}

func TestExtractServiceAndVersion_PHP(t *testing.T) {
	name, ver := extractServiceAndVersion("powered_by", "PHP/8.1.12")
	if name != "php" || ver != "8.1.12" {
		t.Errorf("got (%q, %q), want (php, 8.1.12)", name, ver)
	}
}

func TestExtractServiceAndVersion_IIS(t *testing.T) {
	name, ver := extractServiceAndVersion("web_server", "Microsoft-IIS/10.0")
	if name != "microsoft-iis" || ver != "10.0" {
		t.Errorf("got (%q, %q), want (microsoft-iis, 10.0)", name, ver)
	}
}

func TestExtractServiceAndVersion_PlatformNoVersion(t *testing.T) {
	name, ver := extractServiceAndVersion("platform", "jenkins")
	if name != "jenkins" || ver != "" {
		t.Errorf("got (%q, %q), want (jenkins, \"\")", name, ver)
	}
}

func TestExtractServiceAndVersion_GeneratorMeta(t *testing.T) {
	name, ver := extractServiceAndVersion("generator_meta", "WordPress 6.4.3")
	if name != "wordpress" || ver != "6.4.3" {
		t.Errorf("got (%q, %q), want (wordpress, 6.4.3)", name, ver)
	}
}

func TestExtractServiceAndVersion_Empty(t *testing.T) {
	name, ver := extractServiceAndVersion("web_server", "")
	if name != "" || ver != "" {
		t.Errorf("got (%q, %q), want empty", name, ver)
	}
}

// ── CheckOSVVersions ────────────────────────────────────────────────────────

func TestCheckOSVVersions_EmitsFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a vulnerability for the nginx query.
		var req struct {
			Queries []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		type osvEvent struct {
			Fixed string `json:"fixed,omitempty"`
		}
		type osvRange struct {
			Type   string     `json:"type"`
			Events []osvEvent `json:"events"`
		}
		type osvAffected struct {
			Ranges []osvRange `json:"ranges"`
		}
		type osvVuln struct {
			ID       string        `json:"id"`
			Aliases  []string      `json:"aliases"`
			Summary  string        `json:"summary"`
			Affected []osvAffected `json:"affected"`
		}
		type resultEntry struct {
			Vulns []osvVuln `json:"vulns"`
		}
		type batchResp struct {
			Results []resultEntry `json:"results"`
		}

		results := make([]resultEntry, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "nginx" {
				results[i] = resultEntry{
					Vulns: []osvVuln{
						{
							ID:      "GHSA-nginx-test",
							Aliases: []string{"CVE-2024-99999"},
							Summary: "Test nginx vulnerability",
							Affected: []osvAffected{{
								Ranges: []osvRange{{
									Type:   "SEMVER",
									Events: []osvEvent{{Fixed: "1.20.0"}},
								}},
							}},
						},
					},
				}
			}
		}

		resp := batchResp{Results: results}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Override the OSV client for this test.
	SetOSVClient(osv.NewWithHTTPClient(srv.Client(), srv.URL))
	defer SetOSVClient(nil)

	ev := playbook.Evidence{
		ServiceVersions: map[string]string{
			"web_server": "nginx/1.18.0",
		},
	}

	findings := CheckOSVVersions(context.Background(), ev, "example.com")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := findings[0]
	if f.CheckID != finding.CheckOSVCVEMatch {
		t.Errorf("CheckID = %q, want %q", f.CheckID, finding.CheckOSVCVEMatch)
	}
	if f.Confidence != finding.ConfidenceProbable {
		t.Errorf("Confidence = %q, want probable", f.Confidence)
	}
	if f.Scanner != "classify" {
		t.Errorf("Scanner = %q, want classify", f.Scanner)
	}

	if f.Evidence["osv_id"] != "GHSA-nginx-test" {
		t.Errorf("osv_id = %v", f.Evidence["osv_id"])
	}
	if f.Evidence["fixed_version"] != "1.20.0" {
		t.Errorf("fixed_version = %v", f.Evidence["fixed_version"])
	}
}

func TestCheckOSVVersions_NoVersions(t *testing.T) {
	ev := playbook.Evidence{}
	findings := CheckOSVVersions(context.Background(), ev, "example.com")
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestCheckOSVVersions_PlatformNoVersion(t *testing.T) {
	// Platform tags without versions should not generate OSV queries or panic.
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{
			"platform": "jenkins",
		},
	}
	findings := CheckOSVVersions(context.Background(), ev, "example.com")
	// No version means no OSV query, so no findings expected.
	if len(findings) != 0 {
		t.Errorf("expected no findings for versionless platform, got %d", len(findings))
	}
}

func TestCheckOSVVersions_DeduplicatesCVEs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type osvVuln struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
			Summary string   `json:"summary"`
		}
		type resultEntry struct {
			Vulns []osvVuln `json:"vulns"`
		}
		type batchResp struct {
			Results []resultEntry `json:"results"`
		}
		// Return two vulns with the same CVE alias.
		resp := batchResp{
			Results: []resultEntry{
				{
					Vulns: []osvVuln{
						{ID: "GHSA-1", Aliases: []string{"CVE-2024-11111"}, Summary: "First"},
						{ID: "GHSA-2", Aliases: []string{"CVE-2024-11111"}, Summary: "Duplicate"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	SetOSVClient(osv.NewWithHTTPClient(srv.Client(), srv.URL))
	defer SetOSVClient(nil)

	ev := playbook.Evidence{
		ServiceVersions: map[string]string{
			"web_server": "nginx/1.18.0",
		},
	}

	findings := CheckOSVVersions(context.Background(), ev, "example.com")
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

// ── mapOSVSeverity ──────────────────────────────────────────────────────────

func TestMapOSVSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want finding.Severity
	}{
		{"critical", finding.SeverityCritical},
		{"high", finding.SeverityHigh},
		{"medium", finding.SeverityMedium},
		{"low", finding.SeverityLow},
		{"", finding.SeverityHigh}, // unknown defaults to high
		{"CRITICAL", finding.SeverityCritical},
	}
	for _, tc := range cases {
		got := mapOSVSeverity(tc.in)
		if got != tc.want {
			t.Errorf("mapOSVSeverity(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
