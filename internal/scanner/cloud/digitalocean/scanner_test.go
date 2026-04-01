package digitalocean_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/cloud/digitalocean"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// hasCheckID returns true if the slice contains at least one finding with the
// given check ID.
func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// countCheckID counts findings with the given check ID.
func countCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

// newTestScanner creates a Scanner pointing at the given httptest server.
func newTestScanner(ts *httptest.Server) *digitalocean.Scanner {
	s := digitalocean.New(digitalocean.Config{Token: "test-token"})
	s.SetBaseURL(ts.URL)
	return s
}

// doAPI is a minimal router for the DigitalOcean v2 API mock.
type doAPI struct {
	// handlers maps path -> handler func
	handlers map[string]http.HandlerFunc
}

func (a *doAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := a.handlers[r.URL.Path]; ok {
		h(w, r)
		return
	}
	http.NotFound(w, r)
}

// jsonResponse writes v as JSON with status 200.
func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// emptyLists returns handlers that return empty lists for all endpoints.
func emptyLists() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/spaces": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, map[string]any{"spaces": []any{}})
		},
		"/droplets": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, map[string]any{
				"droplets": []any{},
				"meta":     map[string]any{"total": 0},
				"links":    map[string]any{"pages": map[string]any{}},
			})
		},
		"/firewalls": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, map[string]any{"firewalls": []any{}})
		},
	}
}

// ---------------------------------------------------------------------------
// Scanner.Name
// ---------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := digitalocean.New(digitalocean.Config{})
	if got := s.Name(); got != "cloud/digitalocean" {
		t.Errorf("Scanner.Name() = %q, want %q", got, "cloud/digitalocean")
	}
}

// ---------------------------------------------------------------------------
// Run — missing token
// ---------------------------------------------------------------------------

func TestRun_MissingToken(t *testing.T) {
	s := digitalocean.New(digitalocean.Config{Token: ""})
	_, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err == nil {
		t.Fatal("expected error when token is empty")
	}
}

// ---------------------------------------------------------------------------
// Spaces: public access detection
// ---------------------------------------------------------------------------

func TestSpaces_PublicACL(t *testing.T) {
	handlers := emptyLists()
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"spaces": []map[string]any{
				{
					"name":      "public-bucket",
					"region":    "nyc3",
					"space_acl": "public",
					"encryption": map[string]any{
						"enabled": true,
					},
				},
			},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOSpacesPublic) {
		t.Error("expected CheckCloudDOSpacesPublic finding for public ACL")
	}
	// Should not flag encryption since it is enabled.
	if hasCheckID(findings, finding.CheckCloudDOSpacesNoEncryption) {
		t.Error("should not flag encryption when enabled")
	}
}

func TestSpaces_PublicReadACL(t *testing.T) {
	handlers := emptyLists()
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"spaces": []map[string]any{
				{
					"name":      "read-bucket",
					"region":    "sfo3",
					"space_acl": "public-read",
					"encryption": map[string]any{
						"enabled": true,
					},
				},
			},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOSpacesPublic) {
		t.Error("expected CheckCloudDOSpacesPublic finding for public-read ACL")
	}
}

// ---------------------------------------------------------------------------
// Spaces: missing encryption
// ---------------------------------------------------------------------------

func TestSpaces_NoEncryption(t *testing.T) {
	handlers := emptyLists()
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"spaces": []map[string]any{
				{
					"name":      "unencrypted-bucket",
					"region":    "ams3",
					"space_acl": "private",
					"encryption": map[string]any{
						"enabled": false,
					},
				},
			},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOSpacesNoEncryption) {
		t.Error("expected CheckCloudDOSpacesNoEncryption finding")
	}
	// Private ACL should not flag public access.
	if hasCheckID(findings, finding.CheckCloudDOSpacesPublic) {
		t.Error("should not flag public access for private ACL")
	}
}

func TestSpaces_PublicAndNoEncryption(t *testing.T) {
	handlers := emptyLists()
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"spaces": []map[string]any{
				{
					"name":      "bad-bucket",
					"region":    "sgp1",
					"space_acl": "public",
					"encryption": map[string]any{
						"enabled": false,
					},
				},
			},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOSpacesPublic) {
		t.Error("expected public access finding")
	}
	if !hasCheckID(findings, finding.CheckCloudDOSpacesNoEncryption) {
		t.Error("expected no-encryption finding")
	}
}

// ---------------------------------------------------------------------------
// Spaces: CDN fallback path
// ---------------------------------------------------------------------------

func TestSpaces_CDNFallback(t *testing.T) {
	handlers := emptyLists()
	// Spaces endpoint returns 404 to trigger CDN fallback.
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"id":"not_found"}`))
	}
	handlers["/cdn/endpoints"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"endpoints": []map[string]any{
				{
					"id":     "cdn-123",
					"origin": "my-space.nyc3.digitaloceanspaces.com",
				},
			},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOSpacesPublic) {
		t.Error("expected CheckCloudDOSpacesPublic finding from CDN fallback")
	}
}

// ---------------------------------------------------------------------------
// Droplets: no firewall coverage
// ---------------------------------------------------------------------------

func TestDroplet_NoFirewall(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []any{},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []map[string]any{
				{
					"id":     100,
					"name":   "exposed-droplet",
					"status": "active",
					"region": map[string]any{"slug": "nyc1"},
					"networks": map[string]any{
						"v4": []map[string]any{
							{"ip_address": "203.0.113.10", "type": "public"},
						},
					},
				},
			},
			"meta":  map[string]any{"total": 1},
			"links": map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDONoFirewall) {
		t.Error("expected CheckCloudDONoFirewall finding for droplet without firewall")
	}
	if !hasCheckID(findings, finding.CheckCloudDODropletPublicIP) {
		t.Error("expected CheckCloudDODropletPublicIP finding for droplet with public IP")
	}
}

// ---------------------------------------------------------------------------
// Droplets: with firewall coverage (no CheckCloudDONoFirewall expected)
// ---------------------------------------------------------------------------

func TestDroplet_WithFirewall(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-1",
					"name":        "web-fw",
					"status":      "succeeded",
					"droplet_ids": []int{200},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "80",
							"sources":  map[string]any{"addresses": []string{"10.0.0.0/8"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []map[string]any{
				{
					"id":     200,
					"name":   "firewalled-droplet",
					"status": "active",
					"region": map[string]any{"slug": "sfo3"},
					"networks": map[string]any{
						"v4": []map[string]any{
							{"ip_address": "203.0.113.20", "type": "public"},
						},
					},
				},
			},
			"meta":  map[string]any{"total": 1},
			"links": map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if hasCheckID(findings, finding.CheckCloudDONoFirewall) {
		t.Error("should not flag no-firewall when a firewall covers the droplet")
	}
	// Public IP finding should still be emitted.
	if !hasCheckID(findings, finding.CheckCloudDODropletPublicIP) {
		t.Error("expected public IP finding even when firewall exists")
	}
}

// ---------------------------------------------------------------------------
// Droplets: public IP detection
// ---------------------------------------------------------------------------

func TestDroplet_PublicIP(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-2",
					"name":        "basic-fw",
					"status":      "succeeded",
					"droplet_ids": []int{300},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "443",
							"sources":  map[string]any{"addresses": []string{"10.0.0.0/8"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []map[string]any{
				{
					"id":     300,
					"name":   "dual-ip-droplet",
					"status": "active",
					"region": map[string]any{"slug": "lon1"},
					"networks": map[string]any{
						"v4": []map[string]any{
							{"ip_address": "203.0.113.30", "type": "public"},
							{"ip_address": "10.132.0.5", "type": "private"},
						},
					},
				},
			},
			"meta":  map[string]any{"total": 1},
			"links": map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDODropletPublicIP) {
		t.Error("expected CheckCloudDODropletPublicIP for droplet with public IP")
	}
}

func TestDroplet_PrivateOnly_NoPublicIPFinding(t *testing.T) {
	handlers := emptyLists()
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []map[string]any{
				{
					"id":     400,
					"name":   "private-droplet",
					"status": "active",
					"region": map[string]any{"slug": "nyc3"},
					"networks": map[string]any{
						"v4": []map[string]any{
							{"ip_address": "10.132.0.10", "type": "private"},
						},
					},
				},
			},
			"meta":  map[string]any{"total": 1},
			"links": map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if hasCheckID(findings, finding.CheckCloudDODropletPublicIP) {
		t.Error("should not flag public IP for private-only droplet")
	}
	if hasCheckID(findings, finding.CheckCloudDONoFirewall) {
		t.Error("should not flag no-firewall for private-only droplet")
	}
}

func TestDroplet_Inactive_Skipped(t *testing.T) {
	handlers := emptyLists()
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []map[string]any{
				{
					"id":     500,
					"name":   "stopped-droplet",
					"status": "off",
					"region": map[string]any{"slug": "ams3"},
					"networks": map[string]any{
						"v4": []map[string]any{
							{"ip_address": "203.0.113.50", "type": "public"},
						},
					},
				},
			},
			"meta":  map[string]any{"total": 1},
			"links": map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if hasCheckID(findings, finding.CheckCloudDODropletPublicIP) {
		t.Error("should not flag inactive droplets")
	}
	if hasCheckID(findings, finding.CheckCloudDONoFirewall) {
		t.Error("should not flag inactive droplets for firewall coverage")
	}
}

// ---------------------------------------------------------------------------
// Firewalls: all-open rule
// ---------------------------------------------------------------------------

func TestFirewall_AllOpen(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-open",
					"name":        "bad-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{600},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "0",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOFirewallAllOpen) {
		t.Error("expected CheckCloudDOFirewallAllOpen finding")
	}
}

func TestFirewall_AllOpen_FullRange(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-range",
					"name":        "range-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{700},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "1-65535",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOFirewallAllOpen) {
		t.Error("expected CheckCloudDOFirewallAllOpen finding for 1-65535 range")
	}
}

func TestFirewall_AllOpen_AllKeyword(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-all",
					"name":        "all-keyword-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "udp",
							"ports":    "all",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOFirewallAllOpen) {
		t.Error("expected CheckCloudDOFirewallAllOpen finding for ports=all")
	}
}

func TestFirewall_AllOpen_IPv6(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-v6",
					"name":        "ipv6-open-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "0",
							"sources":  map[string]any{"addresses": []string{"::/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOFirewallAllOpen) {
		t.Error("expected CheckCloudDOFirewallAllOpen for ::/0 source")
	}
}

// ---------------------------------------------------------------------------
// Firewalls: SSH-open rule
// ---------------------------------------------------------------------------

func TestFirewall_SSHOpen(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-ssh",
					"name":        "ssh-open-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{800},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "22",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOFirewallSSHOpen) {
		t.Error("expected CheckCloudDOFirewallSSHOpen finding")
	}
	// All-open should NOT fire for port 22 only.
	if hasCheckID(findings, finding.CheckCloudDOFirewallAllOpen) {
		t.Error("should not flag all-open for SSH-only rule")
	}
}

func TestFirewall_SSHOpen_RangeNotation(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-ssh-range",
					"name":        "ssh-range-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "22-22",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOFirewallSSHOpen) {
		t.Error("expected CheckCloudDOFirewallSSHOpen for ports=22-22")
	}
}

func TestFirewall_SSH_UDP_NotFlagged(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-udp-22",
					"name":        "udp-22-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "udp",
							"ports":    "22",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// SSH check only applies to TCP.
	if hasCheckID(findings, finding.CheckCloudDOFirewallSSHOpen) {
		t.Error("should not flag SSH for UDP protocol")
	}
}

func TestFirewall_RestrictedSource_NoFinding(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-restricted",
					"name":        "restricted-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "22",
							"sources":  map[string]any{"addresses": []string{"10.0.0.0/8"}},
						},
						{
							"protocol": "tcp",
							"ports":    "0",
							"sources":  map[string]any{"addresses": []string{"192.168.1.0/24"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if hasCheckID(findings, finding.CheckCloudDOFirewallSSHOpen) {
		t.Error("should not flag SSH when source is restricted")
	}
	if hasCheckID(findings, finding.CheckCloudDOFirewallAllOpen) {
		t.Error("should not flag all-open when source is restricted")
	}
}

// ---------------------------------------------------------------------------
// Firewall: all-open takes priority over SSH-open for same rule
// ---------------------------------------------------------------------------

func TestFirewall_AllOpen_NotSSH(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-combo",
					"name":        "combo-firewall",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "0",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// When all ports are open, the scanner emits all-open and skips SSH check.
	if !hasCheckID(findings, finding.CheckCloudDOFirewallAllOpen) {
		t.Error("expected all-open finding")
	}
	if hasCheckID(findings, finding.CheckCloudDOFirewallSSHOpen) {
		t.Error("should not emit SSH-open when all-open already fires (continue in loop)")
	}
}

// ---------------------------------------------------------------------------
// API failures: scan error findings
// ---------------------------------------------------------------------------

func TestRun_SpacesAPIFailure_EmitsScanError(t *testing.T) {
	handlers := emptyLists()
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"id":"server_error","message":"internal error"}`))
	}
	// CDN also fails to trigger the error path fully.
	handlers["/cdn/endpoints"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"id":"server_error"}`))
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run should not return error, it should emit scan-error finding: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOScanError) {
		t.Error("expected scan error finding when Spaces API fails")
	}
}

func TestRun_DropletsAPIFailure_EmitsScanError(t *testing.T) {
	handlers := emptyLists()
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"id":"forbidden","message":"insufficient scope"}`))
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run should not return error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOScanError) {
		t.Error("expected scan error finding when Droplets API fails")
	}
}

func TestRun_FirewallsAPIFailure_EmitsScanError(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"id":"unauthorized"}`))
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run should not return error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCloudDOScanError) {
		t.Error("expected scan error finding when Firewalls API fails")
	}
}

func TestRun_AllAPIsFailure_MultipleScanErrors(t *testing.T) {
	// All three subsystems return errors.
	handlers := map[string]http.HandlerFunc{
		"/spaces": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{}`))
		},
		"/cdn/endpoints": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{}`))
		},
		"/droplets": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{}`))
		},
		"/firewalls": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{}`))
		},
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run should not return error: %v", err)
	}

	// Spaces + Droplets + Firewalls = 3 scan errors.
	count := countCheckID(findings, finding.CheckCloudDOScanError)
	if count != 3 {
		t.Errorf("expected 3 scan error findings, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// All-secure configuration: no findings
// ---------------------------------------------------------------------------

func TestRun_AllSecure_NoFindings(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"/spaces": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, map[string]any{
				"spaces": []map[string]any{
					{
						"name":      "secure-space",
						"region":    "nyc3",
						"space_acl": "private",
						"encryption": map[string]any{
							"enabled": true,
						},
					},
				},
			})
		},
		"/firewalls": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, map[string]any{
				"firewalls": []map[string]any{
					{
						"id":          "fw-secure",
						"name":        "secure-firewall",
						"status":      "succeeded",
						"droplet_ids": []int{900},
						"inbound_rules": []map[string]any{
							{
								"protocol": "tcp",
								"ports":    "443",
								"sources":  map[string]any{"addresses": []string{"10.0.0.0/8"}},
							},
						},
					},
				},
			})
		},
		"/droplets": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, map[string]any{
				"droplets": []map[string]any{
					{
						"id":     900,
						"name":   "internal-droplet",
						"status": "active",
						"region": map[string]any{"slug": "nyc3"},
						"networks": map[string]any{
							"v4": []map[string]any{
								{"ip_address": "10.132.0.50", "type": "private"},
							},
						},
					},
				},
				"meta":  map[string]any{"total": 1},
				"links": map[string]any{"pages": map[string]any{}},
			})
		},
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for all-secure configuration, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s (%s)", f.CheckID, f.Title)
		}
	}
}

// ---------------------------------------------------------------------------
// Finding field verification
// ---------------------------------------------------------------------------

func TestFinding_Fields_SpacesPublic(t *testing.T) {
	handlers := emptyLists()
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"spaces": []map[string]any{
				{
					"name":      "my-public-space",
					"region":    "sfo2",
					"space_acl": "public",
					"encryption": map[string]any{
						"enabled": true,
					},
				},
			},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "target.example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckCloudDOSpacesPublic {
			if f.Scanner != "cloud/digitalocean" {
				t.Errorf("scanner = %q; want cloud/digitalocean", f.Scanner)
			}
			if f.Asset != "target.example.com" {
				t.Errorf("asset = %q; want target.example.com", f.Asset)
			}
			if f.Severity != finding.SeverityCritical {
				t.Errorf("severity = %v; want Critical", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should not be empty")
			}
			if f.Evidence == nil {
				t.Fatal("Evidence should not be nil")
			}
			space, _ := f.Evidence["space"].(string)
			if space != "my-public-space" {
				t.Errorf("evidence space = %q; want my-public-space", space)
			}
			region, _ := f.Evidence["region"].(string)
			if region != "sfo2" {
				t.Errorf("evidence region = %q; want sfo2", region)
			}
			return
		}
	}
	t.Error("expected CheckCloudDOSpacesPublic finding")
}

func TestFinding_Fields_FirewallSSHOpen(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-field-test",
					"name":        "field-test-fw",
					"status":      "succeeded",
					"droplet_ids": []int{1001, 1002},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "22",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckCloudDOFirewallSSHOpen {
			if f.Severity != finding.SeverityHigh {
				t.Errorf("severity = %v; want High", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should not be empty")
			}
			fwID, _ := f.Evidence["firewall_id"].(string)
			if fwID != "fw-field-test" {
				t.Errorf("evidence firewall_id = %q; want fw-field-test", fwID)
			}
			fwName, _ := f.Evidence["firewall_name"].(string)
			if fwName != "field-test-fw" {
				t.Errorf("evidence firewall_name = %q; want field-test-fw", fwName)
			}
			return
		}
	}
	t.Error("expected CheckCloudDOFirewallSSHOpen finding")
}

func TestFinding_Fields_NoFirewall(t *testing.T) {
	handlers := emptyLists()
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []map[string]any{
				{
					"id":     1100,
					"name":   "evidence-droplet",
					"status": "active",
					"region": map[string]any{"slug": "fra1"},
					"networks": map[string]any{
						"v4": []map[string]any{
							{"ip_address": "203.0.113.100", "type": "public"},
						},
					},
				},
			},
			"meta":  map[string]any{"total": 1},
			"links": map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckCloudDONoFirewall {
			if f.Severity != finding.SeverityHigh {
				t.Errorf("severity = %v; want High", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should not be empty")
			}
			// Evidence should contain droplet details.
			name, _ := f.Evidence["droplet_name"].(string)
			if name != "evidence-droplet" {
				t.Errorf("evidence droplet_name = %q; want evidence-droplet", name)
			}
			region, _ := f.Evidence["region"].(string)
			if region != "fra1" {
				t.Errorf("evidence region = %q; want fra1", region)
			}
			return
		}
	}
	t.Error("expected CheckCloudDONoFirewall finding")
}

// ---------------------------------------------------------------------------
// Authorization header is sent
// ---------------------------------------------------------------------------

func TestRun_AuthorizationHeader(t *testing.T) {
	var gotAuth string
	handlers := emptyLists()
	// Override spaces to capture the auth header.
	handlers["/spaces"] = func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		jsonResponse(w, map[string]any{"spaces": []any{}})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := digitalocean.New(digitalocean.Config{Token: "dop_v1_secret123"})
	s.SetBaseURL(ts.URL)
	_, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	want := "Bearer dop_v1_secret123"
	if gotAuth != want {
		t.Errorf("Authorization header = %q; want %q", gotAuth, want)
	}
}

// ---------------------------------------------------------------------------
// Multiple resources
// ---------------------------------------------------------------------------

func TestRun_MultipleSpaces(t *testing.T) {
	handlers := emptyLists()
	handlers["/spaces"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"spaces": []map[string]any{
				{
					"name":       "private-encrypted",
					"region":     "nyc3",
					"space_acl":  "private",
					"encryption": map[string]any{"enabled": true},
				},
				{
					"name":       "public-unencrypted",
					"region":     "sfo3",
					"space_acl":  "public",
					"encryption": map[string]any{"enabled": false},
				},
				{
					"name":       "private-unencrypted",
					"region":     "ams3",
					"space_acl":  "private",
					"encryption": map[string]any{"enabled": false},
				},
			},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	publicCount := countCheckID(findings, finding.CheckCloudDOSpacesPublic)
	if publicCount != 1 {
		t.Errorf("expected 1 public access finding, got %d", publicCount)
	}

	encCount := countCheckID(findings, finding.CheckCloudDOSpacesNoEncryption)
	if encCount != 2 {
		t.Errorf("expected 2 no-encryption findings, got %d", encCount)
	}
}

func TestRun_MultipleFirewalls(t *testing.T) {
	handlers := emptyLists()
	handlers["/firewalls"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"firewalls": []map[string]any{
				{
					"id":          "fw-good",
					"name":        "good-fw",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "443",
							"sources":  map[string]any{"addresses": []string{"10.0.0.0/8"}},
						},
					},
				},
				{
					"id":          "fw-bad-ssh",
					"name":        "bad-ssh-fw",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "22",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
				{
					"id":          "fw-bad-all",
					"name":        "bad-all-fw",
					"status":      "succeeded",
					"droplet_ids": []int{},
					"inbound_rules": []map[string]any{
						{
							"protocol": "tcp",
							"ports":    "0",
							"sources":  map[string]any{"addresses": []string{"0.0.0.0/0"}},
						},
					},
				},
			},
		})
	}
	handlers["/droplets"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, map[string]any{
			"droplets": []any{},
			"meta":     map[string]any{"total": 0},
			"links":    map[string]any{"pages": map[string]any{}},
		})
	}
	ts := httptest.NewServer(&doAPI{handlers: handlers})
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "example.com", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	sshCount := countCheckID(findings, finding.CheckCloudDOFirewallSSHOpen)
	if sshCount != 1 {
		t.Errorf("expected 1 SSH-open finding, got %d", sshCount)
	}

	allCount := countCheckID(findings, finding.CheckCloudDOFirewallAllOpen)
	if allCount != 1 {
		t.Errorf("expected 1 all-open finding, got %d", allCount)
	}
}
