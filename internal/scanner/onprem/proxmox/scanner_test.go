package proxmox_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/onprem/proxmox"
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

// pveAPI is a minimal router for the Proxmox VE API mock.
type pveAPI struct {
	handlers map[string]http.HandlerFunc
}

func (a *pveAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := a.handlers[r.URL.Path]; ok {
		h(w, r)
		return
	}
	http.NotFound(w, r)
}

// jsonResponse writes v as JSON with status 200.
func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// pveData wraps a value in the standard Proxmox {"data": ...} envelope.
func pveData(v any) map[string]any {
	return map[string]any{"data": v}
}

// newTestScanner creates a Scanner pointing at the given httptest server.
// The configured APIEndpoint is set to https:// so the TLS check does not fire.
// Use a custom Config if you need to test TLS or root token checks.
func newTestScanner(ts *httptest.Server) *proxmox.Scanner {
	s := proxmox.New(proxmox.Config{
		APIEndpoint:   "https://192.168.1.100:8006",
		TokenID:       "scanner@pve!beacon",
		TokenSecret:   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		SkipTLSVerify: false,
	})
	s.SetBaseURL(ts.URL)
	return s
}

// healthyBaseHandlers returns handlers for a healthy Proxmox cluster baseline:
// - Current version (8.3.1)
// - One node "pve1"
// - Datacenter firewall enabled
// - No VMs, no containers, no storage
// - Empty backup schedule
func healthyBaseHandlers() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/api2/json/version": func(w http.ResponseWriter, r *http.Request) {
			// Reject unauthenticated requests.
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				jsonResponse(w, pveData(nil))
				return
			}
			jsonResponse(w, pveData(map[string]any{
				"version": "8.3.1",
				"release": "8.3",
				"repoid":  "abcdef12",
			}))
		},
		"/api2/json/nodes": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{
				{"node": "pve1", "status": "online", "cpu": 0.05, "maxcpu": 16},
				{"node": "pve2", "status": "online", "cpu": 0.10, "maxcpu": 16},
			}))
		},
		"/api2/json/cluster/firewall/options": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData(map[string]any{"enable": float64(1)}))
		},
		"/api2/json/cluster/ha/status/current": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{
				{"type": "quorum", "quorate": float64(1)},
			}))
		},
		"/api2/json/cluster/backup": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{}))
		},
		"/api2/json/nodes/pve1/qemu": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{}))
		},
		"/api2/json/nodes/pve1/lxc": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{}))
		},
		"/api2/json/nodes/pve1/storage": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{}))
		},
		"/api2/json/nodes/pve2/qemu": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{}))
		},
		"/api2/json/nodes/pve2/lxc": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{}))
		},
		"/api2/json/nodes/pve2/storage": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, pveData([]map[string]any{}))
		},
	}
}

// ---------------------------------------------------------------------------
// Scanner.Name
// ---------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := proxmox.New(proxmox.Config{})
	if got := s.Name(); got != "onprem/proxmox" {
		t.Errorf("Scanner.Name() = %q, want %q", got, "onprem/proxmox")
	}
}

// ---------------------------------------------------------------------------
// Run — missing endpoint
// ---------------------------------------------------------------------------

func TestRun_MissingEndpoint(t *testing.T) {
	s := proxmox.New(proxmox.Config{APIEndpoint: ""})
	_, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err == nil {
		t.Fatal("expected error when API endpoint is empty")
	}
}

// ---------------------------------------------------------------------------
// Healthy cluster — no findings (except HA is ok with 2 nodes)
// ---------------------------------------------------------------------------

func TestHealthyCluster_NoFindings(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A healthy cluster with 2 nodes, current version, firewall enabled,
	// no VMs/CTs should produce zero findings.
	if len(findings) != 0 {
		for _, f := range findings {
			t.Logf("  unexpected finding: %s — %s", f.CheckID, f.Title)
		}
		t.Errorf("expected 0 findings for healthy cluster, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Check: No TLS (HTTP endpoint)
// ---------------------------------------------------------------------------

func TestNoTLS_HTTPEndpoint(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	// Create scanner with an explicit http:// base URL.
	s := proxmox.New(proxmox.Config{
		APIEndpoint:   "http://192.168.1.100:8006",
		TokenID:       "scanner@pve!beacon",
		TokenSecret:   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		SkipTLSVerify: false,
	})
	// Override with test server URL but the TLS check uses the configured endpoint.
	s.SetBaseURL(ts.URL)

	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The test server URL is http:// so the TLS check should fire.
	if !hasCheckID(findings, finding.CheckOnpremProxmoxNoTLS) {
		t.Error("expected CheckOnpremProxmoxNoTLS when endpoint is HTTP")
	}
}

func TestTLS_HTTPSEndpoint_NoFinding(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	// Create scanner with an https:// endpoint but override base URL for actual requests.
	s := proxmox.New(proxmox.Config{
		APIEndpoint:   "https://192.168.1.100:8006",
		TokenID:       "scanner@pve!beacon",
		TokenSecret:   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		SkipTLSVerify: false,
	})
	s.SetBaseURL(ts.URL)

	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxNoTLS) {
		t.Error("should not emit CheckOnpremProxmoxNoTLS when endpoint is HTTPS")
	}
}

// ---------------------------------------------------------------------------
// Check: Outdated version
// ---------------------------------------------------------------------------

func TestOutdatedVersion_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/version"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		jsonResponse(w, pveData(map[string]any{
			"version": "7.4.3",
			"release": "7.4",
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxOutdatedVersion) {
		t.Error("expected CheckOnpremProxmoxOutdatedVersion for PVE 7.4.3")
	}
}

func TestCurrentVersion_NoFinding(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxOutdatedVersion) {
		t.Error("should not emit CheckOnpremProxmoxOutdatedVersion for PVE 8.3.1")
	}
}

// ---------------------------------------------------------------------------
// Check: Root API token
// ---------------------------------------------------------------------------

func TestRootAPIToken_Finding(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := proxmox.New(proxmox.Config{
		APIEndpoint:   "https://192.168.1.100:8006",
		TokenID:       "root@pam!automation",
		TokenSecret:   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		SkipTLSVerify: false,
	})
	s.SetBaseURL(ts.URL)

	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxRootAPIToken) {
		t.Error("expected CheckOnpremProxmoxRootAPIToken when token belongs to root@pam")
	}
}

func TestNonRootToken_NoFinding(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxRootAPIToken) {
		t.Error("should not emit CheckOnpremProxmoxRootAPIToken for non-root token")
	}
}

// ---------------------------------------------------------------------------
// Check: Default credentials (unauthenticated access)
// ---------------------------------------------------------------------------

func TestDefaultCreds_UnauthenticatedAccess(t *testing.T) {
	handlers := healthyBaseHandlers()
	// Override version endpoint to accept unauthenticated requests.
	handlers["/api2/json/version"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"version": "8.3.1",
			"release": "8.3",
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxDefaultCreds) {
		t.Error("expected CheckOnpremProxmoxDefaultCreds when API is accessible without auth")
	}
}

func TestDefaultCreds_AuthRequired_NoFinding(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxDefaultCreds) {
		t.Error("should not emit CheckOnpremProxmoxDefaultCreds when auth is required")
	}
}

// ---------------------------------------------------------------------------
// Check: Firewall disabled
// ---------------------------------------------------------------------------

func TestFirewallDisabled_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/cluster/firewall/options"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{"enable": float64(0)}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxNoFirewall) {
		t.Error("expected CheckOnpremProxmoxNoFirewall when datacenter firewall is disabled")
	}
}

func TestFirewallEnabled_NoFinding(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxNoFirewall) {
		t.Error("should not emit CheckOnpremProxmoxNoFirewall when firewall is enabled")
	}
}

// ---------------------------------------------------------------------------
// Check: No HA (single node)
// ---------------------------------------------------------------------------

func TestSingleNode_NoHA(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"node": "pve-solo", "status": "online"},
		}))
	}
	// Single node — remove pve2 handlers, add only pve-solo.
	delete(handlers, "/api2/json/nodes/pve2/qemu")
	delete(handlers, "/api2/json/nodes/pve2/lxc")
	delete(handlers, "/api2/json/nodes/pve2/storage")
	handlers["/api2/json/nodes/pve-solo/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{}))
	}
	handlers["/api2/json/nodes/pve-solo/lxc"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{}))
	}
	handlers["/api2/json/nodes/pve-solo/storage"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxNoHA) {
		t.Error("expected CheckOnpremProxmoxNoHA for single-node cluster")
	}
}

func TestMultiNode_NoHAFinding(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxNoHA) {
		t.Error("should not emit CheckOnpremProxmoxNoHA for multi-node cluster")
	}
}

// ---------------------------------------------------------------------------
// Check: Privileged LXC container
// ---------------------------------------------------------------------------

func TestPrivilegedContainer_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/lxc"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(200), "name": "nginx-priv", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/lxc/200/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"unprivileged": float64(0),
			"hostname":     "nginx-priv",
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxPrivilegedCT) {
		t.Error("expected CheckOnpremProxmoxPrivilegedCT for privileged LXC container")
	}
}

func TestUnprivilegedContainer_NoFinding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/lxc"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(201), "name": "nginx-safe", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/lxc/201/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"unprivileged": float64(1),
			"hostname":     "nginx-safe",
		}))
	}
	// CT 201 still has no backup, so suppress that check with backup-all.
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"all": float64(1), "schedule": "daily"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxPrivilegedCT) {
		t.Error("should not emit CheckOnpremProxmoxPrivilegedCT for unprivileged container")
	}
}

// ---------------------------------------------------------------------------
// Check: VM without backup schedule
// ---------------------------------------------------------------------------

func TestVMNoBackup_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "ubuntu-web", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"agent": "1",
			"vga":   "none",
		}))
	}
	// Empty backup schedule.
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxVMNoBackup) {
		t.Error("expected CheckOnpremProxmoxVMNoBackup when VM is not in any backup schedule")
	}
}

func TestVMWithBackup_NoFinding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "ubuntu-web", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"agent": "1",
			"vga":   "none",
		}))
	}
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": "100", "schedule": "daily"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxVMNoBackup) {
		t.Error("should not emit CheckOnpremProxmoxVMNoBackup when VM is in backup schedule")
	}
}

func TestAllBackup_NoFinding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "ubuntu-web", "status": "running"},
			{"vmid": float64(101), "name": "postgres", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{"agent": "1", "vga": "none"}))
	}
	handlers["/api2/json/nodes/pve1/qemu/101/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{"agent": "1", "vga": "none"}))
	}
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"all": float64(1), "schedule": "daily"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxVMNoBackup) {
		t.Error("should not emit CheckOnpremProxmoxVMNoBackup when backup-all is configured")
	}
}

// ---------------------------------------------------------------------------
// Check: VM without QEMU guest agent
// ---------------------------------------------------------------------------

func TestVMNoAgent_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "noagent-vm", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"agent": "0",
			"vga":   "none",
		}))
	}
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": "100", "schedule": "daily"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxVMNoAgent) {
		t.Error("expected CheckOnpremProxmoxVMNoAgent when agent is '0'")
	}
}

func TestVMWithAgent_NoFinding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "agent-vm", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"agent": "1,fstrim_cloned_disks=1",
			"vga":   "none",
		}))
	}
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": "100", "schedule": "daily"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxVMNoAgent) {
		t.Error("should not emit CheckOnpremProxmoxVMNoAgent when agent is '1,...'")
	}
}

// ---------------------------------------------------------------------------
// Check: Open console (noVNC accessible)
// ---------------------------------------------------------------------------

func TestOpenConsole_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "desktop-vm", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"agent": "1",
			"vga":   "qxl",
		}))
	}
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": "100", "schedule": "daily"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxOpenConsole) {
		t.Error("expected CheckOnpremProxmoxOpenConsole when vga=qxl")
	}
}

func TestNoConsole_NoFinding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "headless-vm", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"agent": "1",
			"vga":   "none",
		}))
	}
	handlers["/api2/json/cluster/backup"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": "100", "schedule": "daily"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxOpenConsole) {
		t.Error("should not emit CheckOnpremProxmoxOpenConsole when vga=none")
	}
}

// ---------------------------------------------------------------------------
// Check: Storage without encryption
// ---------------------------------------------------------------------------

func TestStorageNoEncrypt_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/storage"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"storage": "zfs-pool", "type": "zfspool"},
			{"storage": "ceph-rbd", "type": "rbd"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := countCheckID(findings, finding.CheckOnpremProxmoxStorageNoEncrypt)
	// Should fire for both zfspool and rbd on pve1 (pve2 has empty storage).
	if count < 2 {
		t.Errorf("expected at least 2 CheckOnpremProxmoxStorageNoEncrypt findings, got %d", count)
	}
}

func TestStorageDir_NoEncryptFinding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/nodes/pve1/storage"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"storage": "local", "type": "dir"},
			{"storage": "nfs-share", "type": "nfs"},
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxStorageNoEncrypt) {
		t.Error("should not emit CheckOnpremProxmoxStorageNoEncrypt for 'dir' or 'nfs' storage types")
	}
}

// ---------------------------------------------------------------------------
// Check: Scan error handling
// ---------------------------------------------------------------------------

func TestVersionAPIError_ScanError(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/version"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error")) //nolint:errcheck
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	// Scanner should not return a hard error; it records a scan-error finding.
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxScanError) {
		t.Error("expected CheckOnpremProxmoxScanError when version API returns 500")
	}
}

// ---------------------------------------------------------------------------
// ProofCommand and Evidence correctness
// ---------------------------------------------------------------------------

func TestFindings_HaveProofCommandAndEvidence(t *testing.T) {
	handlers := healthyBaseHandlers()
	// Create a scenario with multiple findings.
	handlers["/api2/json/cluster/firewall/options"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{"enable": float64(0)}))
	}
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "test-vm", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{
			"agent": "0",
			"vga":   "std",
		}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		// Scan errors may lack ProofCommand, skip them.
		if f.CheckID == finding.CheckOnpremProxmoxScanError {
			continue
		}
		if f.ProofCommand == "" {
			t.Errorf("finding %s (%s) has empty ProofCommand", f.CheckID, f.Title)
		}
		if f.Evidence == nil {
			t.Errorf("finding %s (%s) has nil Evidence", f.CheckID, f.Title)
		}
		if f.Scanner != "onprem/proxmox" {
			t.Errorf("finding %s has Scanner=%q, want %q", f.CheckID, f.Scanner, "onprem/proxmox")
		}
		if f.Asset != "proxmox.local" {
			t.Errorf("finding %s has Asset=%q, want %q", f.CheckID, f.Asset, "proxmox.local")
		}
	}
}

// ---------------------------------------------------------------------------
// Context cancellation — no panic
// ---------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	api := &pveAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	s := newTestScanner(ts)
	_, _ = s.Run(ctx, "proxmox.local", module.ScanDeep)
	// Must not panic — partial or no results are fine.
}

// ---------------------------------------------------------------------------
// Multiple VMs and containers — counts
// ---------------------------------------------------------------------------

func TestMultipleVMsAndContainers_CorrectCounts(t *testing.T) {
	handlers := healthyBaseHandlers()
	// Two VMs without agent, one container privileged, no backups.
	handlers["/api2/json/nodes/pve1/qemu"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(100), "name": "vm-a", "status": "running"},
			{"vmid": float64(101), "name": "vm-b", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/qemu/100/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{"agent": "0", "vga": "none"}))
	}
	handlers["/api2/json/nodes/pve1/qemu/101/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{"agent": "0", "vga": "none"}))
	}
	handlers["/api2/json/nodes/pve1/lxc"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData([]map[string]any{
			{"vmid": float64(200), "name": "ct-a", "status": "running"},
		}))
	}
	handlers["/api2/json/nodes/pve1/lxc/200/config"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, pveData(map[string]any{"unprivileged": float64(0)}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2 VMs without agent.
	if got := countCheckID(findings, finding.CheckOnpremProxmoxVMNoAgent); got != 2 {
		t.Errorf("CheckOnpremProxmoxVMNoAgent count = %d, want 2", got)
	}
	// 1 privileged container.
	if got := countCheckID(findings, finding.CheckOnpremProxmoxPrivilegedCT); got != 1 {
		t.Errorf("CheckOnpremProxmoxPrivilegedCT count = %d, want 1", got)
	}
	// 3 resources without backup (2 VMs + 1 CT).
	if got := countCheckID(findings, finding.CheckOnpremProxmoxVMNoBackup); got != 3 {
		t.Errorf("CheckOnpremProxmoxVMNoBackup count = %d, want 3", got)
	}
}

// ---------------------------------------------------------------------------
// Edge: version boundary — 8.0 is below min safe, 8.1 is at boundary
// ---------------------------------------------------------------------------

func TestVersionBoundary_8_0_Outdated(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/version"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		jsonResponse(w, pveData(map[string]any{"version": "8.0.4", "release": "8.0"}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremProxmoxOutdatedVersion) {
		t.Error("expected CheckOnpremProxmoxOutdatedVersion for PVE 8.0.4")
	}
}

func TestVersionBoundary_8_1_NotOutdated(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/api2/json/version"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		jsonResponse(w, pveData(map[string]any{"version": "8.1.0", "release": "8.1"}))
	}
	api := &pveAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "proxmox.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremProxmoxOutdatedVersion) {
		t.Error("should not emit CheckOnpremProxmoxOutdatedVersion for PVE 8.1.0 (at minimum)")
	}
}
