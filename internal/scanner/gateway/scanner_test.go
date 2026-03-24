package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// noRedirectClient returns an HTTP client that does not follow redirects,
// matching the client used internally by the scanner.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ── HAProxy ───────────────────────────────────────────────────────────────────

func TestProbeHAProxyStats_StatisticsReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/haproxy" && r.URL.RawQuery == "stats" {
			fmt.Fprint(w, "<html><head><title>Statistics Report</title></head><body>HAProxy version 2.6</body></html>")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeHAProxyStats(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) == 0 {
		t.Fatal("expected HAProxy stats finding, got none")
	}
	if findings[0].CheckID != finding.CheckGatewayHAProxyStatsExposed {
		t.Errorf("CheckID = %q; want CheckGatewayHAProxyStatsExposed", findings[0].CheckID)
	}
}

func TestProbeHAProxyStats_NotFound_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeHAProxyStats(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no findings for all-404 server, got %d", len(findings))
	}
}

func TestProbeHAProxyStats_200ButNoHAProxyContent_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Welcome to my website</body></html>")
	}))
	defer srv.Close()

	findings := probeHAProxyStats(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no finding for generic HTML, got %d", len(findings))
	}
}

// ── nginx stub_status ─────────────────────────────────────────────────────────

func TestProbeNginxStatus_ActiveConnections(t *testing.T) {
	body := "Active connections: 42\nserver accepts handled requests\n 100 100 250\nReading: 0 Writing: 1 Waiting: 41\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nginx_status" {
			fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeNginxStatus(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) == 0 {
		t.Fatal("expected nginx status finding, got none")
	}
	if findings[0].CheckID != finding.CheckGatewayNginxStatusExposed {
		t.Errorf("CheckID = %q; want CheckGatewayNginxStatusExposed", findings[0].CheckID)
	}
}

func TestProbeNginxStatus_404_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeNginxStatus(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no findings for all-404 server, got %d", len(findings))
	}
}

// ── Traefik ───────────────────────────────────────────────────────────────────

func TestProbeTraefikAPI_RoutersAndServices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/rawdata" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"routers":{"myapp@docker":{"name":"myapp"}},"services":{"myapp@docker":{}}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeTraefikAPI(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) == 0 {
		t.Fatal("expected Traefik API finding, got none")
	}
	if findings[0].CheckID != finding.CheckGatewayTraefikAPIExposed {
		t.Errorf("CheckID = %q; want CheckGatewayTraefikAPIExposed", findings[0].CheckID)
	}
}

func TestProbeTraefikAPI_401_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	findings := probeTraefikAPI(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no finding for 401 response, got %d", len(findings))
	}
}

func TestProbeTraefikAPI_200ButNoRouterKeys_NoFinding(t *testing.T) {
	// Server returns 200 with valid JSON but no "routers" or "services" keys
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"hello","status":"ok"}`)
	}))
	defer srv.Close()

	findings := probeTraefikAPI(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no finding for non-Traefik JSON, got %d", len(findings))
	}
}

// ── Envoy ─────────────────────────────────────────────────────────────────────

func TestProbeEnvoyAdmin_ConfigDump(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config_dump" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.BootstrapConfigDump","bootstrap":{}}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeEnvoyAdmin(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) == 0 {
		t.Fatal("expected Envoy admin finding, got none")
	}
	if findings[0].CheckID != finding.CheckGatewayEnvoyAdminExposed {
		t.Errorf("CheckID = %q; want CheckGatewayEnvoyAdminExposed", findings[0].CheckID)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("Severity = %q; want Critical", findings[0].Severity)
	}
}

func TestProbeEnvoyAdmin_NoEnvoyInBody_NoFinding(t *testing.T) {
	// Returns @type but no "envoy" substring — must not trigger
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"@type":"type.googleapis.com/something.else","data":{}}`)
	}))
	defer srv.Close()

	findings := probeEnvoyAdmin(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no finding when body lacks 'envoy', got %d", len(findings))
	}
}

// ── Varnish PURGE ─────────────────────────────────────────────────────────────

func TestProbeVarnishDebug_PurgeAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PURGE" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "purged")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	findings := probeVarnishDebug(context.Background(), noRedirectClient(), srv.URL, "testhost")
	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckCDNVarnishPurgeEnabled {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CheckCDNVarnishPurgeEnabled finding when PURGE returns 200")
	}
}

func TestProbeVarnishDebug_Purge405_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PURGE" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	findings := probeVarnishDebug(context.Background(), noRedirectClient(), srv.URL, "testhost")
	for _, f := range findings {
		if f.CheckID == finding.CheckCDNVarnishPurgeEnabled {
			t.Errorf("got unexpected CheckCDNVarnishPurgeEnabled when PURGE returns 405")
		}
	}
}

// ── Akamai Pragma debug ───────────────────────────────────────────────────────

func TestProbeAkamaiDebug_CacheKeyHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pragma := r.Header.Get("Pragma")
		if strings.Contains(pragma, "akamai-x-get-cache-key") {
			w.Header().Set("X-Cache-Key", "/L/1234/56/example.com/")
			w.Header().Set("X-Check-Cacheable", "YES")
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	findings := probeAkamaiDebug(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) == 0 {
		t.Fatal("expected Akamai debug finding when X-Cache-Key header returned, got none")
	}
	if findings[0].CheckID != finding.CheckCDNAkamaiPragmaInfo {
		t.Errorf("CheckID = %q; want CheckCDNAkamaiPragmaInfo", findings[0].CheckID)
	}
}

func TestProbeAkamaiDebug_NoDebugHeaders_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	findings := probeAkamaiDebug(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no finding when no debug headers returned, got %d", len(findings))
	}
}

// ── Tyk dashboard ─────────────────────────────────────────────────────────────

func TestProbeTykDashboard_ApisEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/apis" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"apis":[{"tyk_api_definition":{"id":"myapi"}}],"node_id":"abc-123"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeTykDashboard(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) == 0 {
		t.Fatal("expected Tyk dashboard finding, got none")
	}
	if findings[0].CheckID != finding.CheckGatewayTykDashExposed {
		t.Errorf("CheckID = %q; want CheckGatewayTykDashExposed", findings[0].CheckID)
	}
}

func TestProbeTykDashboard_401_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Authorisation failed"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	findings := probeTykDashboard(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) != 0 {
		t.Errorf("expected no finding for 401, got %d", len(findings))
	}
}

// ── Linkerd viz ───────────────────────────────────────────────────────────────

func TestProbeLinkerdViz_StatAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/stat" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":{"statTables":[{"meshedPodCount":3,"linkerd":"ok"}]}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := probeLinkerdViz(context.Background(), noRedirectClient(), srv.URL, "testhost")
	if len(findings) == 0 {
		t.Fatal("expected Linkerd viz finding, got none")
	}
	if findings[0].CheckID != finding.CheckGatewayLinkerdVizExposed {
		t.Errorf("CheckID = %q; want CheckGatewayLinkerdVizExposed", findings[0].CheckID)
	}
}

// ── Run integration ───────────────────────────────────────────────────────────

func TestScanner_RunSurfaceMode_EmitsFindings(t *testing.T) {
	// Server that mimics nginx stub_status on /nginx_status
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nginx_status":
			fmt.Fprint(w, "Active connections: 10\nserver accepts handled requests\n 50 50 100\nReading: 0 Writing: 1 Waiting: 9\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Extract host:port from test server URL
	asset := strings.TrimPrefix(srv.URL, "http://")

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckGatewayNginxStatusExposed {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CheckGatewayNginxStatusExposed from Run, got findings: %v", findings)
	}
}
