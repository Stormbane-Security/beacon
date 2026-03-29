package ssrf

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

// ---------------------------------------------------------------------------
// Helper: count findings by CheckID
// ---------------------------------------------------------------------------

func findingsByCheckID(findings []finding.Finding, id finding.CheckID) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if f.CheckID == id {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Mode gating — scanner must only run in ScanAuthorized mode
// ---------------------------------------------------------------------------

// TestSSRF_SurfaceModeReturnsNil verifies that no probes are sent and no
// findings are returned when running in surface mode.
func TestSSRF_SurfaceModeReturnsNil(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		fmt.Fprintln(w, "hello")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings in surface mode, got %d", len(findings))
	}
	if probed {
		t.Error("scanner should not send any HTTP requests in surface mode")
	}
}

// TestSSRF_DeepModeReturnsNil verifies that no probes are sent in deep mode
// either — SSRF requires ScanAuthorized.
func TestSSRF_DeepModeReturnsNil(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		fmt.Fprintln(w, "hello")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings in deep mode, got %d", len(findings))
	}
	if probed {
		t.Error("scanner should not send any HTTP requests in deep mode")
	}
}

// ---------------------------------------------------------------------------
// Main SSRF: metadata reflected in response body
// ---------------------------------------------------------------------------

// TestSSRF_MetadataReflected verifies that when a server reflects cloud
// metadata content in its response, a Critical SSRF finding is emitted.
func TestSSRF_MetadataReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an SSRF-vulnerable server that fetches the URL param and
		// echoes back the content — we return metadata-like content directly.
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			fmt.Fprintln(w, "ami-id: ami-0abcdef1234567890")
			fmt.Fprintln(w, "instance-id: i-1234567890abcdef0")
			return
		}
		fmt.Fprintln(w, "Welcome")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	ssrfFindings := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrfFindings) == 0 {
		t.Fatal("expected at least 1 SSRF finding, got none")
	}
	for _, f := range ssrfFindings {
		if f.Severity != finding.SeverityCritical {
			t.Errorf("expected Critical severity, got %s", f.Severity)
		}
		if !f.DeepOnly {
			t.Error("DeepOnly should be true for SSRF finding")
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must be set")
		}
		if f.Evidence == nil {
			t.Error("Evidence must be set")
		}
	}
}

// TestSSRF_NoReflection verifies that a server returning normal content
// does not produce any SSRF findings.
func TestSSRF_NoReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, world! This is a normal page.")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrf) > 0 {
		t.Errorf("expected no SSRF findings on normal page, got %d", len(ssrf))
	}
	redir := findingsByCheckID(findings, finding.CheckWebSSRFRedirectMetadata)
	if len(redir) > 0 {
		t.Errorf("expected no redirect-metadata findings on normal page, got %d", len(redir))
	}
}

// TestSSRF_RedirectToNonMetadata verifies that a server issuing a 302
// redirect to a non-metadata URL does not produce a finding.
func TestSSRF_RedirectToNonMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to a harmless URL (not a metadata endpoint).
		http.Redirect(w, r, "https://example.com/welcome", http.StatusFound)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSRF || f.CheckID == finding.CheckWebSSRFRedirectMetadata {
			t.Errorf("unexpected finding on non-metadata redirect: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Redirect-to-metadata detection
// ---------------------------------------------------------------------------

// TestSSRF_RedirectToAWSMetadata verifies that a 302 redirect to the AWS
// metadata IP produces a CheckWebSSRFRedirectMetadata finding.
func TestSSRF_RedirectToAWSMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	redir := findingsByCheckID(findings, finding.CheckWebSSRFRedirectMetadata)
	if len(redir) == 0 {
		t.Fatal("expected at least 1 redirect-to-metadata finding, got none")
	}
	f := redir[0]
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
	if !f.DeepOnly {
		t.Error("DeepOnly should be true")
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand must be set")
	}
	ev := f.Evidence
	if ev == nil {
		t.Fatal("Evidence should not be nil")
	}
	loc, _ := ev["redirect_location"].(string)
	if !strings.Contains(loc, "169.254.169.254") {
		t.Errorf("redirect_location should contain metadata IP, got %q", loc)
	}
	sc, _ := ev["status_code"].(int)
	if sc != http.StatusFound {
		t.Errorf("expected status_code 302, got %d", sc)
	}
}

// TestSSRF_RedirectToGCPMetadata verifies detection of a redirect to the
// GCP metadata hostname.
func TestSSRF_RedirectToGCPMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			http.Redirect(w, r, "http://metadata.google.internal/computeMetadata/v1/", http.StatusTemporaryRedirect)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	redir := findingsByCheckID(findings, finding.CheckWebSSRFRedirectMetadata)
	if len(redir) == 0 {
		t.Fatal("expected redirect-to-metadata finding for GCP metadata hostname")
	}
	ev := redir[0].Evidence
	if ev == nil {
		t.Fatal("Evidence should not be nil")
	}
	loc, _ := ev["redirect_location"].(string)
	if !strings.Contains(loc, "metadata.google.internal") {
		t.Errorf("redirect_location should contain GCP metadata hostname, got %q", loc)
	}
}

// TestSSRF_RedirectToAlibabaMetadata verifies detection of a redirect to the
// Alibaba Cloud metadata IP.
func TestSSRF_RedirectToAlibabaMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			http.Redirect(w, r, "http://100.100.100.200/latest/meta-data/", http.StatusMovedPermanently)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	redir := findingsByCheckID(findings, finding.CheckWebSSRFRedirectMetadata)
	if len(redir) == 0 {
		t.Fatal("expected redirect-to-metadata finding for Alibaba metadata IP")
	}
}

// TestSSRF_Redirect301NoBody verifies that a 301 redirect to metadata is
// detected even when the redirect body is empty (edge case: some servers
// send a bare 301 with only a Location header).
func TestSSRF_Redirect301NoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			w.Header().Set("Location", "http://169.254.169.254/latest/meta-data/")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	redir := findingsByCheckID(findings, finding.CheckWebSSRFRedirectMetadata)
	if len(redir) == 0 {
		t.Fatal("expected redirect-to-metadata finding for 301 redirect with no body")
	}
}

// TestSSRF_RedirectNotSsrf verifies that a 302 redirect does NOT trigger a
// main SSRF finding (CheckWebSSRF) — redirects should only emit the
// redirect-metadata check, not the reflected-content check.
func TestSSRF_RedirectNotSsrf(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to AWS metadata — should only trigger redirect finding,
		// not the body-reflection SSRF finding.
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrf) > 0 {
		t.Error("redirect should NOT produce a body-reflection CheckWebSSRF finding")
	}
}

// ---------------------------------------------------------------------------
// Azure IMDS probe (with Metadata: true header)
// ---------------------------------------------------------------------------

// TestSSRF_AzureIMDS verifies that the Azure-specific probe with
// Metadata: true header detects Azure IMDS metadata in the response.
func TestSSRF_AzureIMDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		metaHeader := r.Header.Get("Metadata")

		// Only respond with Azure metadata when the Metadata header is set.
		if urlParam != "" && metaHeader == "true" {
			fmt.Fprintln(w, `{"subscriptionId":"12345","vmId":"vm-abc","resourceGroupName":"rg-test"}`)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrf) == 0 {
		t.Fatal("expected Azure IMDS SSRF finding, got none")
	}

	// Look for the Azure-specific finding (mentions "Azure" in the title).
	var azureFound bool
	for _, f := range ssrf {
		if strings.Contains(f.Title, "Azure") {
			azureFound = true
			if !strings.Contains(f.Description, "Azure IMDS") {
				t.Errorf("expected Azure IMDS description, got %q", f.Description)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand must be set for Azure finding")
			}
			ev := f.Evidence
			if ev == nil {
				t.Fatal("Evidence should not be nil")
			}
			payload, _ := ev["payload"].(string)
			if !strings.Contains(payload, "metadata/instance") {
				t.Errorf("Azure payload should reference metadata/instance, got %q", payload)
			}
		}
	}
	if !azureFound {
		t.Error("expected at least one finding with 'Azure' in the title")
	}
}

// TestSSRF_AzureIMDS_NoHeader verifies that the Azure IMDS probe does not
// emit a finding when the server ignores requests lacking the Metadata header.
func TestSSRF_AzureIMDS_NoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metaHeader := r.Header.Get("Metadata")
		// Only respond with metadata if the header is present — the main
		// loop (without the header) should not detect it, and the Azure
		// probe should only fire when the header IS forwarded.
		if metaHeader == "true" {
			// If this path is hit, the Azure probe sent the header.
			// Simulate a server that does NOT forward it to the metadata
			// service — returns normal content.
			fmt.Fprintln(w, "Access denied: no metadata header forwarded")
			return
		}
		fmt.Fprintln(w, "normal page content")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	for _, f := range ssrf {
		if strings.Contains(f.Title, "Azure") {
			t.Errorf("should not produce Azure finding when metadata not reflected: %+v", f)
		}
	}
}

// TestSSRF_AzureIMDS_RedirectSkipped verifies that a 302 redirect response
// in the Azure IMDS probe path is skipped (not treated as SSRF).
func TestSSRF_AzureIMDS_RedirectSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			// Redirect — the Azure section should skip this.
			http.Redirect(w, r, "http://169.254.169.254/metadata/instance", http.StatusFound)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// The Azure probe should NOT produce a CheckWebSSRF for a redirect.
	// (The redirect-to-metadata section handles that with a different check.)
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSRF && strings.Contains(f.Title, "Azure") {
			t.Errorf("Azure IMDS probe should not produce SSRF finding for redirect: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Multiple probe parameters — each param emits at most one finding
// ---------------------------------------------------------------------------

// TestSSRF_OnePerParam verifies the scanner emits at most one finding per
// probe parameter from each scan loop (main loop and Azure loop each break
// after the first payload hit per param).
func TestSSRF_OnePerParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond with metadata for every request with any known param.
		for _, p := range probeParams {
			if r.URL.Query().Get(p) != "" {
				fmt.Fprintln(w, "ami-id: ami-abc123")
				return
			}
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Count body-reflection SSRF findings per param. The main loop and Azure
	// IMDS loop are independent — the first param ("url") can legitimately
	// have one finding from each, so we allow up to 2 per param (main + Azure).
	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	paramCount := make(map[string]int)
	for _, f := range ssrf {
		ev := f.Evidence
		if ev == nil {
			continue
		}
		p, _ := ev["param"].(string)
		paramCount[p]++
	}
	for p, count := range paramCount {
		if count > 2 {
			t.Errorf("param %q should have at most 2 findings (main + Azure loop), got %d", p, count)
		}
	}

	// Verify the scanner found at least one param.
	if len(paramCount) == 0 {
		t.Error("expected at least one param to produce findings")
	}
}

// ---------------------------------------------------------------------------
// metadataSignalFound unit tests
// ---------------------------------------------------------------------------

func TestMetadataSignalFound(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty body",
			body: "",
			want: "",
		},
		{
			name: "normal HTML",
			body: "<html><body>Hello World</body></html>",
			want: "",
		},
		{
			name: "AWS ami-id",
			body: "ami-id\ninstance-id\nlocal-hostname",
			want: "ami-id",
		},
		{
			name: "AWS AccessKeyId",
			body: `{"AccessKeyId":"AKIA...","SecretAccessKey":"..."}`,
			want: "AccessKeyId",
		},
		{
			name: "GCP serviceAccounts",
			body: `{"serviceAccounts":{"default":{"email":"test@project.iam.gserviceaccount.com"}}}`,
			want: "serviceAccounts",
		},
		{
			name: "GCP project-id",
			body: "project-id\nsome-project-name",
			want: "project-id",
		},
		{
			name: "Azure subscriptionId",
			body: `{"subscriptionId":"abcd-1234","vmId":"vm-9999"}`,
			want: "subscriptionId",
		},
		{
			name: "Azure vmId only",
			body: `{"vmId":"vm-1234"}`,
			want: "vmId",
		},
		{
			name: "DigitalOcean droplet_id",
			body: `{"droplet_id":12345,"hostname":"my-droplet"}`,
			want: "droplet_id",
		},
		{
			name: "instance-id embedded in longer string",
			body: "some-prefix-instance-id-suffix",
			want: "instance-id",
		},
		{
			name: "no false positive on unrelated JSON",
			body: `{"name":"test","value":"hello","count":42}`,
			want: "",
		},
		{
			name: "security-groups signal",
			body: "security-groups\nsg-12345678",
			want: "security-groups",
		},
		{
			name: "local-hostname signal",
			body: "local-hostname\nip-172-31-0-1.ec2.internal",
			want: "local-hostname",
		},
		{
			name: "instance/id GCP path",
			body: "instance/id\n1234567890",
			want: "instance/id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := metadataSignalFound(tt.body)
			if got != tt.want {
				t.Errorf("metadataSignalFound(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isMetadataRedirect unit tests
// ---------------------------------------------------------------------------

func TestIsMetadataRedirect(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     bool
	}{
		{
			name:     "AWS metadata IP",
			location: "http://169.254.169.254/latest/meta-data/",
			want:     true,
		},
		{
			name:     "Azure metadata IP",
			location: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			want:     true,
		},
		{
			name:     "GCP metadata hostname",
			location: "http://metadata.google.internal/computeMetadata/v1/",
			want:     true,
		},
		{
			name:     "Alibaba metadata IP",
			location: "http://100.100.100.200/latest/meta-data/",
			want:     true,
		},
		{
			name:     "normal URL",
			location: "https://example.com/page",
			want:     false,
		},
		{
			name:     "empty location",
			location: "",
			want:     false,
		},
		{
			name:     "relative path",
			location: "/login",
			want:     false,
		},
		{
			name:     "IP that looks similar but is not metadata",
			location: "http://169.254.169.253/something",
			want:     false,
		},
		{
			name:     "metadata IP embedded in path segment",
			location: "http://evil.com/?redirect=http://169.254.169.254/",
			want:     true,
		},
		{
			name:     "metadata IP with port",
			location: "http://169.254.169.254:80/latest/meta-data/",
			want:     true,
		},
		{
			name:     "GCP hostname in subdomain",
			location: "http://metadata.google.internal:8080/computeMetadata/v1/",
			want:     true,
		},
		{
			name:     "Oracle metadata uses same IP as AWS",
			location: "http://169.254.169.254/opc/v1/instance/",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMetadataRedirect(tt.location)
			if got != tt.want {
				t.Errorf("isMetadataRedirect(%q) = %v, want %v", tt.location, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectScheme unit tests
// ---------------------------------------------------------------------------

// TestDetectScheme_FallsBackToHTTP verifies that when HTTPS is not available,
// detectScheme returns "http".
func TestDetectScheme_FallsBackToHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	client := &http.Client{}
	asset := strings.TrimPrefix(srv.URL, "http://")

	// The asset is an HTTP-only test server; HTTPS will fail.
	scheme := detectScheme(context.Background(), client, asset)
	if scheme != "http" {
		t.Errorf("expected http for HTTP-only server, got %s", scheme)
	}
}

// TestDetectScheme_PrefersHTTPS verifies that when HTTPS is available,
// detectScheme returns "https".
func TestDetectScheme_PrefersHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	// Use the TLS test server's client which trusts the test CA.
	client := srv.Client()
	asset := strings.TrimPrefix(srv.URL, "https://")

	scheme := detectScheme(context.Background(), client, asset)
	if scheme != "https" {
		t.Errorf("expected https for TLS server, got %s", scheme)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

// TestSSRF_CancelledContext verifies that the scanner respects context
// cancellation gracefully (returns no error on cancelled context).
func TestSSRF_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ami-id: ami-12345")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(ctx, asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() should not error on cancelled context, got: %v", err)
	}
	// With a cancelled context, no HTTP requests succeed, so no findings.
	if len(findings) > 0 {
		t.Errorf("expected 0 findings with cancelled context, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Edge case: server returns 3xx with metadata signals in body
// ---------------------------------------------------------------------------

// TestSSRF_RedirectWithMetadataBody verifies that a redirect response whose
// body contains metadata signals does NOT produce a body-reflection SSRF
// finding (redirects are skipped in the body-reflection loop).
func TestSSRF_RedirectWithMetadataBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			w.Header().Set("Location", "http://169.254.169.254/latest/meta-data/")
			w.WriteHeader(http.StatusFound)
			// Sneaky: metadata in the redirect body.
			fmt.Fprintln(w, "ami-id: ami-12345")
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// The body-reflection SSRF check should skip 3xx responses.
	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrf) > 0 {
		t.Error("body-reflection SSRF should not fire on 3xx response, even if body has signals")
	}

	// But the redirect-to-metadata check SHOULD fire.
	redir := findingsByCheckID(findings, finding.CheckWebSSRFRedirectMetadata)
	if len(redir) == 0 {
		t.Error("redirect-to-metadata check should fire for redirect to metadata IP")
	}
}

// ---------------------------------------------------------------------------
// Edge case: server returns non-200 non-3xx status with metadata body
// ---------------------------------------------------------------------------

// TestSSRF_500WithMetadataBody verifies that a 500 response containing
// metadata signals IS detected as SSRF (only 3xx is skipped).
func TestSSRF_500WithMetadataBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Error occurred. Debug: ami-id=ami-12345 instance-id=i-abc")
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrf) == 0 {
		t.Fatal("expected SSRF finding even with 500 status when body has metadata signals")
	}
}

// ---------------------------------------------------------------------------
// Scanner metadata
// ---------------------------------------------------------------------------

func TestScanner_Name(t *testing.T) {
	s := New()
	if s.Name() != "ssrf" {
		t.Errorf("Name() = %q, want %q", s.Name(), "ssrf")
	}
}

// ---------------------------------------------------------------------------
// Edge case: very large response body — scanner must not OOM (64 KB limit)
// ---------------------------------------------------------------------------

func TestSSRF_LargeResponseBody_NoOOM(t *testing.T) {
	// Serve a response much larger than 64 KB. The scanner must cap
	// the body read at maxBodySize and not consume unbounded memory.
	bigBody := strings.Repeat("x", 256*1024) // 256 KB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, bigBody)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// No metadata signals in the body, so no findings expected.
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSRF {
			t.Errorf("unexpected SSRF finding on non-metadata large body: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case: empty response body — no crash, no finding
// ---------------------------------------------------------------------------

func TestSSRF_EmptyResponse_NoCrash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Intentionally empty body.
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSRF {
			t.Errorf("unexpected SSRF finding on empty body: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// False positive: server reflecting the payload URL itself (not metadata)
// ---------------------------------------------------------------------------

func TestSSRF_URLReflectedNotMetadata_NoFinding(t *testing.T) {
	// Server that echoes back the URL parameter value but does NOT fetch it
	// (i.e. it reflects the URL, not the metadata content). The metadata
	// signals are substrings of the URL, not of metadata content. The scanner
	// should NOT fire because the metadataSignals list was curated to avoid
	// matching payload URL substrings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			// Echo the URL back, not the fetched content.
			fmt.Fprintf(w, "You requested: %s\n", urlParam)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrf) > 0 {
		t.Errorf("expected no body-reflection SSRF when server only echoes the URL (not metadata content), got %d", len(ssrf))
	}
}

// ---------------------------------------------------------------------------
// Edge case: server returns 3xx for all requests (redirect to login)
// ---------------------------------------------------------------------------

func TestSSRF_All3xxResponses_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// No metadata IPs in the redirect Location, so no redirect-metadata finding.
	// And 3xx is skipped for body reflection.
	ssrf := findingsByCheckID(findings, finding.CheckWebSSRF)
	if len(ssrf) > 0 {
		t.Error("body-reflection SSRF should never fire on 3xx responses")
	}
}
