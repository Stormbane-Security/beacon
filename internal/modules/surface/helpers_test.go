package surface

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/playbook"
	sc "github.com/stormbane-security/beacon/internal/scanner"
)

// ── planContains ─────────────────────────────────────────────────────────────

func TestPlanContains(t *testing.T) {
	scanners := []string{"wafdetect", "portscan", "email", "tls"}

	tests := []struct {
		name string
		want bool
	}{
		{"wafdetect", true},
		{"portscan", true},
		{"email", true},
		{"tls", true},
		{"nuclei", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := planContains(scanners, tt.name); got != tt.want {
			t.Errorf("planContains(%q) = %v; want %v", tt.name, got, tt.want)
		}
	}
}

func TestPlanContainsEmpty(t *testing.T) {
	if planContains(nil, "wafdetect") {
		t.Error("planContains(nil, ...) should return false")
	}
	if planContains([]string{}, "wafdetect") {
		t.Error("planContains(empty, ...) should return false")
	}
}

// ── extractWAFInfo ────────────────────────────────────────────────────────────

func TestExtractWAFInfoDetected(t *testing.T) {
	findings := []finding.Finding{
		{
			CheckID:  finding.CheckWAFDetected,
			Evidence: map[string]any{"vendor": "Cloudflare", "scheme": "https"},
		},
	}
	behind, vendor := extractWAFInfo(findings)
	if !behind {
		t.Error("expected behindWAF=true")
	}
	if vendor != "Cloudflare" {
		t.Errorf("vendor = %q; want Cloudflare", vendor)
	}
}

func TestExtractWAFInfoNotDetected(t *testing.T) {
	findings := []finding.Finding{
		{
			CheckID:  finding.CheckPortSSHExposed,
			Evidence: map[string]any{"port": 22},
		},
	}
	behind, vendor := extractWAFInfo(findings)
	if behind {
		t.Error("expected behindWAF=false with no WAF finding")
	}
	if vendor != "" {
		t.Errorf("vendor = %q; want empty", vendor)
	}
}

func TestExtractWAFInfoEmpty(t *testing.T) {
	behind, vendor := extractWAFInfo(nil)
	if behind || vendor != "" {
		t.Error("extractWAFInfo(nil) should return (false, \"\")")
	}
}

func TestExtractWAFInfoVendorMissing(t *testing.T) {
	findings := []finding.Finding{
		{
			CheckID:  finding.CheckWAFDetected,
			Evidence: map[string]any{}, // no vendor key
		},
	}
	behind, vendor := extractWAFInfo(findings)
	if !behind {
		t.Error("expected behindWAF=true even without vendor key")
	}
	if vendor != "" {
		t.Errorf("vendor = %q; want empty", vendor)
	}
}

// ── extractOpenPorts ──────────────────────────────────────────────────────────

func TestExtractOpenPortsIntType(t *testing.T) {
	findings := []finding.Finding{
		{
			Scanner:  "portscan",
			Evidence: map[string]any{"port": 6379, "service": "redis"},
		},
		{
			Scanner:  "portscan",
			Evidence: map[string]any{"port": 9200, "service": "elasticsearch"},
		},
	}
	ports := extractOpenPorts(findings)
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	if ports[6379] != "redis" {
		t.Errorf("port 6379 service = %q; want redis", ports[6379])
	}
	if ports[9200] != "elasticsearch" {
		t.Errorf("port 9200 service = %q; want elasticsearch", ports[9200])
	}
}

func TestExtractOpenPortsFloat64Type(t *testing.T) {
	// JSON unmarshaling produces float64 for numbers — verify both types work.
	findings := []finding.Finding{
		{
			Scanner:  "portscan",
			Evidence: map[string]any{"port": float64(22), "service": "ssh"},
		},
	}
	ports := extractOpenPorts(findings)
	if ports[22] != "ssh" {
		t.Errorf("float64 port key: got %q; want ssh", ports[22])
	}
}

func TestExtractOpenPortsIgnoresOtherScanners(t *testing.T) {
	findings := []finding.Finding{
		{Scanner: "email", Evidence: map[string]any{"port": 25, "service": "smtp"}},
		{Scanner: "portscan", Evidence: map[string]any{"port": 443, "service": "https"}},
	}
	ports := extractOpenPorts(findings)
	if _, ok := ports[25]; ok {
		t.Error("port 25 from email scanner should be excluded")
	}
	if _, ok := ports[443]; !ok {
		t.Error("port 443 from portscan should be included")
	}
}

func TestExtractOpenPortsSkipsMissingPortKey(t *testing.T) {
	findings := []finding.Finding{
		{Scanner: "portscan", Evidence: map[string]any{"service": "unknown"}}, // no "port" key
	}
	ports := extractOpenPorts(findings)
	if len(ports) != 0 {
		t.Errorf("expected empty map, got %v", ports)
	}
}

// ── scannerSkipReason ─────────────────────────────────────────────────────────

// stubScanner is a minimal no-op sc.Scanner for testing the registry presence check.
type stubScanner struct{ name string }

func (s *stubScanner) Run(_ context.Context, _ string, _ module.ScanType) ([]finding.Finding, error) {
	return nil, nil
}
func (s *stubScanner) Name() string { return s.name }

func makeStubs(names ...string) map[string]sc.Scanner {
	m := make(map[string]sc.Scanner, len(names))
	for _, n := range names {
		m[n] = &stubScanner{n}
	}
	return m
}

func TestScannerSkipReasonNotRegistered(t *testing.T) {
	scanners := makeStubs("email", "tls")
	reason := scannerSkipReason("nuclei", module.ScanSurface, false, false, "", "", nil, scanners, ServiceClassUnknown)
	if reason != "scanner_not_registered" {
		t.Errorf("got %q; want scanner_not_registered", reason)
	}
}

func TestScannerSkipReasonNoHTTPSkipsHTTPDep(t *testing.T) {
	scanners := makeStubs("crawler", "screenshot")
	httpDep := map[string]bool{"crawler": true, "screenshot": true}
	reason := scannerSkipReason("crawler", module.ScanSurface, true /*noHTTP*/, false, "", "", httpDep, scanners, ServiceClassUnknown)
	if reason != "no_http_service" {
		t.Errorf("got %q; want no_http_service", reason)
	}
}

func TestScannerSkipReasonHTTPServiceAllowsHTTPDep(t *testing.T) {
	scanners := makeStubs("crawler")
	httpDep := map[string]bool{"crawler": true}
	reason := scannerSkipReason("crawler", module.ScanSurface, false /*has HTTP*/, false, "", "", httpDep, scanners, ServiceClassUnknown)
	if reason != "" {
		t.Errorf("expected no skip, got %q", reason)
	}
}

func TestScannerSkipReasonVhostBehindWAFNoOriginIP(t *testing.T) {
	// Behind WAF, no origin IP known — must skip to avoid probing CDN shared edge.
	scanners := makeStubs("vhost")
	reason := scannerSkipReason("vhost", module.ScanDeep, false, true /*behindWAF*/, "Cloudflare", "" /*no origin IP*/, nil, scanners, ServiceClassUnknown)
	if reason != "behind_cdn_vhost_probe_unsafe" {
		t.Errorf("got %q; want behind_cdn_vhost_probe_unsafe", reason)
	}
}

func TestScannerSkipReasonVhostBehindWAFWithOriginIP(t *testing.T) {
	// Behind WAF but origin IP known — RunWithOriginIP probes origin directly, safe to run.
	scanners := makeStubs("vhost")
	reason := scannerSkipReason("vhost", module.ScanDeep, false, true /*behindWAF*/, "Cloudflare", "1.2.3.4" /*origin IP known*/, nil, scanners, ServiceClassUnknown)
	if reason != "" {
		t.Errorf("vhost with known origin IP should not be skipped, got %q", reason)
	}
}

func TestScannerSkipReasonVhostDirectAsset(t *testing.T) {
	scanners := makeStubs("vhost")
	reason := scannerSkipReason("vhost", module.ScanDeep, false, false /*no WAF*/, "", "", nil, scanners, ServiceClassUnknown)
	if reason != "" {
		t.Errorf("vhost on direct asset should not be skipped, got %q", reason)
	}
}

func TestScannerSkipReasonCDNBypassNoCDN(t *testing.T) {
	scanners := makeStubs("cdnbypass")
	reason := scannerSkipReason("cdnbypass", module.ScanSurface, false, false /*no CDN*/, "", "", nil, scanners, ServiceClassUnknown)
	if reason != "no_cdn_detected" {
		t.Errorf("got %q; want no_cdn_detected", reason)
	}
}

func TestScannerSkipReasonCDNBypassBehindCDN(t *testing.T) {
	scanners := makeStubs("cdnbypass")
	reason := scannerSkipReason("cdnbypass", module.ScanSurface, false, true /*CDN detected*/, "Cloudflare", "", nil, scanners, ServiceClassUnknown)
	if reason != "" {
		t.Errorf("cdnbypass behind CDN should not be skipped, got %q", reason)
	}
}

func TestScannerSkipReasonNonHTTPDepNotSkipped(t *testing.T) {
	scanners := makeStubs("email")
	reason := scannerSkipReason("email", module.ScanSurface, true /*noHTTP*/, false, "", "", map[string]bool{}, scanners, ServiceClassUnknown)
	if reason != "" {
		t.Errorf("email is not HTTP-dependent; should not be skipped, got %q", reason)
	}
}

// ── Service classification ───────────────────────────────────────────────────

func TestClassifyServiceDatabase(t *testing.T) {
	ports := map[int]string{5984: "couchdb", 80: "http"}
	if got := classifyService(ports); got != ServiceClassDatabase {
		t.Errorf("got %d; want ServiceClassDatabase", got)
	}
}

func TestClassifyServiceRedis(t *testing.T) {
	ports := map[int]string{6379: "redis"}
	if got := classifyService(ports); got != ServiceClassDatabase {
		t.Errorf("got %d; want ServiceClassDatabase", got)
	}
}

func TestClassifyServiceMessageQueue(t *testing.T) {
	ports := map[int]string{5672: "rabbitmq"}
	if got := classifyService(ports); got != ServiceClassMessageQueue {
		t.Errorf("got %d; want ServiceClassMessageQueue", got)
	}
}

func TestClassifyServiceInfra(t *testing.T) {
	ports := map[int]string{2375: "docker"}
	if got := classifyService(ports); got != ServiceClassInfra {
		t.Errorf("got %d; want ServiceClassInfra", got)
	}
}

func TestClassifyServiceMonitoring(t *testing.T) {
	ports := map[int]string{3000: "grafana"}
	if got := classifyService(ports); got != ServiceClassMonitoring {
		t.Errorf("got %d; want ServiceClassMonitoring", got)
	}
}

func TestClassifyServiceCICD(t *testing.T) {
	ports := map[int]string{8080: "jenkins"}
	if got := classifyService(ports); got != ServiceClassCICD {
		t.Errorf("got %d; want ServiceClassCICD", got)
	}
}

func TestClassifyServiceUnknown(t *testing.T) {
	ports := map[int]string{80: "http", 443: ""}
	if got := classifyService(ports); got != ServiceClassUnknown {
		t.Errorf("got %d; want ServiceClassUnknown", got)
	}
}

func TestClassifyServiceEmpty(t *testing.T) {
	if got := classifyService(nil); got != ServiceClassUnknown {
		t.Errorf("got %d; want ServiceClassUnknown", got)
	}
}

func TestScannerSkipReasonDatabaseSkipsGraphQL(t *testing.T) {
	scanners := makeStubs("graphql")
	reason := scannerSkipReason("graphql", module.ScanSurface, false, false, "", "", nil, scanners, ServiceClassDatabase)
	if reason != "service_type_mismatch" {
		t.Errorf("got %q; want service_type_mismatch", reason)
	}
}

func TestScannerSkipReasonDatabaseAllowsNuclei(t *testing.T) {
	scanners := makeStubs("nuclei")
	reason := scannerSkipReason("nuclei", module.ScanSurface, false, false, "", "", nil, scanners, ServiceClassDatabase)
	if reason != "" {
		t.Errorf("nuclei should not be skipped for databases, got %q", reason)
	}
}

func TestScannerSkipReasonWebAppAllowsAll(t *testing.T) {
	scanners := makeStubs("graphql", "cors", "crawler")
	for _, name := range []string{"graphql", "cors", "crawler"} {
		reason := scannerSkipReason(name, module.ScanSurface, false, false, "", "", nil, scanners, ServiceClassWebApp)
		if reason != "" {
			t.Errorf("WebApp should allow %s, got %q", name, reason)
		}
	}
}

func TestScannerSkipReasonUnknownAllowsAll(t *testing.T) {
	scanners := makeStubs("graphql", "cors")
	for _, name := range []string{"graphql", "cors"} {
		reason := scannerSkipReason(name, module.ScanSurface, false, false, "", "", nil, scanners, ServiceClassUnknown)
		if reason != "" {
			t.Errorf("Unknown should allow %s, got %q", name, reason)
		}
	}
}

// ── saveScanMetric / saveScanMetricElapsed ────────────────────────────────────

func TestSaveScanMetricNilStoreNoOp(t *testing.T) {
	m := &Module{st: nil}
	// Should not panic when store is nil
	m.saveScanMetricElapsed(context.TODO(), "", "asset", "scanner", 0, nil, nil)
	m.saveSkipMetric(context.TODO(), "", "asset", "scanner", "test")
}

func TestSaveScanMetricEmptyRunIDNoOp(t *testing.T) {
	m := &Module{st: nil}
	// scanRunID="" should be a no-op even if store were set
	m.saveScanMetricElapsed(context.TODO(), "" /*scanRunID*/, "asset", "scanner", 0, nil, nil)
}

// ── enrichEvidenceFromFindings ───────────────────────────────────────────────

func TestEnrichEvidenceFromFindings_ExternalServices(t *testing.T) {
	ev := &playbook.Evidence{}
	findings := []finding.Finding{
		{
			CheckID:  finding.CheckJSExternalServiceRef,
			Evidence: map[string]any{"service": "Stripe API", "category": "payments"},
		},
		{
			CheckID:  finding.CheckJSExternalServiceRef,
			Evidence: map[string]any{"service": "Helius RPC (Solana)", "category": "blockchain"},
		},
		// Duplicate — should not appear twice
		{
			CheckID:  finding.CheckJSExternalServiceRef,
			Evidence: map[string]any{"service": "Stripe API", "category": "payments"},
		},
	}

	enrichEvidenceFromFindings(ev, findings)

	if len(ev.ExternalServices) != 2 {
		t.Fatalf("expected 2 external services, got %d: %v", len(ev.ExternalServices), ev.ExternalServices)
	}
	want := map[string]bool{"Stripe API": true, "Helius RPC (Solana)": true}
	for _, svc := range ev.ExternalServices {
		if !want[svc] {
			t.Errorf("unexpected service: %s", svc)
		}
	}
}

func TestEnrichEvidenceFromFindings_MixedCheckIDs(t *testing.T) {
	ev := &playbook.Evidence{}
	findings := []finding.Finding{
		{
			CheckID:  finding.CheckJSExternalServiceRef,
			Evidence: map[string]any{"service": "Auth0", "category": "auth"},
		},
		{
			CheckID:  finding.CheckPortGRPCReflectionEnabled,
			Evidence: map[string]any{},
		},
		{
			CheckID:  finding.CheckJSFrameworkDetected,
			Evidence: map[string]any{"framework": "nextjs"},
		},
	}

	enrichEvidenceFromFindings(ev, findings)

	if len(ev.ExternalServices) != 1 || ev.ExternalServices[0] != "Auth0" {
		t.Errorf("expected [Auth0], got %v", ev.ExternalServices)
	}
	if !ev.GRPCReflection {
		t.Error("expected GRPCReflection=true")
	}
	if ev.Framework != "nextjs" {
		t.Errorf("expected framework=nextjs, got %s", ev.Framework)
	}
}
