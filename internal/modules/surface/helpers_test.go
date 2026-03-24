package surface

import (
	"context"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	sc "github.com/stormbane/beacon/internal/scanner"
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
	reason := scannerSkipReason("nuclei", module.ScanSurface, false, false, "", "", nil, scanners)
	if reason != "scanner_not_registered" {
		t.Errorf("got %q; want scanner_not_registered", reason)
	}
}

func TestScannerSkipReasonNoHTTPSkipsHTTPDep(t *testing.T) {
	scanners := makeStubs("crawler", "screenshot")
	httpDep := map[string]bool{"crawler": true, "screenshot": true}
	reason := scannerSkipReason("crawler", module.ScanSurface, true /*noHTTP*/, false, "", "", httpDep, scanners)
	if reason != "no_http_service" {
		t.Errorf("got %q; want no_http_service", reason)
	}
}

func TestScannerSkipReasonHTTPServiceAllowsHTTPDep(t *testing.T) {
	scanners := makeStubs("crawler")
	httpDep := map[string]bool{"crawler": true}
	reason := scannerSkipReason("crawler", module.ScanSurface, false /*has HTTP*/, false, "", "", httpDep, scanners)
	if reason != "" {
		t.Errorf("expected no skip, got %q", reason)
	}
}

func TestScannerSkipReasonVhostBehindWAFNoOriginIP(t *testing.T) {
	// Behind WAF, no origin IP known — must skip to avoid probing CDN shared edge.
	scanners := makeStubs("vhost")
	reason := scannerSkipReason("vhost", module.ScanDeep, false, true /*behindWAF*/, "Cloudflare", "" /*no origin IP*/, nil, scanners)
	if reason != "behind_cdn_vhost_probe_unsafe" {
		t.Errorf("got %q; want behind_cdn_vhost_probe_unsafe", reason)
	}
}

func TestScannerSkipReasonVhostBehindWAFWithOriginIP(t *testing.T) {
	// Behind WAF but origin IP known — RunWithOriginIP probes origin directly, safe to run.
	scanners := makeStubs("vhost")
	reason := scannerSkipReason("vhost", module.ScanDeep, false, true /*behindWAF*/, "Cloudflare", "1.2.3.4" /*origin IP known*/, nil, scanners)
	if reason != "" {
		t.Errorf("vhost with known origin IP should not be skipped, got %q", reason)
	}
}

func TestScannerSkipReasonVhostDirectAsset(t *testing.T) {
	scanners := makeStubs("vhost")
	reason := scannerSkipReason("vhost", module.ScanDeep, false, false /*no WAF*/, "", "", nil, scanners)
	if reason != "" {
		t.Errorf("vhost on direct asset should not be skipped, got %q", reason)
	}
}

func TestScannerSkipReasonCDNBypassNoCDN(t *testing.T) {
	scanners := makeStubs("cdnbypass")
	reason := scannerSkipReason("cdnbypass", module.ScanSurface, false, false /*no CDN*/, "", "", nil, scanners)
	if reason != "no_cdn_detected" {
		t.Errorf("got %q; want no_cdn_detected", reason)
	}
}

func TestScannerSkipReasonCDNBypassBehindCDN(t *testing.T) {
	scanners := makeStubs("cdnbypass")
	reason := scannerSkipReason("cdnbypass", module.ScanSurface, false, true /*CDN detected*/, "Cloudflare", "", nil, scanners)
	if reason != "" {
		t.Errorf("cdnbypass behind CDN should not be skipped, got %q", reason)
	}
}

func TestScannerSkipReasonNonHTTPDepNotSkipped(t *testing.T) {
	scanners := makeStubs("email")
	reason := scannerSkipReason("email", module.ScanSurface, true /*noHTTP*/, false, "", "", map[string]bool{}, scanners)
	if reason != "" {
		t.Errorf("email is not HTTP-dependent; should not be skipped, got %q", reason)
	}
}

// ── saveScanMetric / saveScanMetricElapsed ────────────────────────────────────

func TestSaveScanMetricNilStoreNoOp(t *testing.T) {
	m := &Module{st: nil}
	// Should not panic when store is nil
	m.saveScanMetric(nil, "", "asset", "scanner", time.Now(), nil, nil)
	m.saveScanMetricElapsed(nil, "", "asset", "scanner", 0, nil, nil)
	m.saveSkipMetric(nil, "", "asset", "scanner", "test")
}

func TestSaveScanMetricEmptyRunIDNoOp(t *testing.T) {
	m := &Module{st: nil}
	// scanRunID="" should be a no-op even if store were set
	m.saveScanMetric(nil, "" /*scanRunID*/, "asset", "scanner", time.Now(), nil, nil)
}
