package honeypot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

// ctxWithScanContext returns a context with a ScanContext injected, plus
// the ScanContext itself for inspection.
func ctxWithScanContext(asset string) (context.Context, *scan.ScanContext) {
	sctx := scan.NewContext(asset, module.ScanSurface)
	return sctx.Inject(context.Background()), sctx
}

func TestNoHoneypotSignals(t *testing.T) {
	// A single plain HTTP service with no honeypot indicators → no findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = fmt.Fprintln(w, "<html><body>Welcome</body></html>")
	}))
	defer srv.Close()

	// Extract host:port from the test server so the scanner hits it.
	s := New()
	ctx, _ := ctxWithScanContext(srv.Listener.Addr().String())
	findings, err := s.Run(ctx, srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) > 0 {
		t.Errorf("expected no findings for a normal server, got %d: %v", len(findings), findings)
	}
}

func TestManyServicesHeuristic(t *testing.T) {
	// Simulate 12 open ports via the aggregateIndicators path.
	// The scanner itself can't discover ports without portscan data, so we
	// test the aggregation logic directly.
	indicators := []HoneypotIndicator{
		{
			Name:       "generic",
			Confidence: 0.5,
			Signals:    []string{"12 open services on single host (threshold: 10)"},
		},
	}

	best := aggregateIndicators(indicators)
	if best.Confidence < 0.3 {
		t.Errorf("expected confidence > 0.3 for many-service heuristic, got %.2f", best.Confidence)
	}
	if best.Name != "generic" {
		t.Errorf("expected name 'generic', got %q", best.Name)
	}
}

func TestConpotHTTPSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "conpot/0.6.0")
		_, _ = fmt.Fprintln(w, `<html><head><title>Siemens, SIMATIC HMI</title></head><body>Siemens, SIMATIC S7-200</body></html>`)
	}))
	defer srv.Close()

	s := New()
	ctx, sctx := ctxWithScanContext(srv.Listener.Addr().String())
	_ = sctx // available for inspection

	findings, err := s.Run(ctx, srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect conpot from both the "Siemens, SIMATIC" body pattern
	// and the "conpot" Server header — combined confidence should be > 0.7.
	var detected bool
	for _, f := range findings {
		if f.CheckID == finding.CheckHoneypotDetected {
			detected = true
			if f.Evidence["honeypot_name"] != "conpot" {
				t.Errorf("expected honeypot_name 'conpot', got %v", f.Evidence["honeypot_name"])
			}
		}
	}
	if !detected {
		t.Error("expected CheckHoneypotDetected finding for Conpot signature, got none")
		for _, f := range findings {
			t.Logf("  finding: %s — %s (confidence: %v)", f.CheckID, f.Title, f.Evidence["confidence"])
		}
	}
}

func TestCowrieSSHBanner(t *testing.T) {
	// Test the SSH banner matching logic directly since we can't easily
	// stand up a fake SSH server in a unit test.
	banners := map[int]string{
		22: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
	}

	var indicators []HoneypotIndicator
	for port, banner := range banners {
		for _, sig := range honeypotSSHBanners {
			if banner == sig.Banner {
				indicators = append(indicators, HoneypotIndicator{
					Name:       sig.Name,
					Confidence: 0.8,
					Signals: []string{
						fmt.Sprintf("SSH banner on port %d matches known %s signature: %q", port, sig.Name, banner),
					},
				})
			}
		}
	}

	if len(indicators) == 0 {
		t.Fatal("expected Cowrie indicator from SSH banner, got none")
	}

	best := aggregateIndicators(indicators)
	if best.Name != "cowrie" {
		t.Errorf("expected name 'cowrie', got %q", best.Name)
	}
	if best.Confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7 for Cowrie SSH banner, got %.2f", best.Confidence)
	}
}

func TestHoneypotFlagPropagation(t *testing.T) {
	// When a high-confidence honeypot is detected, the scanner should set
	// the honeypot flag on the scan context.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "conpot/0.6.0")
		_, _ = fmt.Fprintln(w, `<html><body>Siemens, SIMATIC HMI Panel</body></html>`)
	}))
	defer srv.Close()

	s := New()
	ctx, sctx := ctxWithScanContext(srv.Listener.Addr().String())

	_, err := s.Run(ctx, srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !sctx.HoneypotDetected() {
		t.Error("expected HoneypotDetected() == true after high-confidence detection")
	}
}

func TestAggregateIndicators_CombinesConfidence(t *testing.T) {
	indicators := []HoneypotIndicator{
		{Name: "cowrie", Confidence: 0.5, Signals: []string{"signal A"}},
		{Name: "cowrie", Confidence: 0.5, Signals: []string{"signal B"}},
	}

	best := aggregateIndicators(indicators)
	// P(A or B) = 1 - (1-0.5)(1-0.5) = 0.75
	if best.Confidence < 0.74 || best.Confidence > 0.76 {
		t.Errorf("expected combined confidence ~0.75, got %.2f", best.Confidence)
	}
	if len(best.Signals) != 2 {
		t.Errorf("expected 2 signals, got %d", len(best.Signals))
	}
}

func TestAggregateIndicators_PicksHighest(t *testing.T) {
	indicators := []HoneypotIndicator{
		{Name: "cowrie", Confidence: 0.3, Signals: []string{"SSH banner"}},
		{Name: "conpot", Confidence: 0.85, Signals: []string{"HTTP body"}},
	}

	best := aggregateIndicators(indicators)
	if best.Name != "conpot" {
		t.Errorf("expected highest-confidence indicator 'conpot', got %q", best.Name)
	}
}

func TestAggregateIndicators_CapsAt99(t *testing.T) {
	indicators := []HoneypotIndicator{
		{Name: "conpot", Confidence: 0.95, Signals: []string{"A"}},
		{Name: "conpot", Confidence: 0.95, Signals: []string{"B"}},
		{Name: "conpot", Confidence: 0.95, Signals: []string{"C"}},
	}

	best := aggregateIndicators(indicators)
	if best.Confidence > 0.99 {
		t.Errorf("expected confidence capped at 0.99, got %.4f", best.Confidence)
	}
}

func TestScanContextHoneypotDefault(t *testing.T) {
	sctx := scan.NewContext("example.com", module.ScanSurface)
	if sctx.HoneypotDetected() {
		t.Error("expected HoneypotDetected() == false by default")
	}

	sctx.SetHoneypotDetected(true)
	if !sctx.HoneypotDetected() {
		t.Error("expected HoneypotDetected() == true after SetHoneypotDetected(true)")
	}
}
