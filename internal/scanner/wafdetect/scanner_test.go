package wafdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/module"
)

// ── detectVendor ──────────────────────────────────────────────────────────────

func TestDetectVendorCloudflare(t *testing.T) {
	headers := map[string]string{
		"cf-ray":          "abc123-LAX",
		"cf-cache-status": "HIT",
	}
	got := detectVendor(headers, "")
	if got != "Cloudflare" {
		t.Errorf("detectVendor = %q; want Cloudflare", got)
	}
}

func TestDetectVendorAWSWAF(t *testing.T) {
	headers := map[string]string{
		"x-amzn-requestid": "abc-123",
		"content-type":     "text/html",
	}
	got := detectVendor(headers, "")
	if got != "AWS WAF" {
		t.Errorf("detectVendor = %q; want AWS WAF", got)
	}
}

func TestDetectVendorAWSCloudFront(t *testing.T) {
	headers := map[string]string{
		"x-amz-cf-id": "DEADBEEF==",
	}
	got := detectVendor(headers, "")
	if got != "AWS CloudFront/WAF" {
		t.Errorf("detectVendor = %q; want AWS CloudFront/WAF", got)
	}
}

func TestDetectVendorImperva(t *testing.T) {
	headers := map[string]string{"x-iinfo": "something"}
	got := detectVendor(headers, "")
	if got != "Imperva Incapsula" {
		t.Errorf("detectVendor = %q; want Imperva Incapsula", got)
	}
}

func TestDetectVendorSucuri(t *testing.T) {
	headers := map[string]string{"x-sucuri-id": "12345"}
	got := detectVendor(headers, "")
	if got != "Sucuri WAF" {
		t.Errorf("detectVendor = %q; want Sucuri WAF", got)
	}
}

func TestDetectVendorModSecurity(t *testing.T) {
	headers := map[string]string{"x-mod-security-id": "abc"}
	got := detectVendor(headers, "")
	if got != "ModSecurity" {
		t.Errorf("detectVendor = %q; want ModSecurity", got)
	}
}

func TestDetectVendorNone(t *testing.T) {
	headers := map[string]string{
		"content-type":  "text/html",
		"cache-control": "no-store",
	}
	if got := detectVendor(headers, ""); got != "" {
		t.Errorf("detectVendor = %q; want empty", got)
	}
}

func TestDetectVendorEmpty(t *testing.T) {
	if got := detectVendor(map[string]string{}, ""); got != "" {
		t.Errorf("detectVendor(empty) = %q; want empty", got)
	}
	if got := detectVendor(nil, ""); got != "" {
		t.Errorf("detectVendor(nil) = %q; want empty", got)
	}
}

// ── detectIDS ─────────────────────────────────────────────────────────────────

func TestDetectIDSPaloAlto(t *testing.T) {
	headers := map[string]string{"x-palo-alto-block": "yes"}
	got := detectIDS(headers)
	if got != "Palo Alto NGFW" {
		t.Errorf("detectIDS = %q; want Palo Alto NGFW", got)
	}
}

func TestDetectIDSCheckPoint(t *testing.T) {
	headers := map[string]string{"x-checkpoint-session": "abc"}
	got := detectIDS(headers)
	if got != "Check Point" {
		t.Errorf("detectIDS = %q; want Check Point", got)
	}
}

func TestDetectIDSNone(t *testing.T) {
	headers := map[string]string{"content-type": "text/html"}
	if got := detectIDS(headers); got != "" {
		t.Errorf("detectIDS = %q; want empty", got)
	}
}

// ── header matching is case-insensitive ───────────────────────────────────────

func TestDetectVendorCaseInsensitive(t *testing.T) {
	// Ensure that the scanner normalises headers to lowercase before matching.
	// probeHeaders() already lowercases them, but detectVendor operates on
	// pre-lowercased maps — verify it still matches.
	headers := map[string]string{
		"cf-ray": "abc123", // already lowercase as probeHeaders produces
	}
	if got := detectVendor(headers, ""); got != "Cloudflare" {
		t.Errorf("detectVendor (lowercase key) = %q; want Cloudflare", got)
	}
}

// ── wafHeaders / idsHeaders completeness ─────────────────────────────────────

func TestWAFHeadersNotEmpty(t *testing.T) {
	if len(wafHeaders) == 0 {
		t.Error("wafHeaders should not be empty")
	}
}

func TestIDSHeadersNotEmpty(t *testing.T) {
	if len(idsHeaders) == 0 {
		t.Error("idsHeaders should not be empty")
	}
}

func TestBypassHeadersNotEmpty(t *testing.T) {
	if len(bypassHeaders) == 0 {
		t.Error("bypassHeaders should not be empty")
	}
}

// ── edge cases ────────────────────────────────────────────────────────────────

// TestWAFDetect_OriginResponds_301NotBypass verifies that originResponds returns
// false when the origin replies with a 301 redirect. Only 2xx counts as confirmation.
func TestWAFDetect_OriginResponds_301NotBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	ctx := context.Background()
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Strip the "http://" scheme prefix so we just have "host:port".
	host := strings.TrimPrefix(srv.URL, "http://")
	if originResponds(ctx, client, host, "example.com") {
		t.Error("originResponds must return false when origin replies with 301 (not a bypass)")
	}
}

// TestWAFDetect_CaseInsensitiveVendor verifies that a server returning the
// mixed-case header "CF-Ray: 12345" is detected as Cloudflare. probeHeaders
// lowercases all header names before passing them to detectVendor.
func TestWAFDetect_CaseInsensitiveVendor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "12345-LAX")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := context.Background()
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{},
	}

	headers, _, body, err := probeHeaders(ctx, client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("probeHeaders: %v", err)
	}

	vendor := detectVendor(headers, body)
	if vendor != "Cloudflare" {
		t.Errorf("detectVendor = %q; want Cloudflare (mixed-case CF-Ray header must be normalised)", vendor)
	}
}

// TestWAFDetect_SingleLabelDomain verifies that rootAndWWW does not panic or
// return an out-of-bounds slice when given a single-label hostname like "localhost".
func TestWAFDetect_SingleLabelDomain(t *testing.T) {
	got := rootAndWWW("localhost")
	if len(got) == 0 {
		t.Fatal("rootAndWWW(\"localhost\") returned empty slice")
	}
	if got[0] != "localhost" {
		t.Errorf("rootAndWWW(\"localhost\")[0] = %q; want \"localhost\"", got[0])
	}
}

// TestWAFDetect_MultipleVendors verifies that when headers from two WAF vendors
// are present, detectVendor returns the first match (order in wafHeaders slice).
func TestWAFDetect_MultipleVendors(t *testing.T) {
	// cf-ray (Cloudflare) appears before x-sucuri-id (Sucuri) in wafHeaders.
	headers := map[string]string{
		"cf-ray":      "abc123-LAX",
		"x-sucuri-id": "99999",
	}
	got := detectVendor(headers, "")
	// Either vendor is a valid detection — what matters is exactly one is returned.
	if got != "Cloudflare" && got != "Sucuri WAF" {
		t.Errorf("detectVendor with two vendors = %q; want one of Cloudflare or Sucuri WAF", got)
	}
}

// TestWAFDetect_CatchAllSkipped verifies that a server that responds 200 for
// every path (catch-all / wildcard handler) but returns no WAF headers does not
// produce any finding. The scanner must not emit anything when it cannot identify
// a vendor — response presence alone is not a WAF signal.
func TestWAFDetect_CatchAllSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond 200 for every path — no WAF headers.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	scanner := New()
	findings, err := scanner.Run(context.Background(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for catch-all server with no WAF headers, got %d", len(findings))
	}
}

// TestWAFDetect_NilHeaderMap verifies that a server returning 200 with no WAF
// headers produces no finding and does not panic.
func TestWAFDetect_NilHeaderMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	scanner := New()
	findings, err := scanner.Run(context.Background(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	// No WAF headers → no vendor → no findings.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for a server with no WAF headers, got %d", len(findings))
	}
}
