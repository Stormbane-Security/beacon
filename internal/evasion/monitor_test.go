package evasion

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// mockBody returns an http.Response with the given status code and body text.
func mockResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestCheckResponse_RateLimit429(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/api"

	// Establish baseline.
	m.CheckResponse(url, mockResponse(200, "ok"), 100*time.Millisecond)

	// Trigger rate limit.
	det := m.CheckResponse(url, mockResponse(429, "too many requests"), 100*time.Millisecond)
	if det == nil {
		t.Fatal("expected rate limit detection, got nil")
	}
	if det.Type != DetectionRateLimit {
		t.Fatalf("expected type %s, got %s", DetectionRateLimit, det.Type)
	}
	if !m.RateLimited() {
		t.Fatal("expected RateLimited() to be true")
	}
}

func TestCheckResponse_RateLimit503AfterSuccess(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/page"

	// Establish baseline with 200.
	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)

	// 503 after 200 → rate limit.
	det := m.CheckResponse(url, mockResponse(503, "service unavailable"), 50*time.Millisecond)
	if det == nil {
		t.Fatal("expected rate limit detection, got nil")
	}
	if det.Type != DetectionRateLimit {
		t.Fatalf("expected type %s, got %s", DetectionRateLimit, det.Type)
	}
}

func TestCheckResponse_503WithoutBaseline(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/new"

	// 503 without prior success → not rate limiting (server may just be down).
	det := m.CheckResponse(url, mockResponse(503, "service unavailable"), 50*time.Millisecond)
	if det != nil {
		t.Fatalf("expected no detection for 503 without baseline, got %s", det.Type)
	}
}

func TestCheckResponse_IPBlock(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/target"

	// Establish baseline.
	m.CheckResponse(url, mockResponse(200, "ok"), 100*time.Millisecond)

	// Connection failure (nil resp) after prior success → IP block.
	det := m.CheckResponse(url, nil, 5*time.Second)
	if det == nil {
		t.Fatal("expected IP block detection, got nil")
	}
	if det.Type != DetectionIPBlock {
		t.Fatalf("expected type %s, got %s", DetectionIPBlock, det.Type)
	}
	if !m.Blocked() {
		t.Fatal("expected Blocked() to be true")
	}
}

func TestCheckResponse_IPBlockNoBaseline(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/never-seen"

	// Connection failure without prior success → no detection.
	det := m.CheckResponse(url, nil, 5*time.Second)
	if det != nil {
		t.Fatalf("expected no detection without baseline, got %s", det.Type)
	}
}

func TestCheckResponse_CAPTCHA(t *testing.T) {
	signals := []string{
		"Please complete the captcha below",
		"<div class=\"challenge\">Verify you are human</div>",
		"<script src=\"https://www.google.com/recaptcha/api.js\"></script>",
		"<div class=\"hcaptcha\" data-sitekey=\"abc\"></div>",
		"<script src=\"/cdn-cgi/challenge-platform/scripts/cf-turnstile\"></script>",
	}
	for _, body := range signals {
		m := NewMonitor(nil)
		url := "https://example.com/login"

		det := m.CheckResponse(url, mockResponse(200, body), 100*time.Millisecond)
		if det == nil {
			t.Fatalf("expected CAPTCHA detection for body containing signal, got nil; body=%q", body[:30])
		}
		if det.Type != DetectionCAPTCHA {
			t.Fatalf("expected type %s, got %s", DetectionCAPTCHA, det.Type)
		}
		if !m.CaptchaDetected() {
			t.Fatal("expected CaptchaDetected() to be true")
		}
	}
}

func TestCheckResponse_WAFChallenge(t *testing.T) {
	signals := []struct {
		body string
		sig  string
	}{
		{"<p>Please wait while we perform a security check</p>", "security check"},
		{"<span>Ray ID: abc123</span>", "ray id"},
		{"<title>Attention Required! | Cloudflare</title>", "cloudflare"},
		{"<meta name=\"generator\" content=\"Akamai Bot Manager\"/>", "akamai"},
	}
	for _, tc := range signals {
		m := NewMonitor(nil)
		url := "https://example.com/app"

		det := m.CheckResponse(url, mockResponse(403, tc.body), 100*time.Millisecond)
		if det == nil {
			t.Fatalf("expected WAF detection for signal %q, got nil", tc.sig)
		}
		if det.Type != DetectionWAFChallenge {
			t.Fatalf("expected type %s, got %s for signal %q", DetectionWAFChallenge, det.Type, tc.sig)
		}
	}
}

func TestCheckResponse_Tarpit(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/slow"

	// Build up baseline with fast responses.
	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)
	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)
	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)

	// Response that is >10x the baseline average → tarpit.
	det := m.CheckResponse(url, mockResponse(200, "ok"), 600*time.Millisecond)
	if det == nil {
		t.Fatal("expected tarpit detection, got nil")
	}
	if det.Type != DetectionTarpit {
		t.Fatalf("expected type %s, got %s", DetectionTarpit, det.Type)
	}
	if !m.TarpitDetected() {
		t.Fatal("expected TarpitDetected() to be true")
	}
}

func TestCheckResponse_NoTarpitWithFewSamples(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/single"

	// Only one baseline sample — not enough for tarpit detection.
	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)

	det := m.CheckResponse(url, mockResponse(200, "ok"), 600*time.Millisecond)
	if det != nil {
		t.Fatalf("expected no tarpit detection with only 1 baseline sample, got %s", det.Type)
	}
}

func TestCheckResponse_NormalTraffic(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/healthy"

	for i := 0; i < 10; i++ {
		det := m.CheckResponse(url, mockResponse(200, "normal page content"), 50*time.Millisecond)
		if det != nil {
			t.Fatalf("expected no detection on normal traffic, got %s on iteration %d", det.Type, i)
		}
	}
	if m.Blocked() || m.RateLimited() || m.CaptchaDetected() || m.TarpitDetected() {
		t.Fatal("no flags should be set for normal traffic")
	}
}

func TestAdapt_RateLimitIncreasesJitter(t *testing.T) {
	s := &Strategy{MaxJitterMs: 1000}
	m := NewMonitor(s)
	url := "https://example.com/api"

	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)
	m.CheckResponse(url, mockResponse(429, "slow down"), 50*time.Millisecond)

	if s.MaxJitterMs != 2000 {
		t.Fatalf("expected MaxJitterMs=2000 after rate limit, got %d", s.MaxJitterMs)
	}
	if s.BaseDelayMs != 5000 {
		t.Fatalf("expected BaseDelayMs=5000 after rate limit, got %d", s.BaseDelayMs)
	}
}

func TestAdapt_RateLimitFromZeroJitter(t *testing.T) {
	s := &Strategy{MaxJitterMs: 0}
	m := NewMonitor(s)
	url := "https://example.com/api"

	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)
	m.CheckResponse(url, mockResponse(429, "slow down"), 50*time.Millisecond)

	if s.MaxJitterMs != 5000 {
		t.Fatalf("expected MaxJitterMs=5000 when starting from 0, got %d", s.MaxJitterMs)
	}
}

func TestFindings_EmittedOnDetection(t *testing.T) {
	m := NewMonitor(nil)
	url := "https://example.com/api"

	m.CheckResponse(url, mockResponse(200, "ok"), 50*time.Millisecond)
	m.CheckResponse(url, mockResponse(429, "rate limited"), 50*time.Millisecond)

	findings := m.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != finding.CheckIDSDetected {
		t.Fatalf("expected check_id %s, got %s", finding.CheckIDSDetected, f.CheckID)
	}
	if f.Severity != finding.SeverityInfo {
		t.Fatalf("expected severity info, got %s", f.Severity)
	}
	if f.Scanner != "evasion_monitor" {
		t.Fatalf("expected scanner evasion_monitor, got %s", f.Scanner)
	}
	if f.ProofCommand == "" {
		t.Fatal("expected ProofCommand to be set")
	}
	evType, ok := f.Evidence["detection_type"]
	if !ok || evType != "rate_limit" {
		t.Fatalf("expected evidence detection_type=rate_limit, got %v", evType)
	}
}

func TestMonitoredTransport_PassesResponseThrough(t *testing.T) {
	mon := NewMonitor(nil)
	inner := &mockRoundTripper{
		resp: mockResponse(200, "hello world"),
	}
	transport := &MonitoredTransport{
		Base:    inner,
		Monitor: mon,
	}

	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Body should still be readable by the caller.
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello world" {
		t.Fatalf("expected body 'hello world', got %q", string(body))
	}
}

func TestMonitoredTransport_DetectsRateLimit(t *testing.T) {
	mon := NewMonitor(nil)

	// First request: 200.
	inner := &mockRoundTripper{resp: mockResponse(200, "ok")}
	transport := &MonitoredTransport{Base: inner, Monitor: mon}
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	_, _ = transport.RoundTrip(req)

	// Second request: 429.
	inner.resp = mockResponse(429, "too many requests")
	req2, _ := http.NewRequest("GET", "https://example.com/api", nil)
	_, _ = transport.RoundTrip(req2)

	if !mon.RateLimited() {
		t.Fatal("expected rate limiting to be detected through transport")
	}
	if len(mon.Findings()) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(mon.Findings()))
	}
}

func TestMonitoredTransport_ConnectionFailure(t *testing.T) {
	mon := NewMonitor(nil)

	// Establish baseline.
	inner := &mockRoundTripper{resp: mockResponse(200, "ok")}
	transport := &MonitoredTransport{Base: inner, Monitor: mon}
	req, _ := http.NewRequest("GET", "https://example.com/target", nil)
	_, _ = transport.RoundTrip(req)

	// Simulate connection failure.
	inner.resp = nil
	inner.err = io.ErrUnexpectedEOF
	req2, _ := http.NewRequest("GET", "https://example.com/target", nil)
	_, err := transport.RoundTrip(req2)
	if err == nil {
		t.Fatal("expected error from transport")
	}
	if !mon.Blocked() {
		t.Fatal("expected IP block detection after connection failure")
	}
}

// mockRoundTripper is a test helper that returns a canned response.
type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Clone the body so multiple reads work.
	if m.resp != nil && m.resp.Body != nil {
		body, _ := io.ReadAll(m.resp.Body)
		m.resp.Body = io.NopCloser(strings.NewReader(string(body)))
		clone := *m.resp
		clone.Body = io.NopCloser(strings.NewReader(string(body)))
		return &clone, nil
	}
	return m.resp, nil
}
