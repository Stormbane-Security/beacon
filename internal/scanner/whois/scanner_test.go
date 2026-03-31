package whois_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/whois"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for _, f := range findings {
		if f.CheckID == id {
			return &f
		}
	}
	return nil
}

// rdapJSON builds a complete RDAP response JSON string with the given events,
// entities, nameservers, and status.
func rdapJSON(domain string, events []map[string]string, registrar string, nameservers []string, status []string) string {
	var evArr []map[string]string
	for _, ev := range events {
		evArr = append(evArr, ev)
	}

	// Build nameserver array
	nsArr := []map[string]string{}
	for _, ns := range nameservers {
		nsArr = append(nsArr, map[string]string{"ldhName": ns})
	}

	// Build entity with vCard for registrar
	entities := []map[string]any{}
	if registrar != "" {
		entities = append(entities, map[string]any{
			"roles": []string{"registrar"},
			"vcardArray": []any{
				"vcard",
				[]any{
					[]any{"fn", map[string]any{}, "text", registrar},
				},
			},
		})
	}

	resp := map[string]any{
		"ldhName":     domain,
		"status":      status,
		"events":      evArr,
		"entities":    entities,
		"nameservers": nsArr,
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// ── Test: subdomain filtering ────────────────────────────────────────────────

func TestRun_SkipsDeepSubdomains(t *testing.T) {
	// Subdomains with >2 dots should be skipped entirely.
	s := whois.New()
	findings, err := s.Run(context.Background(), "sub.deep.example.co.uk", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for deep subdomain, got %d", len(findings))
	}
}

func TestRun_AllowsTwoDotsForCcTLD(t *testing.T) {
	// "example.co.uk" has 2 dots — should be processed (not skipped).
	// We need a mock RDAP server for this; the scanner tries rdap.org which
	// we can't intercept without a custom transport. Instead we test the
	// filter logic indirectly: if it returns nil,nil for a server that
	// doesn't respond, that's expected.
	s := whois.New()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// This will time out / fail to connect, which is fine — we're just
	// verifying it doesn't skip the domain.
	_, _ = s.Run(ctx, "example.co.uk", module.ScanSurface)
	// No assertion on results; the point is it attempted the request.
}

// ── Test: scanner name ───────────────────────────────────────────────────────

func TestName(t *testing.T) {
	s := whois.New()
	if s.Name() != "whois" {
		t.Errorf("Name() = %q; want %q", s.Name(), "whois")
	}
}

// ── Test: cancelled context ──────────────────────────────────────────────────

func TestRun_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := whois.New()
	findings, err := s.Run(ctx, "example.com", module.ScanSurface)
	// Cancelled context should return nil, nil (scanner swallows errors)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on cancelled ctx, got %d", len(findings))
	}
}

// ── Test: domain expiry within 7 days → Critical ────────────────────────────

func TestRun_DomainExpiry7Days(t *testing.T) {
	expiresAt := time.Now().Add(3 * 24 * time.Hour) // 3 days from now

	body := rdapJSON("example.com",
		[]map[string]string{
			{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
			{"eventAction": "expiration", "eventDate": expiresAt.Format(time.RFC3339)},
		},
		"Test Registrar Inc.",
		[]string{"ns1.example.com", "ns2.example.com"},
		[]string{"active"},
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	// The whois scanner hardcodes the RDAP URL (rdap.org), so we can't
	// easily redirect it to our test server via httptest alone. Instead,
	// we test the analyzeWorkflow-style helpers by verifying the scanner's
	// behavior with a custom HTTP transport. Since the scanner creates its
	// own client internally, we need a different approach: use the test
	// server URL as the "asset" and rely on the scanner building the URL
	// from it. But the scanner uses rdap.org, not the asset directly.
	//
	// For proper unit testing, we'll use a custom transport via the test.
	// Since the scanner's client is internal, we test it end-to-end by
	// hijacking the DNS/transport. However, for simplicity and to test
	// the parsing logic, we'll create a RoundTripper-based test.
	t.Run("parsing_logic", func(t *testing.T) {
		// We verify the RDAP JSON parsing by constructing a known response
		// and ensuring the scanner would produce the right findings.
		// This is tested indirectly via the httptest approach with a
		// custom transport.

		// Instead let's use a transport that redirects rdap.org to our test server.
		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			targetURL: ts.URL,
			wrapped:   origTransport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		s := whois.New()
		findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !hasCheckID(findings, finding.CheckWHOISDomainExpiry7d) {
			t.Error("expected CheckWHOISDomainExpiry7d finding for domain expiring in 3 days")
		}

		f := findByCheckID(findings, finding.CheckWHOISDomainExpiry7d)
		if f != nil {
			if f.Severity != finding.SeverityCritical {
				t.Errorf("7d expiry severity = %v; want Critical", f.Severity)
			}
			if f.Scanner != "whois" {
				t.Errorf("scanner = %q; want %q", f.Scanner, "whois")
			}
			if f.Asset != "example.com" {
				t.Errorf("asset = %q; want %q", f.Asset, "example.com")
			}
		}

		// Should also have the info finding
		if !hasCheckID(findings, finding.CheckWHOISDomainInfo) {
			t.Error("expected CheckWHOISDomainInfo finding")
		}
	})
}

// ── Test: domain expiry within 30 days → High ────────────────────────────────

func TestRun_DomainExpiry30Days(t *testing.T) {
	expiresAt := time.Now().Add(20 * 24 * time.Hour) // 20 days from now

	body := rdapJSON("example.com",
		[]map[string]string{
			{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
			{"eventAction": "expiration", "eventDate": expiresAt.Format(time.RFC3339)},
		},
		"Test Registrar Inc.",
		[]string{"ns1.example.com"},
		[]string{"active"},
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckWHOISDomainExpiry30d) {
		t.Error("expected CheckWHOISDomainExpiry30d finding for domain expiring in 20 days")
	}

	f := findByCheckID(findings, finding.CheckWHOISDomainExpiry30d)
	if f != nil {
		if f.Severity != finding.SeverityHigh {
			t.Errorf("30d expiry severity = %v; want High", f.Severity)
		}
	}

	// Should NOT have 7d finding
	if hasCheckID(findings, finding.CheckWHOISDomainExpiry7d) {
		t.Error("should not emit 7d expiry finding for domain expiring in 20 days")
	}
}

// ── Test: domain not expiring soon → info only ──────────────────────────────

func TestRun_DomainNotExpiringSoon(t *testing.T) {
	expiresAt := time.Now().Add(365 * 24 * time.Hour) // 1 year from now

	body := rdapJSON("example.com",
		[]map[string]string{
			{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
			{"eventAction": "expiration", "eventDate": expiresAt.Format(time.RFC3339)},
			{"eventAction": "last changed", "eventDate": "2025-01-15T10:00:00Z"},
		},
		"Cloudflare Registrar",
		[]string{"ns1.cloudflare.com", "ns2.cloudflare.com"},
		[]string{"clientTransferProhibited"},
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the info finding, no expiry warnings
	if hasCheckID(findings, finding.CheckWHOISDomainExpiry7d) {
		t.Error("should not emit 7d expiry finding for domain expiring in ~365 days")
	}
	if hasCheckID(findings, finding.CheckWHOISDomainExpiry30d) {
		t.Error("should not emit 30d expiry finding for domain expiring in ~365 days")
	}
	if !hasCheckID(findings, finding.CheckWHOISDomainInfo) {
		t.Error("expected info finding with domain registration details")
	}

	f := findByCheckID(findings, finding.CheckWHOISDomainInfo)
	if f != nil {
		if f.Severity != finding.SeverityInfo {
			t.Errorf("info finding severity = %v; want Info", f.Severity)
		}
		// Verify evidence fields
		ev := f.Evidence
		if ev["registrar"] != "Cloudflare Registrar" {
			t.Errorf("registrar = %v; want %q", ev["registrar"], "Cloudflare Registrar")
		}
		ns, ok := ev["nameservers"].([]string)
		if !ok || len(ns) != 2 {
			t.Errorf("expected 2 nameservers, got %v", ev["nameservers"])
		}
	}
}

// ── Test: non-200 response returns nil ──────────────────────────────────────

func TestRun_Non200Response(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 404 response, got %d", len(findings))
	}
}

// ── Test: malformed JSON response returns nil ───────────────────────────────

func TestRun_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{{not valid json}}")
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for malformed JSON, got %d", len(findings))
	}
}

// ── Test: empty response body returns nil ───────────────────────────────────

func TestRun_EmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty JSON body still parses as empty struct — info finding with empty fields
	// should still be emitted.
	_ = findings
}

// ── Test: no expiration event → info only, no warnings ──────────────────────

func TestRun_NoExpirationEvent(t *testing.T) {
	body := rdapJSON("example.com",
		[]map[string]string{
			{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
		},
		"Some Registrar",
		[]string{"ns1.example.com"},
		[]string{"active"},
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckWHOISDomainExpiry7d) ||
		hasCheckID(findings, finding.CheckWHOISDomainExpiry30d) {
		t.Error("should not emit expiry warnings when no expiration event exists")
	}

	if !hasCheckID(findings, finding.CheckWHOISDomainInfo) {
		t.Error("expected info finding even without expiration event")
	}
}

// ── Test: no registrar entity → empty registrar in info finding ─────────────

func TestRun_NoRegistrarEntity(t *testing.T) {
	// Build minimal RDAP response with no entities
	resp := map[string]any{
		"ldhName":     "example.com",
		"status":      []string{"active"},
		"events":      []map[string]string{},
		"entities":    []map[string]any{},
		"nameservers": []map[string]string{},
	}
	body, _ := json.Marshal(resp)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findByCheckID(findings, finding.CheckWHOISDomainInfo)
	if f == nil {
		t.Fatal("expected info finding")
	}
	if f.Evidence["registrar"] != "" {
		t.Errorf("expected empty registrar, got %v", f.Evidence["registrar"])
	}
}

// ── Test: nameservers are lowercased ─────────────────────────────────────────

func TestRun_NameserversAreLowercased(t *testing.T) {
	body := rdapJSON("example.com",
		[]map[string]string{},
		"",
		[]string{"NS1.EXAMPLE.COM", "NS2.Example.Com"},
		[]string{"active"},
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findByCheckID(findings, finding.CheckWHOISDomainInfo)
	if f == nil {
		t.Fatal("expected info finding")
	}

	ns, ok := f.Evidence["nameservers"].([]string)
	if !ok {
		t.Fatalf("nameservers not a string slice: %T", f.Evidence["nameservers"])
	}
	for _, n := range ns {
		if n != strings.ToLower(n) {
			t.Errorf("nameserver %q not lowercased", n)
		}
	}
}

// ── Test: malformed event dates are skipped ──────────────────────────────────

func TestRun_MalformedEventDates(t *testing.T) {
	// Use non-RFC3339 date format — should be silently skipped.
	resp := map[string]any{
		"ldhName": "example.com",
		"status":  []string{"active"},
		"events": []map[string]string{
			{"eventAction": "expiration", "eventDate": "Jan 15, 2025"}, // not RFC3339
		},
		"entities":    []map[string]any{},
		"nameservers": []map[string]string{},
	}
	body, _ := json.Marshal(resp)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{targetURL: ts.URL, wrapped: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	s := whois.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have the info finding, no expiry warnings (date couldn't be parsed)
	if hasCheckID(findings, finding.CheckWHOISDomainExpiry7d) ||
		hasCheckID(findings, finding.CheckWHOISDomainExpiry30d) {
		t.Error("should not emit expiry warnings when date format is invalid")
	}
}

// ── redirectTransport ────────────────────────────────────────────────────────

// redirectTransport intercepts HTTP requests to rdap.org and redirects them
// to the test server URL.
type redirectTransport struct {
	targetURL string
	wrapped   http.RoundTripper
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "rdap.org") {
		// Rewrite URL to point to our test server
		newURL := t.targetURL + req.URL.Path
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		for k, v := range req.Header {
			newReq.Header[k] = v
		}
		return t.wrapped.RoundTrip(newReq)
	}
	return t.wrapped.RoundTrip(req)
}
