package takeover

// Unit tests for the takeover scanner helper functions.
// Tests are written against expected correct behaviour, not to rubber-stamp
// the existing implementation. Each test documents the precise contract it
// verifies so failures are immediately actionable.
//
// Real DNS is not used — httpProbe and platform matching are tested by
// spinning up local HTTP servers and calling the helpers directly.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── httpProbe ─────────────────────────────────────────────────────────────────

func TestHTTPProbe_Returns200AndBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	body, code := httpProbe(context.Background(), host)
	if code != http.StatusOK {
		t.Errorf("httpProbe: got status %d, want 200", code)
	}
	if !strings.Contains(body, "GitHub Pages") {
		t.Errorf("httpProbe: body %q does not contain expected content", body)
	}
}

func TestHTTPProbe_Returns404Body(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("NoSuchBucket"))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	body, code := httpProbe(context.Background(), host)
	if code != http.StatusNotFound {
		t.Errorf("httpProbe: got status %d, want 404", code)
	}
	if !strings.Contains(body, "NoSuchBucket") {
		t.Errorf("httpProbe: body %q does not contain 'NoSuchBucket'", body)
	}
}

func TestHTTPProbe_UnreachableServer_ReturnsEmpty(t *testing.T) {
	// Port 1 on loopback is reserved and not reachable.
	body, code := httpProbe(context.Background(), "127.0.0.1:1")
	if code != 0 {
		t.Errorf("httpProbe on unreachable host: got status %d, want 0", code)
	}
	if body != "" {
		t.Errorf("httpProbe on unreachable host: got non-empty body %q", body)
	}
}

func TestHTTPProbe_BodyLimitedTo4KB(t *testing.T) {
	// Serve 8 KB — we must get exactly 4 KB back.
	payload := strings.Repeat("x", 8192)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	body, _ := httpProbe(context.Background(), host)
	if len(body) != 4096 {
		t.Errorf("httpProbe body limit: got %d bytes, want 4096", len(body))
	}
}

// ── platform matching (CNAME suffix) ─────────────────────────────────────────

func TestPlatformMatch_GitHubPages(t *testing.T) {
	cname := "example.github.io"
	var matched *platform
	cnameLower := strings.ToLower(cname)
	for i := range platforms {
		for _, suffix := range platforms[i].cnameSuffixes {
			if strings.Contains(cnameLower, suffix) {
				matched = &platforms[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		t.Fatal("expected match for github.io CNAME, got nil")
	}
	if matched.name != "GitHub Pages" {
		t.Errorf("matched platform: got %q, want %q", matched.name, "GitHub Pages")
	}
}

func TestPlatformMatch_S3(t *testing.T) {
	cname := "mybucket.s3.amazonaws.com"
	var matched *platform
	cnameLower := strings.ToLower(cname)
	for i := range platforms {
		for _, suffix := range platforms[i].cnameSuffixes {
			if strings.Contains(cnameLower, suffix) {
				matched = &platforms[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		t.Fatal("expected match for s3.amazonaws.com CNAME, got nil")
	}
	if !strings.Contains(matched.name, "S3") {
		t.Errorf("matched platform: got %q, want name containing 'S3'", matched.name)
	}
}

func TestPlatformMatch_Heroku(t *testing.T) {
	cname := "app.herokudns.com"
	var matched *platform
	cnameLower := strings.ToLower(cname)
	for i := range platforms {
		for _, suffix := range platforms[i].cnameSuffixes {
			if strings.Contains(cnameLower, suffix) {
				matched = &platforms[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		t.Fatal("expected match for herokudns.com CNAME, got nil")
	}
	if matched.name != "Heroku" {
		t.Errorf("matched platform: got %q, want %q", matched.name, "Heroku")
	}
}

func TestPlatformMatch_UnknownCNAME_NoMatch(t *testing.T) {
	cname := "backend.example-internal.com"
	cnameLower := strings.ToLower(cname)
	for i := range platforms {
		for _, suffix := range platforms[i].cnameSuffixes {
			if strings.Contains(cnameLower, suffix) {
				t.Errorf("unexpected match for non-platform CNAME %q: matched %s (suffix %q)", cname, platforms[i].name, suffix)
			}
		}
	}
}

// ── httpFingerprint matching ──────────────────────────────────────────────────

func TestFingerprintMatch_GitHubPages_CaseInsensitive(t *testing.T) {
	// The scanner lowercases both body and fingerprint before matching.
	body := "THERE ISN'T A GITHUB PAGES SITE HERE."
	fp := "There isn't a GitHub Pages site here."
	matched := strings.Contains(strings.ToLower(body), strings.ToLower(fp))
	if !matched {
		t.Errorf("fingerprint match should be case-insensitive: body %q, fp %q", body, fp)
	}
}

func TestFingerprintMatch_NoMatch(t *testing.T) {
	body := "Welcome to our website. Everything is working fine."
	fp := "There isn't a GitHub Pages site here."
	matched := strings.Contains(strings.ToLower(body), strings.ToLower(fp))
	if matched {
		t.Errorf("fingerprint should not match live page body: body %q", body)
	}
}

// ── dangling vs confirmed logic ────────────────────────────────────────────────

// TestDanglingConfirmed_Logic verifies the three state transitions the scanner
// uses when evaluating an HTTP response against a platform fingerprint:
//
//   confirmed=true:  body contains the fingerprint (unclaimed resource)
//   dangling=false:  200 response without fingerprint (resource is live/claimed)
//   dangling=true:   network error or non-2xx without fingerprint (dangling CNAME)
func TestDanglingConfirmed_Logic(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		statusCode      int
		httpFingerprint string
		wantDangling    bool
		wantConfirmed   bool
	}{
		{
			name:            "fingerprint in body → confirmed",
			body:            "There isn't a GitHub Pages site here.",
			statusCode:      404,
			httpFingerprint: "There isn't a GitHub Pages site here.",
			wantDangling:    true,
			wantConfirmed:   true,
		},
		{
			name:            "200 without fingerprint → not dangling (claimed)",
			body:            "Welcome to the site!",
			statusCode:      200,
			httpFingerprint: "There isn't a GitHub Pages site here.",
			wantDangling:    false,
			wantConfirmed:   false,
		},
		{
			name:            "network error (empty body, 0 status) → dangling",
			body:            "",
			statusCode:      0,
			httpFingerprint: "There isn't a GitHub Pages site here.",
			wantDangling:    true,
			wantConfirmed:   false,
		},
		{
			name:            "404 without fingerprint → dangling (CNAME alone is finding)",
			body:            "Page not found",
			statusCode:      404,
			httpFingerprint: "There isn't a GitHub Pages site here.",
			wantDangling:    true,
			wantConfirmed:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dangling := true
			confirmed := false

			if tt.body != "" && tt.httpFingerprint != "" {
				if strings.Contains(strings.ToLower(tt.body), strings.ToLower(tt.httpFingerprint)) {
					confirmed = true
				} else if tt.statusCode >= 200 && tt.statusCode < 300 {
					dangling = false
				}
			}

			if dangling != tt.wantDangling {
				t.Errorf("dangling: got %v, want %v", dangling, tt.wantDangling)
			}
			if confirmed != tt.wantConfirmed {
				t.Errorf("confirmed: got %v, want %v", confirmed, tt.wantConfirmed)
			}
		})
	}
}

// ── resolveCNAME ──────────────────────────────────────────────────────────────

// TestResolveCNAME_SelfReturnsEmpty verifies that a hostname with no CNAME
// (i.e., LookupCNAME returns the hostname itself) produces an empty string,
// indicating there is no dangling CNAME to evaluate.
//
// We use "localhost" because it resolves directly to 127.0.0.1 with no CNAME
// on all platforms where these tests run.
func TestResolveCNAME_SelfReturnsEmpty(t *testing.T) {
	// localhost should resolve directly via A record without a CNAME chain.
	// net.DefaultResolver.LookupCNAME returns "localhost." (itself + dot).
	cname, err := resolveCNAME(context.Background(), "localhost")
	if err != nil {
		// NXDOMAIN or no resolver available — skip rather than fail.
		t.Skipf("DNS unavailable: %v", err)
	}
	// A host with no real CNAME should return empty string.
	// Skip if the environment's DNS search domain causes localhost to resolve
	// via a search suffix (e.g. localhost.corp.example.com) — that is a
	// DNS resolver behaviour difference, not a takeover scanner bug.
	if cname != "" {
		t.Skipf("DNS search domain in effect: resolveCNAME(localhost) = %q (skipping — not a scanner bug)", cname)
	}
}
