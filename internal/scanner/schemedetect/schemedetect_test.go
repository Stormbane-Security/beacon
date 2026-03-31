package schemedetect

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// shortTimeoutClient returns an HTTP client with a 1-second dial timeout,
// suitable for tests that need connection failures to resolve quickly.
func shortTimeoutClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 1 * time.Second}).DialContext,
		},
		Timeout: 2 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — HTTPS server → returns "https"
// ---------------------------------------------------------------------------

func TestScheme_HTTPS_ReturnsHTTPS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()
	asset := strings.TrimPrefix(ts.URL, "https://")

	scheme := Scheme(context.Background(), client, asset)
	if scheme != "https" {
		t.Errorf("expected https, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — HTTP-only server, HTTPS fails → returns "http"
// ---------------------------------------------------------------------------

func TestScheme_HTTPOnly_ReturnsHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Use a client that won't accept self-signed certs, so HTTPS probe fails.
	client := &http.Client{}
	asset := strings.TrimPrefix(ts.URL, "http://")

	scheme := Scheme(context.Background(), client, asset)
	if scheme != "http" {
		t.Errorf("expected http, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — cancelled context → returns "http"
// ---------------------------------------------------------------------------

func TestScheme_CancelledContext_ReturnsHTTP(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()
	asset := strings.TrimPrefix(ts.URL, "https://")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scheme := Scheme(ctx, client, asset)
	if scheme != "http" {
		t.Errorf("expected http on cancelled context, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — asset with port
// ---------------------------------------------------------------------------

func TestScheme_AssetWithPort(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()
	// The TLS test server URL is already "https://127.0.0.1:PORT".
	asset := strings.TrimPrefix(ts.URL, "https://")

	scheme := Scheme(context.Background(), client, asset)
	if scheme != "https" {
		t.Errorf("expected https for asset with port, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Base — returns full URL with correct scheme (HTTPS)
// ---------------------------------------------------------------------------

func TestBase_HTTPS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()
	asset := strings.TrimPrefix(ts.URL, "https://")

	base := Base(context.Background(), client, asset)
	if base != "https://"+asset {
		t.Errorf("expected %q, got %q", "https://"+asset, base)
	}
}

// ---------------------------------------------------------------------------
// Test: Base — HTTPS probe fails → falls back to "http://"
// ---------------------------------------------------------------------------

func TestBase_FallbackHTTP(t *testing.T) {
	// Use a cancelled context to make the HTTPS probe fail immediately,
	// avoiding slow network timeouts.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := shortTimeoutClient()
	base := Base(ctx, client, "example.invalid:9999")
	if base != "http://example.invalid:9999" {
		t.Errorf("expected %q, got %q", "http://example.invalid:9999", base)
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — connection error (refused) → returns "http"
// ---------------------------------------------------------------------------

func TestScheme_ConnectionRefused_ReturnsHTTP(t *testing.T) {
	// Listen on a random port then close it immediately so we get a fast
	// connection-refused error instead of a slow timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // port is now closed → connection refused

	client := shortTimeoutClient()
	scheme := Scheme(context.Background(), client, addr)
	if scheme != "http" {
		t.Errorf("expected http for connection-refused, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: StripScheme — removes http/https prefix
// ---------------------------------------------------------------------------

func TestStripScheme(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com:8443", "example.com:8443"},
		{"http://example.com:8080", "example.com:8080"},
		{"example.com", "example.com"},
		{"example.com:443", "example.com:443"},
		{"", ""},
		{"ftp://example.com", "ftp://example.com"}, // Only http/https are stripped.
		{"https://", ""},
		{"http://", ""},
	}

	for _, tt := range tests {
		got := StripScheme(tt.input)
		if got != tt.want {
			t.Errorf("StripScheme(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — HTTPS server that returns non-200 → still returns "https"
// ---------------------------------------------------------------------------

func TestScheme_HTTPS_Non200_StillReturnsHTTPS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	client := ts.Client()
	asset := strings.TrimPrefix(ts.URL, "https://")

	scheme := Scheme(context.Background(), client, asset)
	if scheme != "https" {
		t.Errorf("expected https even for non-200, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — HTTPS with redirect → still returns "https"
// ---------------------------------------------------------------------------

func TestScheme_HTTPS_Redirect_ReturnsHTTPS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer ts.Close()

	client := ts.Client()
	asset := strings.TrimPrefix(ts.URL, "https://")

	scheme := Scheme(context.Background(), client, asset)
	if scheme != "https" {
		t.Errorf("expected https for redirect response, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — TLS connection rejected (bad cert) → falls back to http
// ---------------------------------------------------------------------------

func TestScheme_BadCert_FallsBackToHTTP(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Use a client that verifies certs — will reject the test server's self-signed cert.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{},
		},
	}
	asset := strings.TrimPrefix(ts.URL, "https://")

	scheme := Scheme(context.Background(), client, asset)
	if scheme != "http" {
		t.Errorf("expected http when TLS cert verification fails, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Scheme — unresolvable hostname → returns "http"
// ---------------------------------------------------------------------------

func TestScheme_UnresolvableHostname_ReturnsHTTP(t *testing.T) {
	client := shortTimeoutClient()
	scheme := Scheme(context.Background(), client, "nonexistent.invalid")
	if scheme != "http" {
		t.Errorf("expected http for unresolvable host, got %q", scheme)
	}
}

// ---------------------------------------------------------------------------
// Test: Base — preserves asset format with port
// ---------------------------------------------------------------------------

func TestBase_PreservesAssetFormat(t *testing.T) {
	// Use a cancelled context so HTTPS probe fails fast.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := shortTimeoutClient()
	base := Base(ctx, client, "10.0.0.1:8080")
	if base != "http://10.0.0.1:8080" {
		t.Errorf("expected %q, got %q", "http://10.0.0.1:8080", base)
	}
}
