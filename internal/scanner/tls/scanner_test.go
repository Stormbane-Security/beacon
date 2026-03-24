package tls

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSplitHostPort_WithPort(t *testing.T) {
	h, p := splitHostPort("example.com:8443")
	if h != "example.com" || p != "8443" {
		t.Errorf("got %q %q", h, p)
	}
}

func TestSplitHostPort_NoPort(t *testing.T) {
	h, p := splitHostPort("example.com")
	if h != "example.com" || p != "443" {
		t.Errorf("got %q %q", h, p)
	}
}

func TestTLSVersionName(t *testing.T) {
	if tlsVersionName(tls.VersionTLS13) != "TLS 1.3" {
		t.Error("expected TLS 1.3")
	}
	if tlsVersionName(tls.VersionTLS12) != "TLS 1.2" {
		t.Error("expected TLS 1.2")
	}
}

func TestOCSPRevocationReason(t *testing.T) {
	if ocspRevocationReason(1) != "key_compromise" {
		t.Error("expected key_compromise")
	}
	if ocspRevocationReason(99) != "reason_99" {
		t.Error("expected reason_99")
	}
}

func TestHasSCT_MissingExtension(t *testing.T) {
	// httptest TLS server certs have no SCT extension
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	conn, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Skip("cannot dial test server:", err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no certs")
	}
	// httptest certs won't have SCT — this should return false
	if hasSCT(certs[0]) {
		t.Error("httptest cert unexpectedly has SCT")
	}
}

func TestSupportsTLS13_RealServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	// httptest uses Go's TLS stack which supports TLS 1.3
	result := supportsTLS13(context.Background(), host, port)
	if !result {
		t.Error("Go httptest TLS server should support TLS 1.3")
	}
}

func TestCheckHSTS_ShortMaxAge(t *testing.T) {
	findings := parseHSTSFindings("max-age=3600", "example.com", time.Time{})
	found := false
	for _, f := range findings {
		if f.CheckID == "tls.hsts_short_max_age" {
			found = true
		}
	}
	if !found {
		t.Error("expected hsts_short_max_age finding for max-age=3600")
	}
}

func TestCheckHSTS_MissingSubdomains(t *testing.T) {
	findings := parseHSTSFindings("max-age=31536000", "example.com", time.Time{})
	found := false
	for _, f := range findings {
		if f.CheckID == "tls.hsts_no_subdomains" {
			found = true
		}
	}
	if !found {
		t.Error("expected hsts_no_subdomains finding")
	}
}

func TestCheckHSTS_MissingPreload(t *testing.T) {
	findings := parseHSTSFindings("max-age=31536000; includeSubDomains", "example.com", time.Time{})
	found := false
	for _, f := range findings {
		if f.CheckID == "tls.hsts_no_preload" {
			found = true
		}
	}
	if !found {
		t.Error("expected hsts_no_preload finding")
	}
}

func TestCheckHSTS_AllDirectivesPresent_NoExtraFindings(t *testing.T) {
	findings := parseHSTSFindings("max-age=31536000; includeSubDomains; preload", "example.com", time.Time{})
	for _, f := range findings {
		switch f.CheckID {
		case "tls.hsts_short_max_age", "tls.hsts_no_subdomains", "tls.hsts_no_preload":
			t.Errorf("unexpected finding %s for well-configured HSTS", f.CheckID)
		}
	}
}
