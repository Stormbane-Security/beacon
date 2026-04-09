package dnsrebind

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// --- bodySimilar unit tests ---

func TestBodySimilar_Identical(t *testing.T) {
	if !bodySimilar("hello world", "hello world") {
		t.Error("identical strings should be similar")
	}
}

func TestBodySimilar_Empty(t *testing.T) {
	if bodySimilar("", "hello") {
		t.Error("empty vs non-empty should not be similar")
	}
	if bodySimilar("hello", "") {
		t.Error("non-empty vs empty should not be similar")
	}
}

func TestBodySimilar_VeryDifferentLength(t *testing.T) {
	short := "abc"
	long := strings.Repeat("abc", 100)
	if bodySimilar(short, long) {
		t.Error("very different lengths should not be similar")
	}
}

func TestBodySimilar_SameLengthDifferentContent(t *testing.T) {
	// Same length, zero prefix overlap.
	if bodySimilar("aaaa", "zzzz") {
		t.Error("same-length but totally different bodies should not be similar")
	}
}

func TestBodySimilar_CloseEnough(t *testing.T) {
	a := "Hello, this is a page with some content"
	b := "Hello, this is a page with some conTENT"
	if !bodySimilar(a, b) {
		t.Error("bodies with high prefix overlap and same length should be similar")
	}
}

// --- Scanner.Run mode gating ---

func TestRun_SkipsSurfaceMode(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Error("surface mode should produce no findings")
	}
}

func TestRun_RunsInDeepMode(t *testing.T) {
	// Spin up a server that always returns the same thing regardless of Host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "same content for everyone")
	}))
	defer srv.Close()

	// Strip scheme — the scanner adds it.
	asset := strings.TrimPrefix(srv.URL, "http://")

	// Limit to just one localhost host to keep the test fast.
	restore := SetLocalhostHosts([]string{"127.0.0.1"})
	defer restore()
	restoreInt := SetInternalHosts([]string{"localhost"})
	defer restoreInt()

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// This server accepts any Host → should flag host unvalidated.
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for a server that ignores Host")
	}
}

// --- Check 1: Host header unvalidated ---

func TestProbe_HostUnvalidated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always returns same body regardless of Host.
		fmt.Fprint(w, "Welcome to my app")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	restore := SetLocalhostHosts(nil)
	defer restore()
	restoreInt := SetInternalHosts(nil)
	defer restoreInt()

	s := New()
	client := &http.Client{}
	findings := s.Probe(context.Background(), client, asset, "http")

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckDNSRebindHostUnvalidated {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected severity High, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CheckDNSRebindHostUnvalidated finding")
	}
}

func TestProbe_HostValidated_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "" && !strings.Contains(r.Host, "127.0.0.1") && !strings.HasPrefix(r.Host, "localhost") {
			http.Error(w, "Invalid Host", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, "Welcome to my app")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	restore := SetLocalhostHosts(nil)
	defer restore()
	restoreInt := SetInternalHosts(nil)
	defer restoreInt()

	s := New()
	client := &http.Client{}
	findings := s.Probe(context.Background(), client, asset, "http")

	for _, f := range findings {
		if f.CheckID == finding.CheckDNSRebindHostUnvalidated {
			t.Error("should not flag host unvalidated when server rejects bad Host")
		}
	}
}

// --- Check 2: CORS amplification note ---

func TestProbe_CORSAmplification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "open CORS and open Host")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	restore := SetLocalhostHosts(nil)
	defer restore()
	restoreInt := SetInternalHosts(nil)
	defer restoreInt()

	s := New()
	client := &http.Client{}
	findings := s.Probe(context.Background(), client, asset, "http")

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckDNSRebindHostUnvalidated {
			found = true
			if cp, ok := f.Evidence["cors_permissive"].(bool); !ok || !cp {
				t.Error("expected cors_permissive=true in evidence")
			}
			if !strings.Contains(f.Description, "Access-Control-Allow-Origin") {
				t.Error("expected CORS note in description")
			}
		}
	}
	if !found {
		t.Error("expected host unvalidated finding with CORS note")
	}
}

// --- Check 3: Internal service exposure ---

func TestProbe_InternalServiceExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a reverse proxy routing to different backends.
		switch r.Host {
		case "metadata.google.internal":
			fmt.Fprint(w, `{"instance":{"id":"12345","zone":"us-central1-a"}}`)
		default:
			fmt.Fprint(w, "Welcome to the public site")
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	// Only test metadata.google.internal to keep things fast.
	restoreInt := SetInternalHosts([]string{"metadata.google.internal"})
	defer restoreInt()
	restore := SetLocalhostHosts(nil)
	defer restore()

	s := New()
	client := &http.Client{}
	findings := s.Probe(context.Background(), client, asset, "http")

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckDNSRebindInternalRoutable {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected severity Critical, got %s", f.Severity)
			}
			if !strings.Contains(f.Title, "metadata.google.internal") {
				t.Errorf("expected metadata.google.internal in title, got %q", f.Title)
			}
		}
	}
	if !found {
		t.Error("expected CheckDNSRebindInternalRoutable finding for metadata endpoint")
	}
}

func TestProbe_InternalServiceExposure_SameContent_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always the same content — no internal routing.
		fmt.Fprint(w, "same content for everyone")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	restoreInt := SetInternalHosts([]string{"metadata.google.internal"})
	defer restoreInt()
	restore := SetLocalhostHosts(nil)
	defer restore()

	s := New()
	client := &http.Client{}
	findings := s.Probe(context.Background(), client, asset, "http")

	for _, f := range findings {
		if f.CheckID == finding.CheckDNSRebindInternalRoutable {
			t.Error("should not flag internal routable when content is the same")
		}
	}
}

// --- Check 4: Localhost Host acceptance ---

func TestProbe_LocalhostHostAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "same content for everyone")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	restore := SetLocalhostHosts([]string{"0.0.0.0"})
	defer restore()
	restoreInt := SetInternalHosts(nil)
	defer restoreInt()

	s := New()
	client := &http.Client{}
	findings := s.Probe(context.Background(), client, asset, "http")

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckDNSRebindHostUnvalidated && strings.Contains(f.Title, "0.0.0.0") {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for Host: 0.0.0.0 accepted")
	}
}

// --- Name ---

func TestName(t *testing.T) {
	s := New()
	if s.Name() != "dnsrebind" {
		t.Errorf("expected 'dnsrebind', got %q", s.Name())
	}
}

// --- truncate ---

func TestTruncate(t *testing.T) {
	if got := truncate("short", 100); got != "short" {
		t.Errorf("expected 'short', got %q", got)
	}
	if got := truncate("a long string that should be cut", 10); !strings.HasSuffix(got, "...") {
		t.Errorf("expected truncated string to end with '...', got %q", got)
	}
	if got := truncate("a long string that should be cut", 10); len(got) != 13 { // 10 + "..."
		t.Errorf("expected length 13, got %d", len(got))
	}
}
