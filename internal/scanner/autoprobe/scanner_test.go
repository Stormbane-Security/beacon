package autoprobe

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/module"
)

// loginHandler simulates a login endpoint that behaves identically for all requests.
// This is the "correct" behavior — no enumeration, no lockout gap.
func loginHandlerSafe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	io.Copy(io.Discard, r.Body) //nolint:errcheck
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintln(w, `{"error":"invalid credentials"}`)
}

// loginHandlerEnumerable leaks username existence via status code difference.
// The scanner sends two distinct synthetic users; we differentiate on the "-a" vs "-b" suffix.
// The initial discovery probe (probe@example.invalid) returns 200 so the endpoint is discovered.
func loginHandlerEnumerable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// URL-decode the body (probeLogin uses url.Values.Encode which encodes "@" as "%40").
	raw, _ := io.ReadAll(r.Body)
	decoded, _ := url.QueryUnescape(string(raw))
	w.Header().Set("Content-Type", "application/json")
	// beacon-probe-nonexistent-a@... → 200 "wrong password"
	// beacon-probe-nonexistent-b@... → 404 "user not found"
	// initial discovery probe (probe@example.invalid) → 200 (endpoint is found)
	if strings.Contains(decoded, "-b@") {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"error":"user not found"}`)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"error":"wrong password"}`)
	}
}

func TestAutoprobe_SkippedInSurfaceMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(loginHandlerSafe))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("autoprobe should return nil in surface mode, got %d findings", len(findings))
	}
}

func TestAutoprobe_NoLoginEndpoint(t *testing.T) {
	// Server returns 404 for all POST requests — no login endpoint found.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when no login endpoint found, got %d", len(findings))
	}
}

func TestAutoprobe_NoLockoutDetected(t *testing.T) {
	// Login endpoint always returns 401 with same body — no lockout implemented.
	srv := httptest.NewServer(http.HandlerFunc(loginHandlerSafe))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.CheckID == "auth.no_lockout" {
			found = true
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set on no_lockout finding")
			}
		}
	}
	if !found {
		t.Error("expected auth.no_lockout finding for endpoint with no rate limiting")
	}
}

func TestAutoprobe_LockoutPresent_NoFinding(t *testing.T) {
	// After 5 attempts, return 429 — lockout is present.
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		attempts++
		if attempts >= 5 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, `{"error":"invalid credentials"}`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == "auth.no_lockout" {
			t.Error("should not report no_lockout when server returns 429 after 5 attempts")
		}
	}
}

func TestAutoprobe_UsernameEnumeration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(loginHandlerEnumerable))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.CheckID == "auth.username_enumeration" {
			found = true
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set on username_enumeration finding")
			}
		}
	}
	if !found {
		t.Error("expected auth.username_enumeration finding for status-differentiating endpoint")
	}
}

func TestAutoprobe_SameResponseNoEnumeration(t *testing.T) {
	// Identical response body and status for both synthetic users — no enumeration.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, `{"error":"invalid credentials","code":401}`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == "auth.username_enumeration" {
			t.Error("should not report enumeration when responses are identical")
		}
	}
}

func TestAutoprobe_Unreachable(t *testing.T) {
	findings, err := New().Run(t.Context(), "127.0.0.1:1", module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unreachable host, got %d", len(findings))
	}
}
