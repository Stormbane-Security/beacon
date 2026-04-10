package secondorder_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/secondorder"
)

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Non-authorized modes must be no-ops
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secondorder.NewWithClient(ts.Client())
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

func TestDeepMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secondorder.NewWithClient(ts.Client())
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in deep mode (scanner is authorized-only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Canary reflection detection
// ---------------------------------------------------------------------------

func TestCanaryReflection_EmitsReflectionFinding(t *testing.T) {
	var mu sync.Mutex
	var stored string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/register":
			_ = r.ParseForm()
			mu.Lock()
			// Store whatever was posted in any field.
			for _, vals := range r.Form {
				for _, v := range vals {
					if strings.HasPrefix(v, "BEACON_2ND_ORDER_") {
						stored = v
					}
				}
			}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodGet && r.URL.Path == "/admin/users":
			mu.Lock()
			s := stored
			mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, "<html><body>Users: %s</body></html>", s)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secondorder.NewWithClient(ts.Client())
	findings, err := s.Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSecondOrderReflection) {
		t.Error("expected second-order reflection finding, got none")
	}
}

// ---------------------------------------------------------------------------
// XSS payload confirmation
// ---------------------------------------------------------------------------

func TestXSSPayload_EmitsXSSFinding(t *testing.T) {
	var mu sync.Mutex
	var stored string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/register":
			_ = r.ParseForm()
			mu.Lock()
			// Store the latest POST value — canary or payload.
			for _, vals := range r.Form {
				for _, v := range vals {
					stored = v
				}
			}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodGet && r.URL.Path == "/admin/users":
			mu.Lock()
			s := stored
			mu.Unlock()
			// Render stored value without escaping — vulnerable to XSS.
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", s)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secondorder.NewWithClient(ts.Client())
	findings, err := s.Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSecondOrderXSS) {
		t.Error("expected second-order XSS finding, got none")
	}
}

// ---------------------------------------------------------------------------
// SQLi payload confirmation
// ---------------------------------------------------------------------------

func TestSQLiPayload_EmitsSQLiFinding(t *testing.T) {
	var mu sync.Mutex
	var stored string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/register":
			_ = r.ParseForm()
			mu.Lock()
			for _, vals := range r.Form {
				for _, v := range vals {
					stored = v
				}
			}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodGet && r.URL.Path == "/admin/users":
			mu.Lock()
			s := stored
			mu.Unlock()
			// Render stored value directly — vulnerable to second-order SQLi reflection.
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", s)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secondorder.NewWithClient(ts.Client())
	findings, err := s.Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSecondOrderSQLi) {
		t.Error("expected second-order SQLi finding, got none")
	}
}

// ---------------------------------------------------------------------------
// No reflection — no findings
// ---------------------------------------------------------------------------

func TestNoReflection_NoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/register":
			// Accept the POST but don't store anything.
			w.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodGet && r.URL.Path == "/admin/users":
			// Return static content — no reflection.
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, "<html><body>User list: admin, bob</body></html>")

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secondorder.NewWithClient(ts.Client())
	findings, err := s.Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no reflection occurs, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestContextCancellation_Aborts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secondorder.NewWithClient(ts.Client())
	findings, err := s.Run(ctx, asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on cancelled context, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Scanner name
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := secondorder.New()
	if s.Name() != "secondorder" {
		t.Errorf("Name() = %q, want %q", s.Name(), "secondorder")
	}
}
