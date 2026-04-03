package nosqli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestAuthBypass(t *testing.T) {
	// Simulate a MongoDB-backed login that is vulnerable to $ne bypass.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Vulnerable: if username/password are objects (operators), bypass auth
		switch body["username"].(type) {
		case map[string]any:
			// Operator injection → auth bypass
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.fake","user":"admin"}`))
			return
		}

		// Normal login: always fail
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebNoSQLi {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected critical severity, got %s", f.Severity)
			}
			if !strings.Contains(f.Title, "$ne") && !strings.Contains(f.Title, "$gt") &&
				!strings.Contains(f.Title, "$regex") {
				t.Errorf("title should mention operator type: %s", f.Title)
			}
			break
		}
	}
	if !found {
		t.Error("expected nosql injection finding for auth bypass, got none")
	}
}

func TestNoFalsePositiveOnSafeServer(t *testing.T) {
	// Server that properly handles JSON and rejects all logins.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid credentials"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckWebNoSQLi {
			t.Errorf("false positive: found nosqli on safe server: %s", f.Title)
		}
	}
}

func TestWhereInjection(t *testing.T) {
	// Server that returns MongoDB error when $where is used.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/search" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if _, ok := body["$where"]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"MongoServerError: $where is not allowed in this context"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebNoSQLi && strings.Contains(f.Title, "$where") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected nosql $where injection finding, got none")
	}
}

func TestSurfaceModeSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
}
