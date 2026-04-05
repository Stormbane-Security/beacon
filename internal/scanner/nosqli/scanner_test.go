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
			_, _ = w.Write([]byte(`{"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.fake","user":"admin"}`))
			return
		}

		// Normal login: always fail
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
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
			_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
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
			_, _ = w.Write([]byte(`{"error":"MongoServerError: $where is not allowed in this context"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"results":[]}`))
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

func TestNoFalsePositiveOnCatchAllServer(t *testing.T) {
	// Simulates a Vercel/SPA catch-all: returns 200 with similar-sized JSON
	// for ANY POST to ANY path. This previously generated 15+ CRITICAL
	// $where findings per host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return a consistent-ish response regardless of body content
		_, _ = w.Write([]byte(`{"status":"ok","page":"` + r.URL.Path + `","data":{"items":[1,2,3,4,5],"total":5,"message":"Welcome to our API"}}`))
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
			t.Errorf("false positive on catch-all server: %s", f.Title)
		}
	}
}

func TestWhereMaxOnePerHost(t *testing.T) {
	// Even a genuinely vulnerable server should produce at most ONE $where finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
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
			_, _ = w.Write([]byte(`{"error":"MongoServerError: bad query"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	whereCount := 0
	for _, f := range findings {
		if strings.Contains(f.Title, "$where") {
			whereCount++
		}
	}
	if whereCount > 1 {
		t.Errorf("expected at most 1 $where finding, got %d", whereCount)
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

func TestAppendSliceSafety(t *testing.T) {
	// Verify that combining loginPaths and dataPaths does not mutate the
	// original package-level slices. Before the fix, append(loginPaths,
	// dataPaths...) could corrupt loginPaths if its backing array had
	// spare capacity.
	origLogin := make([]string, len(loginPaths))
	copy(origLogin, loginPaths)
	origData := make([]string, len(dataPaths))
	copy(origData, dataPaths)

	// Simulate what checkWhereInjection does
	allPaths := make([]string, 0, len(loginPaths)+len(dataPaths))
	allPaths = append(allPaths, loginPaths...)
	allPaths = append(allPaths, dataPaths...)

	// Verify originals unchanged
	for i, p := range loginPaths {
		if p != origLogin[i] {
			t.Errorf("loginPaths[%d] mutated: %q -> %q", i, origLogin[i], p)
		}
	}
	for i, p := range dataPaths {
		if p != origData[i] {
			t.Errorf("dataPaths[%d] mutated: %q -> %q", i, origData[i], p)
		}
	}
	if len(allPaths) != len(loginPaths)+len(dataPaths) {
		t.Errorf("allPaths length mismatch: got %d, want %d", len(allPaths), len(loginPaths)+len(dataPaths))
	}
}
