package hibp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

func TestHIBP_NoKey_IsNoop(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New("")
	fs, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("got %d findings with empty key; want 0", len(fs))
	}
	if called {
		t.Error("HIBP API was called despite empty key")
	}
}

func TestHIBP_Subdomain_IsSkipped(t *testing.T) {
	// HIBP should only run on root domain, not subdomains (avoids duplicate calls).
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	s := New("testkey")
	// More than 2 dots = subdomain, should be skipped.
	fs, _ := s.Run(context.Background(), "mail.sub.example.com", module.ScanSurface)
	if len(fs) != 0 {
		t.Errorf("got findings for subdomain; want 0")
	}
	if called {
		t.Error("HIBP API was called for a subdomain")
	}
}

func TestHIBP_Breaches_ProducesFinding(t *testing.T) {
	body := `[
		{"Name":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165,"DataClasses":["Email addresses","Passwords","Usernames"],"IsVerified":true},
		{"Name":"LinkedIn","Domain":"linkedin.com","BreachDate":"2016-05-05","PwnCount":164611595,"DataClasses":["Email addresses","Passwords"],"IsVerified":true}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("hibp-api-key") == "" {
			t.Error("HIBP request missing hibp-api-key header")
		}
		if !strings.Contains(r.URL.Path, "breaches") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	// Patch HIBP URL via a custom client on the scanner struct.
	s := New("testkey")
	s.baseURL = srv.URL // patch base URL for testing

	fs, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("expected findings for domain with breaches, got none")
	}
	var found bool
	for _, f := range fs {
		if f.CheckID == finding.CheckHIBPBreach {
			found = true
			if f.Severity < finding.SeverityMedium {
				t.Errorf("Severity = %d; want >= Medium for breach exposure", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("no %q finding; got: %v", finding.CheckHIBPBreach, fs)
	}
}

func TestHIBP_NoBreaches_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HIBP returns 404 when no breaches found for domain.
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New("testkey")
	s.baseURL = srv.URL

	fs, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("expected 0 findings for domain with no breaches, got %d", len(fs))
	}
}

func TestHIBP_APIError_ReturnsEmpty(t *testing.T) {
	// 401 = bad API key — should not panic, should return empty.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"statusCode":401,"message":"Unauthorised"}`))
	}))
	defer srv.Close()

	s := New("badkey")
	s.baseURL = srv.URL

	fs, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("expected 0 findings on 401, got %d", len(fs))
	}
}
