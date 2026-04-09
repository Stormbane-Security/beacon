package wafbypass

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdaptiveTester_NoWAF(t *testing.T) {
	// Server that never blocks — returns 200 for everything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	result := AdaptiveTester(context.Background(), srv.Client(), srv.URL+"/", "q", "' OR 1=1")
	if result.OriginalBlocked {
		t.Error("expected original not blocked when server returns 200")
	}
	if result.Bypassed {
		t.Error("should not report bypass when original was not blocked")
	}
}

func TestAdaptiveTester_WAFBlocksAll(t *testing.T) {
	// Server that blocks everything with 403.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = fmt.Fprint(w, "Access Denied")
	}))
	defer srv.Close()

	result := AdaptiveTester(context.Background(), srv.Client(), srv.URL+"/", "q", "' OR 1=1")
	if !result.OriginalBlocked {
		t.Error("expected original to be blocked")
	}
	if result.Bypassed {
		t.Error("should not report bypass when all variants are blocked")
	}
}

func TestAdaptiveTester_DoubleEncodeBypass(t *testing.T) {
	// Server that blocks raw SQL injection patterns (single quote followed by
	// SQL keywords) but allows encoded variants where the quote is not literal.
	// This simulates a WAF doing single-pass pattern matching without recursive decoding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Block if raw single quote is present (typical WAF regex)
		if strings.Contains(q, "'") && strings.Contains(strings.ToUpper(q), "OR") {
			w.WriteHeader(403)
			_, _ = fmt.Fprint(w, "Blocked by WAF")
			return
		}
		w.WriteHeader(200)
		_, _ = fmt.Fprintf(w, "Result: %s", q)
	}))
	defer srv.Close()

	result := AdaptiveTester(context.Background(), srv.Client(), srv.URL+"/", "q", "' OR 1=1")
	if !result.OriginalBlocked {
		t.Error("expected original to be blocked")
	}
	if !result.Bypassed {
		t.Error("expected a bypass to be found (double encoded variant should pass)")
	}
	if result.Encoder == "" {
		t.Error("expected encoder name to be set")
	}
	if result.EncodedPayload == "" {
		t.Error("expected encoded payload to be set")
	}
}

func TestAdaptiveTester_BodySignatureDetection(t *testing.T) {
	// Server returns 200 but with WAF signature in body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "'") {
			w.WriteHeader(200) // Not 403, but body reveals WAF
			_, _ = fmt.Fprint(w, "<html><body>Request Blocked by Web Application Firewall</body></html>")
			return
		}
		w.WriteHeader(200)
		_, _ = fmt.Fprintf(w, "OK: %s", q)
	}))
	defer srv.Close()

	result := AdaptiveTester(context.Background(), srv.Client(), srv.URL+"/", "q", "' OR 1=1")
	if !result.OriginalBlocked {
		t.Error("expected body-based WAF signature to be detected as blocked")
	}
}

func TestAdaptiveTester_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result := AdaptiveTester(ctx, srv.Client(), srv.URL+"/", "q", "' OR 1=1")
	// Should not panic and should not report bypass
	if result.Bypassed {
		t.Error("cancelled context should not report bypass")
	}
}

func TestIsBlockedResponse_StatusCodes(t *testing.T) {
	tests := []struct {
		status int
		body   string
		want   bool
	}{
		{200, "OK", false},
		{403, "Forbidden", true},
		{406, "Not Acceptable", true},
		{429, "Too Many Requests", true},
		{503, "Service Unavailable", true},
		{200, "Your request has been blocked", true},
		{200, "Powered by Incapsula", true},
		{200, "<html>Normal page</html>", false},
		{301, "Redirect", false},
	}

	for _, tt := range tests {
		got := isBlockedResponse(tt.status, tt.body)
		if got != tt.want {
			t.Errorf("isBlockedResponse(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	long := strings.Repeat("a", 2000)
	result := truncate(long, 1024)
	if len(result) != 1024 {
		t.Errorf("expected 1024, got %d", len(result))
	}

	short := "hello"
	result = truncate(short, 1024)
	if result != short {
		t.Errorf("short string should not be truncated")
	}
}
