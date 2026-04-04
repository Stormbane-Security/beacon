package csrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestCSRF_SkipsSurface(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Error("CSRF scanner should skip surface mode")
	}
}

func TestCSRF_DetectsMissingToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/submit">
				<input type="text" name="username">
				<input type="password" name="password">
				<button type="submit">Login</button>
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	s := New()
	// Extract host from test server URL
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected CSRF finding for form without token")
	}

	f := findings[0]
	if f.CheckID != "web.csrf_token_missing" {
		t.Errorf("expected check ID web.csrf_token_missing, got %s", f.CheckID)
	}
	if f.Module != "deep" {
		t.Errorf("expected Module=deep for deep-only scanner, got %q", f.Module)
	}
}

func TestCSRF_SkipsFormWithToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/submit">
				<input type="hidden" name="csrf_token" value="abc123">
				<input type="text" name="username">
				<button type="submit">Login</button>
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for form with CSRF token, got %d", len(findings))
	}
}

func TestCSRF_SkipsFormWithSameSiteCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "abc",
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/submit">
				<input type="text" name="username">
				<button type="submit">Login</button>
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings when SameSite=Strict cookie present, got %d", len(findings))
	}
}

func TestCSRF_SkipsGETForms(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="GET" action="/search">
				<input type="text" name="q">
				<button type="submit">Search</button>
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for GET form, got %d", len(findings))
	}
}

func TestCSRF_DetectsRailsToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/users">
				<input type="hidden" name="authenticity_token" value="xyz789">
				<input type="text" name="name">
				<button type="submit">Create</button>
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for form with authenticity_token, got %d", len(findings))
	}
}

func TestCSRF_DetectsDjangoToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/api/data">
				<input type="hidden" name="csrfmiddlewaretoken" value="abc">
				<input type="text" name="data">
				<button>Submit</button>
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for form with csrfmiddlewaretoken, got %d", len(findings))
	}
}

func TestCSRF_MultipleForms(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only serve forms on the root path; return 404 for everything else
		// to avoid duplicating findings across all probed paths.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/login">
				<input type="text" name="user">
			</form>
			<form method="POST" action="/register">
				<input type="hidden" name="_token" value="safe">
				<input type="text" name="email">
			</form>
			<form method="POST" action="/contact">
				<input type="text" name="message">
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	// Should find 2 vulnerable forms (/login and /contact), skip /register (has _token)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings for 2 unprotected forms, got %d", len(findings))
	}
}

func TestParseForms_Basic(t *testing.T) {
	body := `<html><body>
		<form method="POST" action="/submit">
			<input type="hidden" name="_token" value="abc">
			<input type="text" name="email">
		</form>
	</body></html>`

	forms := parseForms(body)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if !forms[0].isPost {
		t.Error("expected POST form")
	}
	if !forms[0].hasCSRFToken {
		t.Error("expected CSRF token detected")
	}
	if forms[0].action != "/submit" {
		t.Errorf("expected action /submit, got %s", forms[0].action)
	}
}

func TestParseForms_NoForms(t *testing.T) {
	body := `<html><body><p>No forms here</p></body></html>`
	forms := parseForms(body)
	if len(forms) != 0 {
		t.Errorf("expected 0 forms, got %d", len(forms))
	}
}

func TestHasSameSiteCookie(t *testing.T) {
	tests := []struct {
		name    string
		cookies []*http.Cookie
		want    bool
	}{
		{"no cookies", nil, false},
		{"no samesite", []*http.Cookie{{Name: "a", SameSite: http.SameSiteDefaultMode}}, false},
		{"samesite strict", []*http.Cookie{{Name: "a", SameSite: http.SameSiteStrictMode}}, true},
		{"samesite lax", []*http.Cookie{{Name: "a", SameSite: http.SameSiteLaxMode}}, true},
		{"mixed", []*http.Cookie{
			{Name: "a", SameSite: http.SameSiteDefaultMode},
			{Name: "b", SameSite: http.SameSiteLaxMode},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSameSiteCookie(tt.cookies)
			if got != tt.want {
				t.Errorf("hasSameSiteCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}
