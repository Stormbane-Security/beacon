package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsSPA_Angular(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body ng-app="myApp"><div ng-view></div><script src="app.js"></script></body></html>`
	if !IsSPA(html) {
		t.Error("expected Angular page (ng-app) to be detected as SPA")
	}
}

func TestIsSPA_AngularModern(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body><app-root></app-root><script src="main.js"></script></body></html>`
	if !IsSPA(html) {
		t.Error("expected Angular (app-root) to be detected as SPA")
	}
}

func TestIsSPA_React(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body><div id="root" data-reactroot></div><script src="bundle.js"></script></body></html>`
	if !IsSPA(html) {
		t.Error("expected React page (data-reactroot) to be detected as SPA")
	}
}

func TestIsSPA_ReactEmptyRoot(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body><div id="root"></div><script src="/static/js/main.js"></script></body></html>`
	if !IsSPA(html) {
		t.Error("expected React page (empty #root div) to be detected as SPA")
	}
}

func TestIsSPA_Vue(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body><div id="app"></div><script src="app.js"></script></body></html>`
	if !IsSPA(html) {
		t.Error("expected Vue page (#app div) to be detected as SPA")
	}
}

func TestIsSPA_Nuxt(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body><div id="__nuxt"><div id="__layout"></div></div><script src="/_nuxt/app.js"></script></body></html>`
	if !IsSPA(html) {
		t.Error("expected Nuxt.js page to be detected as SPA")
	}
}

func TestIsSPA_NextJS(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body><div id="__next"></div><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script></body></html>`
	if !IsSPA(html) {
		t.Error("expected Next.js page (__NEXT_DATA__) to be detected as SPA")
	}
}

func TestIsSPA_EmptyBodyWithScripts(t *testing.T) {
	html := `<!DOCTYPE html><html><head><title>App</title></head><body><script src="vendor.js"></script><script src="app.js"></script></body></html>`
	if !IsSPA(html) {
		t.Error("expected empty body with multiple scripts to be detected as SPA")
	}
}

func TestIsSPA_PlainHTML_NotSPA(t *testing.T) {
	html := `<!DOCTYPE html><html><head><title>My Site</title></head><body><h1>Welcome</h1><p>This is a plain HTML page with server-rendered content. It has forms and links and plenty of text content that was rendered on the server side.</p><form action="/login"><input type="text" name="user"><input type="password" name="pass"><button>Login</button></form></body></html>`
	if IsSPA(html) {
		t.Error("expected plain server-rendered HTML to NOT be detected as SPA")
	}
}

func TestIsSPA_ServerRenderedWithScripts_NotSPA(t *testing.T) {
	html := `<!DOCTYPE html><html><head></head><body><h1>Dashboard</h1><p>Welcome back, user. Here is your server-rendered dashboard content with lots of text and data tables.</p><table><tr><td>Data</td></tr></table><script src="analytics.js"></script></body></html>`
	if IsSPA(html) {
		t.Error("expected server-rendered page with analytics script to NOT be detected as SPA")
	}
}

func TestRenderSPA_FallbackToHTTP(t *testing.T) {
	// When Chrome is not available (CI environments), RenderSPA should
	// gracefully fall back to a raw HTTP GET.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div id="root">Server content</div></body></html>`))
	}))
	defer srv.Close()

	html, err := RenderSPA(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("RenderSPA returned error: %v", err)
	}
	if html == "" {
		t.Fatal("RenderSPA returned empty string")
	}
	if !contains(html, "Server content") {
		t.Errorf("expected fallback HTML to contain 'Server content', got: %s", truncateStr(html, 200))
	}
}

func TestRenderSPAWithCookies_FallbackSendsCookies(t *testing.T) {
	var receivedCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			receivedCookie = c.Value
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>authenticated</body></html>`))
	}))
	defer srv.Close()

	cookies := []*http.Cookie{{Name: "session", Value: "abc123"}}
	html, err := RenderSPAWithCookies(context.Background(), srv.URL, cookies)
	if err != nil {
		t.Fatalf("RenderSPAWithCookies returned error: %v", err)
	}
	if !contains(html, "authenticated") {
		t.Errorf("expected HTML to contain 'authenticated', got: %s", truncateStr(html, 200))
	}
	// In fallback mode (no Chrome), cookies should be sent via HTTP.
	if !chromeInstalled() && receivedCookie != "abc123" {
		t.Errorf("expected cookie 'abc123' to be sent in fallback mode, got: %q", receivedCookie)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
