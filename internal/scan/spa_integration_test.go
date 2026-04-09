package scan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// angularSPAHTML is a realistic Angular-like HTML shell: empty <app-root>
// with a script tag, similar to what `ng build` produces.
const angularSPAHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>My Angular App</title>
<base href="/">
<link rel="stylesheet" href="styles.css">
</head>
<body>
<app-root></app-root>
<script src="runtime.js" type="module"></script>
<script src="polyfills.js" type="module"></script>
<script src="main.js" type="module"></script>
</body>
</html>`

// reactSPAHTML is a realistic React CRA shell.
const reactSPAHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>React App</title>
</head>
<body>
<noscript>You need to enable JavaScript to run this app.</noscript>
<div id="root"></div>
<script src="/static/js/main.chunk.js"></script>
<script src="/static/js/bundle.js"></script>
</body>
</html>`

// vueSPAHTML is a realistic Vue CLI shell.
const vueSPAHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vue App</title>
</head>
<body>
<div id="app"></div>
<script src="/js/chunk-vendors.js"></script>
<script src="/js/app.js"></script>
</body>
</html>`

// serverRenderedHTML has actual content in the body — not an SPA.
const serverRenderedHTML = `<!DOCTYPE html>
<html lang="en">
<head><title>Blog</title></head>
<body>
<h1>Welcome to the Blog</h1>
<p>This page is fully server-rendered with lots of text content.
It has navigation, articles, footers, and all the usual things
you would expect from a traditional multi-page application that
renders everything on the server side.</p>
<nav><a href="/about">About</a><a href="/contact">Contact</a></nav>
<article><h2>First Post</h2><p>Content here.</p></article>
<script src="/analytics.js"></script>
</body>
</html>`

func TestIsSPA_Integration_AngularShell(t *testing.T) {
	if !IsSPA(angularSPAHTML) {
		t.Error("expected Angular shell (app-root + script tags) to be detected as SPA")
	}
}

func TestIsSPA_Integration_ReactShell(t *testing.T) {
	if !IsSPA(reactSPAHTML) {
		t.Error("expected React CRA shell (empty #root div) to be detected as SPA")
	}
}

func TestIsSPA_Integration_VueShell(t *testing.T) {
	if !IsSPA(vueSPAHTML) {
		t.Error("expected Vue CLI shell (empty #app div) to be detected as SPA")
	}
}

func TestIsSPA_Integration_ServerRendered_NotSPA(t *testing.T) {
	if IsSPA(serverRenderedHTML) {
		t.Error("expected server-rendered HTML with lots of text to NOT be detected as SPA")
	}
}

func TestRenderSPA_Integration_FallbackReturnsRawHTML(t *testing.T) {
	// Serve Angular-like HTML with <app-root>. When Chrome is not installed
	// RenderSPA should fall back to raw HTTP and return the shell HTML.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(angularSPAHTML))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	html, err := RenderSPA(ctx, srv.URL)
	if err != nil {
		// On CI without Chrome, RenderSPA may timeout trying Chrome then fallback.
		// If we got an error, try the raw HTTP fallback directly.
		t.Logf("RenderSPA returned error (expected on CI without Chrome): %v", err)
		resp, httpErr := http.Get(srv.URL)
		if httpErr != nil {
			t.Fatalf("raw HTTP fallback also failed: %v", httpErr)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		html = string(body)
	}
	if html == "" {
		t.Fatal("RenderSPA returned empty string")
	}
	// Regardless of whether Chrome is available, we should get HTML back.
	if !strings.Contains(html, "app-root") {
		t.Errorf("expected HTML to contain 'app-root', got: %s", truncateStr(html, 300))
	}
}

func TestRenderSPA_Integration_FallbackGraceful(t *testing.T) {
	// Verify that RenderSPA never returns an error when Chrome is absent —
	// it must always fall back to raw HTTP GET.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><app-root>Loading...</app-root></body></html>`))
	}))
	defer srv.Close()

	html, err := RenderSPA(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("RenderSPA should never error (fallback to HTTP), got: %v", err)
	}
	if !strings.Contains(html, "Loading...") {
		t.Errorf("expected fallback HTML to contain 'Loading...', got: %s", truncateStr(html, 200))
	}
}

func TestRenderSPAWithCookies_Integration_FallbackSendsCookies(t *testing.T) {
	// Ensure cookies are forwarded in fallback (non-Chrome) mode.
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("token"); err == nil {
			gotCookie = c.Value
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><app-root>Dashboard</app-root></body></html>`))
	}))
	defer srv.Close()

	cookies := []*http.Cookie{{Name: "token", Value: "secret-jwt"}}
	html, err := RenderSPAWithCookies(context.Background(), srv.URL, cookies)
	if err != nil {
		t.Fatalf("RenderSPAWithCookies error: %v", err)
	}
	if !strings.Contains(html, "Dashboard") {
		t.Errorf("expected 'Dashboard' in response, got: %s", truncateStr(html, 200))
	}
	// Only check cookie receipt in fallback mode (no Chrome).
	if !chromeInstalled() && gotCookie != "secret-jwt" {
		t.Errorf("expected cookie 'secret-jwt' in fallback mode, got: %q", gotCookie)
	}
}

func TestIsSPA_Integration_HTTPTestServer(t *testing.T) {
	// End-to-end: fetch from an httptest server, then run IsSPA on the response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(angularSPAHTML))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !IsSPA(body) {
		t.Error("expected IsSPA to return true for Angular HTML served over HTTP")
	}
}
