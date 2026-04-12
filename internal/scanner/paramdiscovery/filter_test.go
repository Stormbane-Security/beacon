package paramdiscovery

import (
	"testing"
)

func TestFilterFuzzTargets(t *testing.T) {
	urls := []string{
		"https://example.com/api/v1/users?id=1",
		"https://example.com/static/style.css",
		"https://example.com/images/logo.png",
		"https://example.com/fonts/inter.woff2",
		"https://example.com/login?next=/dashboard",
		"https://example.com/api/v2/search",
		"https://example.com/assets/app.js",
		"https://example.com/download/report.pdf",
		"https://example.com/admin/settings",
		"https://example.com/data.json",
		"https://example.com/feed.xml",
	}

	got := FilterFuzzTargets(urls)

	// Should keep: api/v1/users?id=1, login?next=, api/v2/search,
	// admin/settings, data.json, feed.xml
	// Should drop: style.css, logo.png, inter.woff2, app.js, report.pdf
	want := map[string]bool{
		"https://example.com/api/v1/users?id=1":     true,
		"https://example.com/login?next=/dashboard":  true,
		"https://example.com/api/v2/search":          true,
		"https://example.com/admin/settings":         true,
		"https://example.com/data.json":              true,
		"https://example.com/feed.xml":               true,
	}

	if len(got) != len(want) {
		t.Fatalf("FilterFuzzTargets returned %d URLs, want %d\ngot: %v", len(got), len(want), got)
	}

	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected URL in filtered list: %s", u)
		}
	}
}

func TestFilterFuzzTargets_KeepsNonStatic(t *testing.T) {
	urls := []string{
		"https://example.com/",
		"https://example.com/search?q=test",
		"https://example.com/graphql",
	}

	got := FilterFuzzTargets(urls)
	if len(got) != 3 {
		t.Fatalf("expected all 3 URLs kept, got %d: %v", len(got), got)
	}
}

func TestFilterFuzzTargets_EmptyInput(t *testing.T) {
	got := FilterFuzzTargets(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty output for nil input, got %v", got)
	}
}

func TestIsStaticAsset(t *testing.T) {
	staticExts := []string{".js", ".css", ".png", ".jpg", ".gif", ".svg",
		".woff", ".woff2", ".pdf", ".zip", ".mp4", ".webp"}
	for _, ext := range staticExts {
		if !isStaticAsset(ext) {
			t.Errorf("expected %q to be static asset", ext)
		}
	}

	dynamicExts := []string{".php", ".asp", ".jsp", ".py", ".rb", ".go", ""}
	for _, ext := range dynamicExts {
		if isStaticAsset(ext) {
			t.Errorf("expected %q to NOT be static asset", ext)
		}
	}
}

func TestIsAPIPath(t *testing.T) {
	apiPaths := []string{"/api/v1/users", "/v2/search", "/v1/data", "/data.json", "/feed.xml", "/graphql"}
	for _, p := range apiPaths {
		if !isAPIPath(p) {
			t.Errorf("expected %q to be API path", p)
		}
	}

	nonAPIPaths := []string{"/login", "/", "/admin", "/images/logo"}
	for _, p := range nonAPIPaths {
		if isAPIPath(p) {
			t.Errorf("expected %q to NOT be API path", p)
		}
	}
}
