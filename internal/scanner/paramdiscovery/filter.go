package paramdiscovery

import (
	"net/url"
	"path/filepath"
	"strings"
)

// FilterFuzzTargets removes URLs that are unlikely to be injectable,
// reducing scan time without losing coverage. Static assets (images,
// fonts, stylesheets, scripts) never contain server-side injection
// points, so probing them wastes time. URLs with query parameters or
// API-like paths are always kept.
func FilterFuzzTargets(urls []string) []string {
	var targets []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}

		// Skip static assets — never injectable.
		ext := strings.ToLower(filepath.Ext(parsed.Path))
		if isStaticAsset(ext) {
			continue
		}

		// Prioritize URLs with parameters — most likely injectable.
		if len(parsed.Query()) > 0 {
			targets = append(targets, u)
			continue
		}

		// Include API-like paths — high value for injection testing.
		if isAPIPath(parsed.Path) {
			targets = append(targets, u)
			continue
		}

		// Include everything else (form actions, dynamic pages, etc.)
		targets = append(targets, u)
	}
	return targets
}

// isStaticAsset returns true for file extensions that are always
// served as static content and never contain server-side injection
// points.
func isStaticAsset(ext string) bool {
	switch ext {
	case ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
		".mp3", ".mp4", ".webm", ".pdf", ".zip", ".tar", ".gz",
		".bz2", ".rar", ".7z", ".swf", ".flv", ".avi", ".mov",
		".wmv", ".ogg", ".wav", ".flac", ".aac", ".tif", ".tiff",
		".bmp", ".cur", ".otf":
		return true
	}
	return false
}

// isAPIPath returns true for URL paths that look like API endpoints.
func isAPIPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "/api/") ||
		strings.Contains(lower, "/v1/") ||
		strings.Contains(lower, "/v2/") ||
		strings.Contains(lower, "/v3/") ||
		strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".xml") ||
		strings.HasSuffix(lower, "/graphql")
}
