// Package schemedetect provides a shared helper for determining whether an
// asset's web service is reachable via HTTPS or HTTP.
//
// The asset parameter may contain a port (e.g. "example.com:8443" or
// "192.168.1.1:8080"). The helper constructs the full URL correctly in all
// cases and does not append a second port when one is already present.
package schemedetect

import (
	"context"
	"net/http"
	"strings"
)

// Scheme probes the asset and returns "https" if TLS is available, "http"
// otherwise. It tries HTTPS first with a 5-second HEAD request; on any error
// it falls back to HTTP.
//
// asset may be:
//   - "example.com"           → tries https://example.com
//   - "example.com:443"       → tries https://example.com:443
//   - "example.com:8443"      → tries https://example.com:8443
//   - "192.168.1.1:8080"      → tries https://192.168.1.1:8080, falls back to http
func Scheme(ctx context.Context, client *http.Client, asset string) string {
	// Build the probe URL — asset may already include a port.
	httpsURL := "https://" + asset
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, httpsURL, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}

// Base returns the full base URL ("https://asset" or "http://asset") for the
// given asset, probing HTTPS first.
func Base(ctx context.Context, client *http.Client, asset string) string {
	return Scheme(ctx, client, asset) + "://" + asset
}

// StripScheme removes any leading http:// or https:// prefix from a URL,
// returning just the host[:port] component. Useful when an asset was
// accidentally passed with a scheme prefix.
func StripScheme(asset string) string {
	for _, pfx := range []string{"https://", "http://"} {
		if strings.HasPrefix(asset, pfx) {
			return strings.TrimPrefix(asset, pfx)
		}
	}
	return asset
}
