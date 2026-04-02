// Package authctx provides context-based HTTP client injection for authenticated scanning.
//
// Scanners that need to make HTTP requests can retrieve an authenticated *http.Client
// from the context without coupling to auth configuration. The surface module injects
// the client after matching AuthConfig rules, and scanners transparently use it.
//
// Usage in scanners:
//
//	func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
//	    client := authctx.HTTPClient(ctx) // returns auth-wrapped client, or default
//	    resp, err := client.Get("https://" + asset + "/api/endpoint")
//	    ...
//	}
package authctx

import (
	"context"
	"net/http"
)

type contextKey struct{}

// WithHTTPClient returns a new context carrying the given HTTP client.
// The client is typically wrapped with auth transport (bearer token, cookie, etc.)
// by the surface module before scanner execution.
func WithHTTPClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, contextKey{}, client)
}

// HTTPClient retrieves the authenticated HTTP client from the context.
// If no client was injected (unauthenticated scan), returns a default http.Client.
// Callers never need to nil-check the return value.
func HTTPClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(contextKey{}).(*http.Client); ok && c != nil {
		return c
	}
	return &http.Client{}
}
