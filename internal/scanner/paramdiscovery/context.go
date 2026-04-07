// Package paramdiscovery — context helpers for passing discovered parameters to
// downstream scanners.
package paramdiscovery

import "context"

type ctxKey struct{}

// WithDiscoveredParams returns a context that carries the given discovered
// parameter map. Keys are URL paths; values are deduplicated parameter name
// slices discovered from crawl results, HTML forms, JS source, and JSON bodies.
func WithDiscoveredParams(ctx context.Context, params map[string][]string) context.Context {
	return context.WithValue(ctx, ctxKey{}, params)
}

// DiscoveredParamsFromContext retrieves the discovered parameter map from ctx.
// Returns nil if no parameters were stored.
func DiscoveredParamsFromContext(ctx context.Context) map[string][]string {
	if v, ok := ctx.Value(ctxKey{}).(map[string][]string); ok {
		return v
	}
	return nil
}
