package evasion

import "context"

type monitorCtxKey struct{}

// WithMonitor returns a context carrying the given Monitor instance.
// Scanners can retrieve it via MonitorFromContext to check whether the target
// has blocked or rate-limited the scanner before sending more probes.
func WithMonitor(ctx context.Context, m *Monitor) context.Context {
	return context.WithValue(ctx, monitorCtxKey{}, m)
}

// MonitorFromContext retrieves the evasion Monitor from ctx.
// Returns nil if no monitor was stored.
func MonitorFromContext(ctx context.Context) *Monitor {
	if m, ok := ctx.Value(monitorCtxKey{}).(*Monitor); ok {
		return m
	}
	return nil
}
