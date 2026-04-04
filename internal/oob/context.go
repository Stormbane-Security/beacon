package oob

import "context"

type contextKey struct{}

// WithOOB returns a context carrying the OOB server.
func WithOOB(ctx context.Context, srv *Server) context.Context {
	return context.WithValue(ctx, contextKey{}, srv)
}

// FromContext retrieves the OOB server from the context.
// Returns nil if no OOB server is configured.
func FromContext(ctx context.Context) *Server {
	srv, _ := ctx.Value(contextKey{}).(*Server)
	return srv
}
