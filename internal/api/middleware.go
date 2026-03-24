package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
)

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.apiKey == "" {
		log.Println("WARNING: beacond started without an API key — all endpoints are unauthenticated. Set BEACON_SERVER_API_KEY for production use.")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" {
			// No key configured — open access (dev/test mode only)
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.apiKey)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
