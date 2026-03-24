package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetryAfterPresent_HeaderPresent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	if !retryAfterPresent(context.Background(), ts.Client(), ts.URL) {
		t.Error("expected retryAfterPresent=true when Retry-After header is set")
	}
}

func TestRetryAfterPresent_HeaderAbsent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	if retryAfterPresent(context.Background(), ts.Client(), ts.URL) {
		t.Error("expected retryAfterPresent=false when Retry-After header is absent")
	}
}

func TestRetryAfterPresent_NetworkError_ReturnsTrue(t *testing.T) {
	// On network error we return true to avoid a false positive finding.
	result := retryAfterPresent(context.Background(), &http.Client{}, "http://127.0.0.1:1")
	if !result {
		t.Error("expected retryAfterPresent=true on network error (safe default)")
	}
}
