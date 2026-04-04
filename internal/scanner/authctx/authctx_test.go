package authctx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClient_Default(t *testing.T) {
	ctx := context.Background()
	client := HTTPClient(ctx)
	if client == nil {
		t.Fatal("HTTPClient should never return nil")
	}
}

func TestHTTPClient_Injected(t *testing.T) {
	custom := &http.Client{}
	ctx := WithHTTPClient(context.Background(), custom)
	got := HTTPClient(ctx)
	if got != custom {
		t.Error("HTTPClient should return the injected client")
	}
}

func TestHTTPClient_AuthTransportUsed(t *testing.T) {
	// Simulate an authenticated client that injects a Bearer token.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Without auth context — should get 401
	ctx := context.Background()
	resp, err := HTTPClient(ctx).Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}

	// With auth context — should get 200
	authedClient := &http.Client{
		Transport: &bearerTransport{token: "test-token"},
	}
	ctx = WithHTTPClient(ctx, authedClient)
	resp, err = HTTPClient(ctx).Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with auth, got %d", resp.StatusCode)
	}
}

func TestHTTPClient_NilClientFallsBack(t *testing.T) {
	// Explicitly setting nil should still return a usable default client
	ctx := WithHTTPClient(context.Background(), nil)
	client := HTTPClient(ctx)
	if client == nil {
		t.Fatal("HTTPClient should return default client even when nil was injected")
	}
}

// bearerTransport is a test helper that injects Authorization: Bearer headers.
type bearerTransport struct {
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(req)
}
