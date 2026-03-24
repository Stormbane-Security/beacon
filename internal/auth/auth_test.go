package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane/beacon/internal/auth"
	"github.com/stormbane/beacon/internal/config"
)

func TestAuthenticate_Bearer(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfgs := []config.AuthConfig{{Asset: "example.com", Method: "bearer", Token: "mytoken123"}}
	client, session, err := auth.Authenticate(context.Background(), cfgs, "example.com", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if session.Method != "bearer" {
		t.Errorf("expected bearer, got %s", session.Method)
	}
	client.Get(srv.URL)
	if gotHeader != "Bearer mytoken123" {
		t.Errorf("unexpected Authorization header: %q", gotHeader)
	}
}

func TestAuthenticate_NoMatch(t *testing.T) {
	cfgs := []config.AuthConfig{{Asset: "other.com", Method: "bearer", Token: "tok"}}
	client, session, err := auth.Authenticate(context.Background(), cfgs, "example.com", &http.Client{})
	if err != nil || client != nil || session != nil {
		t.Errorf("expected nil results for non-matching asset, got client=%v session=%v err=%v", client, session, err)
	}
}

func TestAuthenticate_Cookie(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfgs := []config.AuthConfig{{Asset: "*", Method: "cookie", Cookie: "session=abc123"}}
	client, _, err := auth.Authenticate(context.Background(), cfgs, "anyhost.com", &http.Client{})
	if err != nil || client == nil {
		t.Fatalf("err=%v client=%v", err, client)
	}
	client.Get(srv.URL)
	if gotCookie != "session=abc123" {
		t.Errorf("unexpected Cookie: %q", gotCookie)
	}
}
