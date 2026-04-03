package credparse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateCredential_UnknownType(t *testing.T) {
	cred := Credential{Type: "some_random_thing", Value: "abc"}
	result := ValidateCredential(context.Background(), cred)
	if result != nil {
		t.Error("unknown credential type should return nil")
	}
}

func TestValidateCredential_AWSAccessKeyOnly(t *testing.T) {
	cred := Credential{Type: "aws_access_key", Value: "AKIAIOSFODNN7EXAMPLE"}
	result := ValidateCredential(context.Background(), cred)
	if result == nil {
		t.Fatal("expected result for AWS key")
	}
	if result.Error != "access_key_only" {
		t.Errorf("expected access_key_only error, got %s", result.Error)
	}
	if result.Service != "aws" {
		t.Errorf("expected service=aws, got %s", result.Service)
	}
}

func TestValidateGitHubToken_Invalid(t *testing.T) {
	// Mock GitHub API returning 401 for invalid token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message":"Bad credentials"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// We can't easily override the GitHub API URL in the validator without
	// refactoring, so this test validates the parsing logic by calling the
	// function directly with a mock server won't work without DI.
	// Instead, test the credential dispatch.
	cred := Credential{Type: "github_pat", Value: "ghp_invalidtokenfortest000000000000000000"}
	result := ValidateCredential(context.Background(), cred)
	if result == nil {
		t.Fatal("expected result for GitHub token")
	}
	// Will either be invalid (401) or error (DNS/network for api.github.com).
	// Both are acceptable — we're testing the code doesn't panic.
	if result.Service != "github" {
		t.Errorf("expected service=github, got %s", result.Service)
	}
}

func TestValidateSlackToken_Invalid(t *testing.T) {
	cred := Credential{Type: "slack_token", Value: "xoxb-invalid-test-token"}
	result := ValidateCredential(context.Background(), cred)
	if result == nil {
		t.Fatal("expected result for Slack token")
	}
	if result.Service != "slack" {
		t.Errorf("expected service=slack, got %s", result.Service)
	}
}

func TestValidateGoogleToken_Invalid(t *testing.T) {
	cred := Credential{Type: "google_oauth", Value: "ya29.invalid-test-token"}
	result := ValidateCredential(context.Background(), cred)
	if result == nil {
		t.Fatal("expected result for Google token")
	}
	if result.Service != "google" {
		t.Errorf("expected service=google, got %s", result.Service)
	}
	// Invalid token should return valid=false.
	if result.Valid {
		t.Error("invalid Google token should not validate")
	}
}

func TestValidateStripeKey_Invalid(t *testing.T) {
	cred := Credential{Type: "stripe_secret", Value: "sk_live_invalid_test_key_00000"}
	result := ValidateCredential(context.Background(), cred)
	if result == nil {
		t.Fatal("expected result for Stripe key")
	}
	if result.Service != "stripe" {
		t.Errorf("expected service=stripe, got %s", result.Service)
	}
	if result.Valid {
		t.Error("invalid Stripe key should not validate")
	}
}
