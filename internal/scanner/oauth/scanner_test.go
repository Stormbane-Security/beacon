package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// asset returns the host:port for an httptest.Server.
func asset(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}

// ── JWKS exposure ─────────────────────────────────────────────────────────────

func TestOAuth_JWKSExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"keys":[{"kty":"RSA","n":"abc","e":"AQAB"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(t.Context(), asset(srv), module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckJWKSExposed {
			return // pass
		}
	}
	t.Error("expected CheckJWKSExposed finding, got none")
}

func TestOAuth_JWKSNotExposed_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(t.Context(), asset(srv), module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckJWKSExposed {
			t.Errorf("unexpected CheckJWKSExposed finding when no JWKS endpoint exists")
		}
	}
}

func TestOAuth_JWKS_200WithoutKeysField_NoFinding(t *testing.T) {
	// A 200 response that doesn't contain "keys" must not trigger a finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"certificates":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New()
	findings, _ := s.Run(t.Context(), asset(srv), module.ScanSurface)
	for _, f := range findings {
		if f.CheckID == finding.CheckJWKSExposed {
			t.Error("should not fire when response lacks 'keys' field")
		}
	}
}

// ── OIDC implicit flow ────────────────────────────────────────────────────────

func oidcDoc(t *testing.T, doc oidcDocument) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOAuth_ImplicitFlowOnly_FindingEmitted(t *testing.T) {
	doc := oidcDocument{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/oauth/authorize",
		TokenEndpoint:         "https://example.com/oauth/token",
		ResponseTypesSupported: []string{"token", "id_token"},
	}
	f := checkImplicitFlow("example.com", &doc)
	if f == nil {
		t.Fatal("expected implicit flow finding, got nil")
	}
	if f.CheckID != finding.CheckOIDCImplicitFlow {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
}

func TestOAuth_ImplicitFlowWithCode_NoFinding(t *testing.T) {
	// Authorization code flow is present — implicit flow alongside it is acceptable.
	doc := oidcDocument{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/oauth/authorize",
		ResponseTypesSupported: []string{"code", "token", "id_token"},
	}
	if f := checkImplicitFlow("example.com", &doc); f != nil {
		t.Error("no finding expected when code flow is also present")
	}
}

func TestOAuth_OnlyCodeFlow_NoImplicitFinding(t *testing.T) {
	doc := oidcDocument{
		AuthorizationEndpoint:  "https://example.com/authorize",
		ResponseTypesSupported: []string{"code"},
	}
	if f := checkImplicitFlow("example.com", &doc); f != nil {
		t.Error("no implicit flow finding expected for code-only server")
	}
}

// ── PKCE support ──────────────────────────────────────────────────────────────

func TestOAuth_PKCENotAdvertised_FindingEmitted(t *testing.T) {
	doc := oidcDocument{
		AuthorizationEndpoint:         "https://example.com/authorize",
		CodeChallengeMethodsSupported: nil, // absent
	}
	f := checkPKCESupport("example.com", &doc)
	if f == nil {
		t.Fatal("expected PKCE finding, got nil")
	}
	if f.CheckID != finding.CheckOAuthMissingPKCE {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
}

func TestOAuth_PKCEAdvertised_NoFinding(t *testing.T) {
	doc := oidcDocument{
		AuthorizationEndpoint:         "https://example.com/authorize",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	if f := checkPKCESupport("example.com", &doc); f != nil {
		t.Error("no finding expected when S256 PKCE is advertised")
	}
}

// ── OIDC discovery doc via HTTP ───────────────────────────────────────────────

func TestOAuth_OIDCDiscovery_ParsedAndChecked(t *testing.T) {
	// End-to-end: server exposes a discovery doc with implicit-only flow.
	// Expect CheckOIDCImplicitFlow from a surface scan.
	doc := oidcDocument{
		Issuer:                 "https://example.com",
		AuthorizationEndpoint:  "https://example.com/authorize",
		TokenEndpoint:          "https://example.com/token",
		ResponseTypesSupported: []string{"token"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(oidcDoc(t, doc))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(t.Context(), asset(srv), module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckOIDCImplicitFlow {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckOIDCImplicitFlow from OIDC discovery doc, got none")
	}
}

// ── Token endpoint auth ───────────────────────────────────────────────────────

func TestOAuth_TokenEndpoint_CorrectlyRejects_NoFinding(t *testing.T) {
	// 401 with invalid_client body → endpoint is correctly guarded.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_client","error_description":"Client authentication failed"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenEndpointAuth(t.Context(), client, asset(srv), srv.URL, "")
	if f != nil {
		t.Errorf("expected no finding when endpoint properly returns 401 invalid_client, got: %s", f.Title)
	}
}

func TestOAuth_TokenEndpoint_400WithInvalidRequest_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_request"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenEndpointAuth(t.Context(), client, asset(srv), srv.URL, "")
	if f != nil {
		t.Errorf("unexpected finding for properly-rejecting token endpoint: %s", f.Title)
	}
}

func TestOAuth_TokenEndpoint_Returns200_FindingEmitted(t *testing.T) {
	// Token endpoint accepts unauthenticated request and returns a token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.test.test","token_type":"bearer"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenEndpointAuth(t.Context(), client, asset(srv), srv.URL, "")
	if f == nil {
		t.Fatal("expected finding for token endpoint that returns 200, got nil")
	}
}

// ── Missing state (CSRF) ──────────────────────────────────────────────────────

func TestOAuth_MissingState_ServerRejectsWithStateError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_request","error_description":"state parameter is required"}`))
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkMissingState(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f != nil {
		t.Errorf("expected no finding when server enforces state, got: %s", f.Title)
	}
}

func TestOAuth_MissingState_ServerRedirectsWithoutStateValidation_FindingEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirects with auth code even without state → state not enforced.
		http.Redirect(w, r, "https://example.com/callback?code=abc123", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkMissingState(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f == nil {
		t.Fatal("expected missing state finding, got nil")
	}
	if f.CheckID != finding.CheckOAuthMissingState {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
}

func TestOAuth_MissingState_InvalidClientRejection_NoFinding(t *testing.T) {
	// Server rejects the probe due to unknown client_id — can't conclude anything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_client","error_description":"client not found"}`))
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkMissingState(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f != nil {
		t.Error("should not emit finding when server rejects probe due to invalid_client")
	}
}

// ── Missing PKCE enforcement ──────────────────────────────────────────────────

func TestOAuth_MissingPKCE_ServerEnforces_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_request","error_description":"code_challenge is required"}`))
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkMissingPKCE(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f != nil {
		t.Errorf("expected no finding when PKCE is enforced, got: %s", f.Title)
	}
}

func TestOAuth_MissingPKCE_ServerAllows_FindingEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accepts code flow without code_challenge — PKCE not enforced.
		http.Redirect(w, r, "https://example.com/callback?code=xyz", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkMissingPKCE(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f == nil {
		t.Fatal("expected PKCE finding, got nil")
	}
	if f.CheckID != finding.CheckOAuthMissingPKCE {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
}

func TestOAuth_MissingPKCE_SyntheticClient_SeverityDowngraded(t *testing.T) {
	// With synthetic (confidence=low) client, severity must be downgraded to Low.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/callback?code=xyz", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkMissingPKCE(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f == nil {
		t.Fatal("expected PKCE finding")
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("expected SeverityLow for synthetic client, got %s", f.Severity)
	}
}

// ── Open redirect ─────────────────────────────────────────────────────────────

func TestOAuth_OpenRedirect_Accepted_CriticalFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflects back the redirect_uri directly — open redirect.
		redirectURI := r.URL.Query().Get("redirect_uri")
		http.Redirect(w, r, redirectURI+"?code=abc", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkOpenRedirect(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f == nil {
		t.Fatal("expected open redirect finding, got nil")
	}
	if f.CheckID != finding.CheckOAuthOpenRedirect {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
}

func TestOAuth_OpenRedirect_Rejected_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server validates redirect_uri and rejects unknown domains.
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_request","error_description":"redirect_uri not registered"}`))
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkOpenRedirect(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f != nil {
		t.Errorf("expected no finding when redirect_uri is validated, got: %s", f.Title)
	}
}

// ── Token leak via Referer (implicit flow token in URL) ───────────────────────

func TestOAuth_TokenLeakReferer_AccessTokenInLocation_FindingEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/callback#access_token=eyJhbGci.eyJzdWIi.sig&token_type=bearer", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkTokenLeakReferer(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f == nil {
		t.Fatal("expected token leak finding, got nil")
	}
	if f.CheckID != finding.CheckOAuthTokenLeakReferer {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
}

func TestOAuth_TokenLeakReferer_NoTokenInLocation_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Code flow — code in Location, not token.
		http.Redirect(w, r, "https://example.com/callback?code=abc123&state=beacontest", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := checkTokenLeakReferer(t.Context(), client, asset(srv), srv.URL+"/authorize", syntheticClient())
	if f != nil {
		t.Errorf("unexpected token leak finding for code flow response: %s", f.Title)
	}
}

func TestOAuth_TokenLeakReferer_EmptyAuthEndpoint_NoFinding(t *testing.T) {
	client := &http.Client{}
	f := checkTokenLeakReferer(t.Context(), client, "example.com", "", syntheticClient())
	if f != nil {
		t.Error("expected nil when authEndpoint is empty")
	}
}

// ── JWT no-verification ───────────────────────────────────────────────────────

func TestOAuth_JWTNoVerification_200WithFakeJWT_CriticalFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/user", "/api/user", "/api/me", "/me", "/userinfo", "/profile":
			// Accepts JWT without verifying signature.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":1,"email":"admin@example.com","admin":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkJWTNoVerification(t.Context(), client, asset(srv), srv.URL)
	if f == nil {
		t.Fatal("expected JWT no-verification finding, got nil")
	}
	if f.CheckID != finding.CheckJWTNoVerification {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
}

func TestOAuth_JWTNoVerification_401WithFakeJWT_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server properly validates JWT and rejects invalid signature.
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token","error_description":"Signature verification failed"}`))
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkJWTNoVerification(t.Context(), client, asset(srv), srv.URL)
	if f != nil {
		t.Errorf("unexpected finding when server properly rejects invalid JWT: %s", f.Title)
	}
}

func TestOAuth_JWTNoVerification_200WithErrorBody_NoFinding(t *testing.T) {
	// Status 200 but body contains "invalid" — treat as rejection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/me" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"error":"invalid token provided"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkJWTNoVerification(t.Context(), client, asset(srv), srv.URL)
	if f != nil {
		t.Errorf("should not fire when 200 body contains 'invalid': %s", f.Title)
	}
}

// ── Token endpoint false positive / true positive edge cases ─────────────────

func TestOAuth_TokenEndpoint_BlockchainAPI400NonOAuthBody_NoFinding(t *testing.T) {
	// Regression: blockchain explorer /api/token returns 400 with a generic
	// rate-limit/API-error body that has no OAuth keywords. Must not fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			// No grant_type, access_token, token_type, "error":, client_id, oauth — pure API error.
			w.Write([]byte(`{"status":"0","message":"NOTOK","result":"Max rate limit reached, please use API Key for higher rate limit"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenEndpointAuth(t.Context(), client, asset(srv), srv.URL, "")
	if f != nil {
		t.Errorf("blockchain /api/token with non-OAuth body must not fire; got: %s", f.Title)
	}
}

func TestOAuth_TokenEndpoint_400WithGrantTypeButNoProperRejection_FindingEmitted(t *testing.T) {
	// Server returns 400 and echoes back grant_type in the body, but without
	// a proper RFC 6749 rejection code — indicates a misconfigured OAuth endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message":"Unknown grant_type","code":400}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenEndpointAuth(t.Context(), client, asset(srv), srv.URL, "")
	if f == nil {
		t.Fatal("expected finding for OAuth 400 with grant_type in body but no proper rejection code")
	}
}

func TestOAuth_TokenEndpoint_400WithInvalidScope_FindingEmitted(t *testing.T) {
	// Server returns 400 with "invalid_scope" — this means the server is
	// processing the request (accepting the client identity) but objecting to
	// the scope. It should NOT be excluded by isProperRejection (only
	// invalid_client/invalid_request/unauthorized_client/invalid_grant are exclusions).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			// "invalid_scope" means server accepted the client but rejected the scope.
			w.Write([]byte(`{"error":"invalid_scope","error_description":"requested scope is invalid","grant_type":"client_credentials"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenEndpointAuth(t.Context(), client, asset(srv), srv.URL, "")
	if f == nil {
		t.Fatal("expected finding for OAuth 400 with invalid_scope (server processing request without auth check)")
	}
}

func TestOAuth_TokenEndpoint_400WithInvalidToken_FindingEmitted(t *testing.T) {
	// "invalid_token" in the body also means the server is processing the
	// request — it should not be excluded. The scanner should fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_token","error_description":"The access token is invalid","oauth":"2.0"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenEndpointAuth(t.Context(), client, asset(srv), srv.URL, "")
	if f == nil {
		t.Fatal("expected finding for 400 with invalid_token (not a proper credential rejection)")
	}
}

// ── matchClientID ─────────────────────────────────────────────────────────────

func TestMatchClientID_ExtractsFromExplicitAssignment(t *testing.T) {
	html := `<script>var config = {client_id: "my-app-client-abc123", scopes: ["openid"]};</script>`
	got := matchClientID(html)
	if got != "my-app-client-abc123" {
		t.Errorf("expected 'my-app-client-abc123', got %q", got)
	}
}

func TestMatchClientID_ExtractsFromReactEnvVar(t *testing.T) {
	// In a built JS bundle the env var is inlined as a string literal.
	js := `REACT_APP_CLIENT_ID:"7f8e9d3a-b241-4c52-a19f-0011223344ff"`
	got := matchClientID(js)
	if got != "7f8e9d3a-b241-4c52-a19f-0011223344ff" {
		t.Errorf("expected UUID client ID, got %q", got)
	}
}

func TestMatchClientID_RejectsPlaceholder_Undefined(t *testing.T) {
	html := `clientId: "undefined"`
	got := matchClientID(html)
	if got != "" {
		t.Errorf("expected empty result for placeholder 'undefined', got %q", got)
	}
}

func TestMatchClientID_RejectsPureNumbers(t *testing.T) {
	html := `clientId: "12345678"`
	got := matchClientID(html)
	if got != "" {
		t.Errorf("expected empty result for pure-numeric value, got %q", got)
	}
}

func TestMatchClientID_RejectsTooShort(t *testing.T) {
	html := `client_id: "abc"`
	got := matchClientID(html)
	if got != "" {
		t.Errorf("expected empty result for short value (< 8 chars), got %q", got)
	}
}

func TestMatchClientID_NoMatchInPlainText(t *testing.T) {
	if got := matchClientID("hello world, no oauth here"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ── checkTokenInFragment ──────────────────────────────────────────────────────

func TestOAuth_TokenInFragment_TokenOnlyResponseType_FindingWithProofCommand(t *testing.T) {
	doc := oidcDocument{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/oauth/authorize",
		ResponseTypesSupported: []string{"token"},
	}
	f := checkTokenInFragment("example.com", &doc)
	if f == nil {
		t.Fatal("expected token-in-fragment finding for response_type=token, got nil")
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand must not be empty on token-in-fragment finding")
	}
	if strings.Contains(f.ProofCommand, "{asset}") {
		t.Errorf("ProofCommand must not use {asset} placeholder, got: %s", f.ProofCommand)
	}
	// ProofCommand must reference the actual auth endpoint.
	if !strings.Contains(f.ProofCommand, "oauth/authorize") {
		t.Errorf("ProofCommand must include the authorization_endpoint URL, got: %s", f.ProofCommand)
	}
}

func TestOAuth_TokenInFragment_EmptyResponseTypes_NoFinding(t *testing.T) {
	doc := oidcDocument{
		AuthorizationEndpoint:  "https://example.com/authorize",
		ResponseTypesSupported: []string{},
	}
	if f := checkTokenInFragment("example.com", &doc); f != nil {
		t.Errorf("no finding expected for empty response_types, got: %s", f.Title)
	}
}

// ── checkTokenLongExpiry ──────────────────────────────────────────────────────

func TestOAuth_TokenLongExpiry_Exactly86400_NoBoundaryFinding(t *testing.T) {
	// expires_in exactly 86400 (24h) must not trigger — it's within the threshold.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"abc","expires_in":86400}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenLongExpiry(t.Context(), client, asset(srv), srv.URL, "")
	if f != nil {
		t.Errorf("no finding expected for expires_in=86400 (boundary), got: %s", f.Title)
	}
}

func TestOAuth_TokenLongExpiry_Over24h_FindingEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"abc","expires_in":90000}`)) // 25 hours
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenLongExpiry(t.Context(), client, asset(srv), srv.URL, "")
	if f == nil {
		t.Fatal("expected long-expiry finding for expires_in=90000, got nil")
	}
	if f.CheckID != finding.CheckOAuthTokenLongExpiry {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand must not be empty on token-long-expiry finding")
	}
}

func TestOAuth_TokenLongExpiry_NonJSONBody_NoFinding(t *testing.T) {
	// Non-JSON response (e.g. HTML error page) must not produce a finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>Error: maintenance mode</body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkTokenLongExpiry(t.Context(), client, asset(srv), srv.URL, "")
	if f != nil {
		t.Errorf("no finding expected for non-JSON response, got: %s", f.Title)
	}
}

// ── checkRefreshNotRotated ────────────────────────────────────────────────────

func TestOAuth_RefreshNotRotated_NoRefreshTokenInResponse_Skipped(t *testing.T) {
	// Token endpoint returns 200 but no refresh_token field — check must be skipped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"abc","token_type":"bearer"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkRefreshNotRotated(t.Context(), client, asset(srv), srv.URL, "")
	if f != nil {
		t.Errorf("expected nil when no refresh_token is issued, got: %s", f.Title)
	}
}

func TestOAuth_RefreshNotRotated_SecondUseRejected_NoFinding(t *testing.T) {
	// First refresh_token use succeeds; second is rejected (correctly rotated).
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		r.ParseForm() //nolint:errcheck
		callCount++
		if callCount == 1 {
			// First call (client_credentials): return a refresh token.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"at1","refresh_token":"rt1","token_type":"bearer"}`))
			return
		}
		if r.FormValue("grant_type") == "refresh_token" {
			if callCount == 2 {
				// First refresh use: accepted.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"at2","token_type":"bearer"}`))
				return
			}
			// Second refresh use: rejected (token rotated/invalidated).
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{}
	f := checkRefreshNotRotated(t.Context(), client, asset(srv), srv.URL, "")
	if f != nil {
		t.Errorf("expected no finding when second refresh use is rejected, got: %s", f.Title)
	}
}
