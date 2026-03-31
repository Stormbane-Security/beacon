package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	oauthscanner "github.com/stormbane/beacon/internal/scanner/oauth"
)

// makeToken builds a JWT with the given header and payload maps.
// The signature segment is a stub — the scanner does not verify signatures.
func makeToken(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".stub_signature"
}

// --- extractStringField ---

func TestExtractStringField_Present(t *testing.T) {
	json := `{"alg":"RS256","typ":"JWT"}`
	if got := extractStringField(json, "alg"); got != "RS256" {
		t.Errorf("expected RS256, got %q", got)
	}
}

func TestExtractStringField_WithSpaces(t *testing.T) {
	json := `{"alg" : "HS256"}`
	if got := extractStringField(json, "alg"); got != "HS256" {
		t.Errorf("expected HS256, got %q", got)
	}
}

func TestExtractStringField_Missing(t *testing.T) {
	if got := extractStringField(`{"typ":"JWT"}`, "alg"); got != "" {
		t.Errorf("expected empty string for missing key, got %q", got)
	}
}

func TestExtractStringField_EmptyValue(t *testing.T) {
	if got := extractStringField(`{"alg":""}`, "alg"); got != "" {
		t.Errorf("expected empty value, got %q", got)
	}
}

// --- extractIntField ---

func TestExtractIntField_Present(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	payload := fmt.Sprintf(`{"sub":"u1","exp":%d}`, exp)
	got, ok := extractIntField(payload, "exp")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != exp {
		t.Errorf("expected %d, got %d", exp, got)
	}
}

func TestExtractIntField_Negative(t *testing.T) {
	got, ok := extractIntField(`{"iat":-1}`, "iat")
	if !ok {
		t.Fatal("expected ok=true for negative value")
	}
	if got != -1 {
		t.Errorf("expected -1, got %d", got)
	}
}

func TestExtractIntField_Missing(t *testing.T) {
	_, ok := extractIntField(`{"sub":"u1"}`, "exp")
	if ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestExtractIntField_StringValueNotParsed(t *testing.T) {
	// exp is a string, not a number — should not parse
	_, ok := extractIntField(`{"exp":"notanumber"}`, "exp")
	if ok {
		t.Error("expected ok=false when value is a string, not a number")
	}
}

// --- analyseToken: algorithm checks ---

func TestAnalyseToken_NoneAlgorithm_Critical(t *testing.T) {
	token := makeToken(map[string]any{"alg": "none", "typ": "JWT"}, map[string]any{"sub": "1"})
	findings := analyseToken("example.com", token)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTWeakAlg && f.Severity == finding.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected Critical finding for alg:none, got none")
	}
}

func TestAnalyseToken_NoneAlgorithmCaseInsensitive(t *testing.T) {
	// "NONE" and "None" should also trigger the critical finding
	for _, alg := range []string{"NONE", "None", "nOnE"} {
		token := makeToken(map[string]any{"alg": alg, "typ": "JWT"}, map[string]any{"sub": "1"})
		findings := analyseToken("example.com", token)
		var found bool
		for _, f := range findings {
			if f.CheckID == finding.CheckJWTWeakAlg && f.Severity == finding.SeverityCritical {
				found = true
			}
		}
		if !found {
			t.Errorf("expected Critical finding for alg:%q", alg)
		}
	}
}

func TestAnalyseToken_HS256_WeakAlg_Medium(t *testing.T) {
	token := makeToken(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "1"})
	findings := analyseToken("example.com", token)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTWeakAlg && f.Severity == finding.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Error("expected Medium finding for alg:HS256")
	}
}

func TestAnalyseToken_RS256_NoAlgFinding(t *testing.T) {
	exp := time.Now().Add(30 * time.Minute).Unix()
	token := makeToken(map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{"sub": "1", "exp": exp})
	findings := analyseToken("example.com", token)
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTWeakAlg {
			t.Errorf("unexpected alg finding for RS256: %s", f.Title)
		}
	}
}

func TestAnalyseToken_ES256_NoAlgFinding(t *testing.T) {
	exp := time.Now().Add(15 * time.Minute).Unix()
	token := makeToken(map[string]any{"alg": "ES256"}, map[string]any{"sub": "1", "exp": exp})
	findings := analyseToken("example.com", token)
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTWeakAlg {
			t.Errorf("unexpected weak-alg finding for ES256")
		}
	}
}

// --- analyseToken: expiry checks ---

func TestAnalyseToken_NoExpClaim_Finding(t *testing.T) {
	token := makeToken(map[string]any{"alg": "RS256"}, map[string]any{"sub": "1"})
	findings := analyseToken("example.com", token)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTLongExpiry {
			found = true
		}
	}
	if !found {
		t.Error("expected long-expiry finding when exp is absent")
	}
}

func TestAnalyseToken_ExpIn8Days_LongExpiryFinding(t *testing.T) {
	exp := time.Now().Add(8 * 24 * time.Hour).Unix()
	token := makeToken(map[string]any{"alg": "RS256"}, map[string]any{"sub": "1", "exp": exp})
	findings := analyseToken("example.com", token)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTLongExpiry {
			found = true
		}
	}
	if !found {
		t.Error("expected long-expiry finding for 8-day token")
	}
}

func TestAnalyseToken_ExpIn6Days_NoExpiryFinding(t *testing.T) {
	// 6 days is within the 7-day threshold — no finding expected
	exp := time.Now().Add(6 * 24 * time.Hour).Unix()
	token := makeToken(map[string]any{"alg": "RS256"}, map[string]any{"sub": "1", "exp": exp})
	findings := analyseToken("example.com", token)
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTLongExpiry {
			t.Errorf("unexpected long-expiry finding for 6-day token")
		}
	}
}

func TestAnalyseToken_ExpIn1Hour_NoExpiryFinding(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	token := makeToken(map[string]any{"alg": "RS256"}, map[string]any{"sub": "1", "exp": exp})
	findings := analyseToken("example.com", token)
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTLongExpiry {
			t.Errorf("unexpected expiry finding for 1-hour token")
		}
	}
}

// --- analyseToken: sensitive payload checks ---

func TestAnalyseToken_EmailInPayload_PIIFinding(t *testing.T) {
	exp := time.Now().Add(15 * time.Minute).Unix()
	token := makeToken(
		map[string]any{"alg": "RS256"},
		map[string]any{"sub": "1", "exp": exp, "email": "user@example.com"},
	)
	findings := analyseToken("example.com", token)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTSensitivePayload && f.Severity == finding.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Error("expected High PII finding for email in payload")
	}
}

func TestAnalyseToken_RoleInPayload_AuthFinding(t *testing.T) {
	exp := time.Now().Add(15 * time.Minute).Unix()
	token := makeToken(
		map[string]any{"alg": "RS256"},
		map[string]any{"sub": "1", "exp": exp, "role": "admin"},
	)
	findings := analyseToken("example.com", token)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTSensitivePayload && f.Severity == finding.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Error("expected Medium auth-claims finding for role in payload")
	}
}

func TestAnalyseToken_NoSensitiveFields_NoPayloadFinding(t *testing.T) {
	exp := time.Now().Add(15 * time.Minute).Unix()
	token := makeToken(
		map[string]any{"alg": "RS256"},
		map[string]any{"sub": "user123", "exp": exp, "name": "Alice"},
	)
	findings := analyseToken("example.com", token)
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTSensitivePayload {
			t.Errorf("unexpected sensitive-payload finding for innocuous token: %s", f.Title)
		}
	}
}

// --- analyseToken: malformed input ---

func TestAnalyseToken_InvalidBase64Header_NoFindings(t *testing.T) {
	findings := analyseToken("example.com", "!!!.payload.sig")
	if len(findings) != 0 {
		t.Errorf("expected no findings for invalid base64 header, got %d", len(findings))
	}
}

func TestAnalyseToken_OnlyOneSegment_NoFindings(t *testing.T) {
	findings := analyseToken("example.com", "notavalidjwt")
	if len(findings) != 0 {
		t.Errorf("expected no findings for single-segment string, got %d", len(findings))
	}
}

func TestAnalyseToken_EmptyToken_NoFindings(t *testing.T) {
	findings := analyseToken("example.com", "")
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty token, got %d", len(findings))
	}
}

// --- truncate ---

func TestTruncate_ShortString_Unchanged(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("expected unchanged string, got %q", got)
	}
}

func TestTruncate_LongString_Truncated(t *testing.T) {
	got := truncate("hello world", 5)
	if !strings.HasPrefix(got, "hello") {
		t.Errorf("truncated string should start with original prefix, got %q", got)
	}
	if len(got) <= 5 {
		t.Errorf("expected ellipsis appended, got %q", got)
	}
}

// --- JWKS key strength checks ---

// TestJWT_JWKSWeakRSAKey serves a JWKS document containing a 1024-bit RSA key
// (128-byte modulus) and asserts that checkJWKSKeys emits CheckJWKSWeakKey.
func TestJWT_JWKSWeakRSAKey(t *testing.T) {
	// 128 bytes = 1024-bit modulus (all 0xFF for simplicity; we only check length).
	weakModulus := base64.RawURLEncoding.EncodeToString(make([]byte, 128))
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"test-key-1","n":"%s","e":"AQAB"}]}`, weakModulus)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, jwks)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// Strip "http://" to get the host:port form that checkJWKSKeys expects.
	host := strings.TrimPrefix(srv.URL, "http://")
	findings := checkJWKSKeys(t.Context(), srv.Client(), host, srv.URL)

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWKSWeakKey {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected CheckJWKSWeakKey finding for 1024-bit RSA key, got findings: %v", findings)
	}
}

// TestJWT_JWKSMissingKID serves a JWKS document where the key has no "kid"
// field and asserts that checkJWKSKeys emits CheckJWKSMissingKID.
func TestJWT_JWKSMissingKID(t *testing.T) {
	// 256 bytes = 2048-bit modulus — strong enough, so only the missing-kid
	// finding should fire (not the weak-key finding).
	strongModulus := base64.RawURLEncoding.EncodeToString(make([]byte, 256))
	// Deliberately omit the "kid" field.
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","n":"%s","e":"AQAB"}]}`, strongModulus)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, jwks)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	findings := checkJWKSKeys(t.Context(), srv.Client(), host, srv.URL)

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWKSMissingKID {
			found = true
			if f.Severity != finding.SeverityMedium {
				t.Errorf("expected Medium severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected CheckJWKSMissingKID finding for key without kid, got findings: %v", findings)
	}
}

// ---------------------------------------------------------------------------
// allSensitiveFields integrity — verify that the package-level append
// does not mutate the underlying sensitiveDataFields slice.
// ---------------------------------------------------------------------------

func TestAllSensitiveFields_DoesNotMutateSensitiveDataFields(t *testing.T) {
	// sensitiveDataFields should not contain any of the role fields.
	for _, rf := range sensitiveRoleFields {
		for _, df := range sensitiveDataFields {
			if df == rf {
				t.Errorf("sensitiveDataFields was mutated — it now contains role field %q", rf)
			}
		}
	}
	// allSensitiveFields must contain both sets.
	if len(allSensitiveFields) != len(sensitiveDataFields)+len(sensitiveRoleFields) {
		t.Errorf("allSensitiveFields has %d entries, expected %d+%d=%d",
			len(allSensitiveFields),
			len(sensitiveDataFields), len(sensitiveRoleFields),
			len(sensitiveDataFields)+len(sensitiveRoleFields))
	}
}

// ---------------------------------------------------------------------------
// JWT found in large body — verify the 512 KB limit catches JWTs
// ---------------------------------------------------------------------------

func TestRun_JWTInLargeBody_Detected(t *testing.T) {
	// Create a page where a JWT appears after 8 KB of padding.
	exp := time.Now().Add(15 * time.Minute).Unix()
	token := makeToken(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"sub": "1", "exp": exp},
	)
	padding := strings.Repeat("x", 8192)
	body := padding + `<script>var token="` + token + `";</script>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for the catch-all canary path so the scanner does not
		// bail out with "catch-all server" detection.
		if strings.Contains(r.URL.Path, "beacon-probe-") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body)) //nolint:errcheck
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTWeakAlg {
			found = true
		}
	}
	if !found {
		t.Error("expected JWT finding for alg:none token embedded after 8KB of padding")
	}
}

// ---------------------------------------------------------------------------
// Deep-mode checks run under ScanAuthorized too
// ---------------------------------------------------------------------------

func TestRun_ScanAuthorized_RunsDeepChecks(t *testing.T) {
	// Serve a catch-all that returns 404 for all paths except the JWKS path
	// to ensure the scanner processes deep-mode checks under ScanAuthorized.
	// We use the alg:none variant check as a proxy for "deep checks ran".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return JSON for all API paths to make submitTokenProbe accept it.
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			// Accept any token — simulates a broken server for the test
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"user":"test","id":1}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Under ScanAuthorized, deep checks should run. The alg:none check
	// submits a forged token. Because our server accepts everything, we
	// should see the alg:none finding.
	var deepCheckRan bool
	for _, f := range findings {
		if f.CheckID == finding.CheckJWTAlgNoneVariant ||
			f.CheckID == finding.CheckJWTEmptySecret ||
			f.CheckID == finding.CheckJWTAlgorithmConfusion ||
			f.CheckID == finding.CheckJWTKidInjection {
			deepCheckRan = true
			break
		}
	}
	if !deepCheckRan {
		t.Error("expected deep-mode JWT checks to run under ScanAuthorized, but none fired")
	}
}

// ---------------------------------------------------------------------------
// analyseToken: JWE token (5 parts) — skipped, no panic
// ---------------------------------------------------------------------------

func TestAnalyseToken_JWE_5Parts_NoFindings(t *testing.T) {
	// JWE tokens have 5 base64url segments. The scanner should skip payload analysis.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM"}`))
	token := header + ".enc_key.iv.ciphertext.tag"
	findings := analyseToken("example.com", token)
	if len(findings) != 0 {
		t.Errorf("expected no findings for JWE token, got %d: %v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// analyseToken: no "alg" in header — must return nil (not a JWT)
// ---------------------------------------------------------------------------

func TestAnalyseToken_NoAlgHeader_NoFindings(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`))
	token := header + "." + payload + ".sig"
	findings := analyseToken("example.com", token)
	if len(findings) != 0 {
		t.Errorf("expected no findings for token without alg header, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Server returning empty response — no panic
// ---------------------------------------------------------------------------

func TestRun_EmptyResponse_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Intentionally empty body.
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings // must not panic
}

// TestOIDC_WeakSigningAlg spins up a mock OIDC discovery document that
// advertises "none" in id_token_signing_alg_values_supported and asserts that
// the oauth scanner emits CheckOIDCWeakSigningAlg (High severity).
func TestOIDC_WeakSigningAlg(t *testing.T) {
	discovery := `{
		"issuer": "https://example.com",
		"authorization_endpoint": "https://example.com/oauth/authorize",
		"token_endpoint": "https://example.com/oauth/token",
		"jwks_uri": "https://example.com/.well-known/jwks.json",
		"response_types_supported": ["code"],
		"id_token_signing_alg_values_supported": ["RS256", "none"]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, discovery)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := oauthscanner.New()
	findings, err := s.Run(t.Context(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("oauth scanner returned error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckOIDCWeakSigningAlg {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected CheckOIDCWeakSigningAlg finding for discovery doc with 'none' alg, got %d findings", len(findings))
	}
}

