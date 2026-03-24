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

