package enrichment

import (
	"context"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestAnonymizer_BasicIPReplacement(t *testing.T) {
	anon := NewAnonymizer()
	findings := []finding.Finding{
		{
			CheckID:     "tls.certificate_expired",
			Asset:       "192.168.1.100:443",
			Title:       "TLS certificate expired on 192.168.1.100",
			Description: "The server at 192.168.1.100 has an expired certificate",
		},
	}

	anonFindings, _ := anon.AnonymizeFindings(findings, "")
	f := anonFindings[0]

	if strings.Contains(f.Asset, "192.168.1.100") {
		t.Errorf("asset still contains IP: %s", f.Asset)
	}
	if strings.Contains(f.Title, "192.168.1.100") {
		t.Errorf("title still contains IP: %s", f.Title)
	}
	if strings.Contains(f.Description, "192.168.1.100") {
		t.Errorf("description still contains IP: %s", f.Description)
	}

	// All occurrences should use the same token.
	if !strings.Contains(f.Asset, "[IP-") {
		t.Errorf("asset missing IP token: %s", f.Asset)
	}
	if !strings.Contains(f.Title, "[IP-") {
		t.Errorf("title missing IP token: %s", f.Title)
	}
}

func TestAnonymizer_HostnameReplacement(t *testing.T) {
	anon := NewAnonymizer()
	findings := []finding.Finding{
		{
			CheckID: "web.cors_wildcard",
			Asset:   "api.example.com",
			Title:   "CORS wildcard on api.example.com",
		},
	}

	anonFindings, anonDomain := anon.AnonymizeFindings(findings, "example.com")
	f := anonFindings[0]

	if strings.Contains(f.Asset, "example.com") {
		t.Errorf("asset still contains hostname: %s", f.Asset)
	}
	if strings.Contains(anonDomain, "example.com") {
		t.Errorf("domain still contains hostname: %s", anonDomain)
	}

	// api.example.com should get its own token distinct from example.com
	if !strings.Contains(f.Asset, "[HOST-") {
		t.Errorf("asset missing HOST token: %s", f.Asset)
	}
}

func TestAnonymizer_ConsistentTokens(t *testing.T) {
	anon := NewAnonymizer()
	findings := []finding.Finding{
		{CheckID: "a", Asset: "10.0.0.1", Title: "first 10.0.0.1"},
		{CheckID: "b", Asset: "10.0.0.1", Title: "second 10.0.0.1"},
		{CheckID: "c", Asset: "10.0.0.2", Title: "different IP 10.0.0.2"},
	}

	anonFindings, _ := anon.AnonymizeFindings(findings, "")

	// Same IP should get same token.
	if anonFindings[0].Asset != anonFindings[1].Asset {
		t.Errorf("same IP got different tokens: %s vs %s", anonFindings[0].Asset, anonFindings[1].Asset)
	}

	// Different IP should get different token.
	if anonFindings[0].Asset == anonFindings[2].Asset {
		t.Errorf("different IPs got same token: %s", anonFindings[0].Asset)
	}
}

func TestAnonymizer_Deanonymize(t *testing.T) {
	anon := NewAnonymizer()
	findings := []finding.Finding{
		{
			CheckID:     "tls.weak_cipher",
			Asset:       "staging.corp.net:443",
			Title:       "Weak cipher suite on staging.corp.net",
			Description: "Server 10.20.30.40 uses CBC mode ciphers",
		},
	}

	anonFindings, _ := anon.AnonymizeFindings(findings, "corp.net")

	// The AI response would contain anonymized tokens.
	aiResponse := "The server " + anonFindings[0].Asset + " has weak ciphers. Update the TLS config."
	restored := anon.Deanonymize(aiResponse)

	if !strings.Contains(restored, "staging.corp.net") {
		t.Errorf("deanonymize failed to restore hostname: %s", restored)
	}
}

func TestAnonymizer_DeanonymizeEnrichedFindings(t *testing.T) {
	anon := NewAnonymizer()
	findings := []finding.Finding{
		{
			CheckID: "web.sqli",
			Asset:   "api.target.com",
			Title:   "SQL injection on api.target.com",
		},
	}

	anonFindings, _ := anon.AnonymizeFindings(findings, "target.com")
	anonAsset := anonFindings[0].Asset

	enriched := []EnrichedFinding{
		{
			Finding:     anonFindings[0],
			Explanation: "The application at " + anonAsset + " is vulnerable to SQL injection.",
			Impact:      "An attacker can extract data from " + anonAsset + ".",
			Remediation: "1. Update " + anonAsset + " to use parameterized queries.",
		},
	}

	restored := anon.DeanonymizeEnrichedFindings(enriched)

	if !strings.Contains(restored[0].Finding.Asset, "api.target.com") {
		t.Errorf("asset not restored: %s", restored[0].Finding.Asset)
	}
	if !strings.Contains(restored[0].Explanation, "api.target.com") {
		t.Errorf("explanation not restored: %s", restored[0].Explanation)
	}
	if !strings.Contains(restored[0].Impact, "api.target.com") {
		t.Errorf("impact not restored: %s", restored[0].Impact)
	}
	if !strings.Contains(restored[0].Remediation, "api.target.com") {
		t.Errorf("remediation not restored: %s", restored[0].Remediation)
	}
}

func TestAnonymizer_OriginalUnmodified(t *testing.T) {
	anon := NewAnonymizer()
	original := finding.Finding{
		CheckID: "port.redis_unauthenticated",
		Asset:   "10.0.0.5:6379",
		Title:   "Redis exposed on 10.0.0.5",
	}

	findings := []finding.Finding{original}
	anon.AnonymizeFindings(findings, "")

	// Original slice element should be unchanged.
	if findings[0].Asset != "10.0.0.5:6379" {
		t.Errorf("original finding was modified: %s", findings[0].Asset)
	}
	if findings[0].Title != "Redis exposed on 10.0.0.5" {
		t.Errorf("original title was modified: %s", findings[0].Title)
	}
}

func TestAnonymizer_LongestMatchFirst(t *testing.T) {
	anon := NewAnonymizer()
	findings := []finding.Finding{
		{CheckID: "a", Asset: "api.example.com"},
		{CheckID: "b", Asset: "example.com"},
	}

	anonFindings, _ := anon.AnonymizeFindings(findings, "example.com")

	// "api.example.com" should be a single token, not "[HOST-x].example.com"
	// or "api.[HOST-y]".
	if strings.Contains(anonFindings[0].Asset, ".") {
		t.Errorf("api.example.com was partially replaced: %s", anonFindings[0].Asset)
	}
}

func TestAnonymizer_PortPreserved(t *testing.T) {
	anon := NewAnonymizer()
	findings := []finding.Finding{
		{CheckID: "a", Asset: "db.internal:5432"},
	}

	anonFindings, _ := anon.AnonymizeFindings(findings, "")
	asset := anonFindings[0].Asset

	// Port should still be there, hostname replaced.
	if !strings.Contains(asset, ":5432") {
		t.Errorf("port was stripped from asset: %s", asset)
	}
	if strings.Contains(asset, "db.internal") {
		t.Errorf("hostname not anonymized: %s", asset)
	}
}

// fakeEnricher is a test double that records what it receives.
type fakeEnricher struct {
	receivedFindings []finding.Finding
	receivedDomain   string
	enrichedAssets   []string
}

func (fe *fakeEnricher) Enrich(_ context.Context, findings []finding.Finding) ([]EnrichedFinding, error) {
	fe.receivedFindings = findings
	out := make([]EnrichedFinding, len(findings))
	for i, f := range findings {
		fe.enrichedAssets = append(fe.enrichedAssets, f.Asset)
		out[i] = EnrichedFinding{
			Finding:     f,
			Explanation: "Issue on " + f.Asset,
		}
	}
	return out, nil
}

func (fe *fakeEnricher) ContextualizeAndSummarize(_ context.Context, enriched []EnrichedFinding, domain string) ([]EnrichedFinding, string, error) {
	fe.receivedDomain = domain
	return enriched, "Summary for " + domain, nil
}

func (fe *fakeEnricher) AnalyzeAttackPaths(_ context.Context, _ []EnrichedFinding, domain string) (string, error) {
	return "Attack paths for " + domain, nil
}

func (fe *fakeEnricher) GenerateFollowUpProbes(_ context.Context, _ []EnrichedFinding, _ string) ([]FollowUpProbe, error) {
	return nil, nil
}

func (fe *fakeEnricher) EnrichFingerprints(_ context.Context, inputs []FingerprintInput) (*FingerprintResult, error) {
	return &FingerprintResult{}, nil
}

func TestAnonymizingEnricher_EnrichHidesAndRestores(t *testing.T) {
	fake := &fakeEnricher{}
	ae := NewAnonymizingEnricher(fake)

	findings := []finding.Finding{
		{
			CheckID: "web.cors_wildcard",
			Asset:   "api.secret-corp.com:443",
			Title:   "CORS misconfiguration on api.secret-corp.com",
		},
	}

	enriched, err := ae.Enrich(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}

	// The inner enricher should NOT have seen the real hostname.
	for _, asset := range fake.enrichedAssets {
		if strings.Contains(asset, "secret-corp") {
			t.Errorf("inner enricher saw real hostname: %s", asset)
		}
	}

	// The returned enriched findings should have the real hostname restored.
	if !strings.Contains(enriched[0].Finding.Asset, "api.secret-corp.com") {
		t.Errorf("asset not restored: %s", enriched[0].Finding.Asset)
	}
	if !strings.Contains(enriched[0].Explanation, "api.secret-corp.com") {
		t.Errorf("explanation not restored: %s", enriched[0].Explanation)
	}
}

func TestAnonymizingEnricher_SummarizeHidesAndRestores(t *testing.T) {
	fake := &fakeEnricher{}
	ae := NewAnonymizingEnricher(fake)

	findings := []finding.Finding{
		{CheckID: "a", Asset: "10.0.0.5"},
	}

	// Prime the anonymizer by running Enrich first (as the real pipeline does).
	enriched, _ := ae.Enrich(context.Background(), findings)

	result, summary, err := ae.ContextualizeAndSummarize(context.Background(), enriched, "secret-corp.com")
	if err != nil {
		t.Fatal(err)
	}

	// Inner should not have seen the real domain.
	if strings.Contains(fake.receivedDomain, "secret-corp") {
		t.Errorf("inner enricher saw real domain: %s", fake.receivedDomain)
	}

	// Output should be deanonymized.
	if strings.Contains(summary, "[HOST-") {
		t.Errorf("summary still contains token: %s", summary)
	}
	_ = result
}
