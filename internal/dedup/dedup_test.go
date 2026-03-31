package dedup

import (
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

func makeFinding(checkID, asset, title string, sev finding.Severity) finding.Finding {
	return finding.Finding{
		CheckID:      checkID,
		Asset:        asset,
		Title:        title,
		Severity:     sev,
		DiscoveredAt: time.Now(),
	}
}

func makeWithEvidence(checkID, asset, title string, sev finding.Severity, evidence map[string]any) finding.Finding {
	f := makeFinding(checkID, asset, title, sev)
	f.Evidence = evidence
	return f
}

// --- Unit tests for helpers ---

func TestCheckPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"tls.protocol_sslv2", "tls"},
		{"web.cors_misconfiguration", "web"},
		{"nuclei.s3_bucket_exposed", "nuclei"},
		{"email.spf_missing", "email"},
		{"nodot", "nodot"},
		{"", ""},
	}
	for _, tt := range tests {
		got := checkPrefix(tt.input)
		if got != tt.want {
			t.Errorf("checkPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBaseDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"*.example.com", "example.com"},
		{"com", "com"},
		{"", ""},
	}
	for _, tt := range tests {
		got := baseDomain(tt.input)
		if got != tt.want {
			t.Errorf("baseDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSameBaseDomain(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"api.example.com", "www.example.com", true},
		{"example.com", "sub.example.com", true},
		{"example.com", "other.com", false},
		{"a.example.com", "a.other.com", false},
	}
	for _, tt := range tests {
		got := sameBaseDomain(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("sameBaseDomain(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsMoreSpecific(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"sub.example.com", "example.com", true},
		{"example.com", "sub.example.com", false},
		{"a.b.example.com", "b.example.com", true},
		{"sub.example.com", "*.example.com", true},
		{"*.example.com", "sub.example.com", false},
		{"example.com", "example.com", false},
	}
	for _, tt := range tests {
		got := isMoreSpecific(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("isMoreSpecific(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestAssetOverlapConfidence(t *testing.T) {
	tests := []struct {
		a, b       string
		wantMin    float64
		wantMax    float64
		wantNonZero bool
	}{
		// Wildcard overlap
		{"*.example.com", "sub.example.com", 0.9, 0.9, true},
		{"sub.example.com", "*.example.com", 0.9, 0.9, true},
		{"*.example.com", "example.com", 0.9, 0.9, true},
		// Parent domain overlap
		{"example.com", "sub.example.com", 0.7, 0.7, true},
		{"sub.example.com", "example.com", 0.7, 0.7, true},
		// Same base domain, different subdomains
		{"api.example.com", "www.example.com", 0.3, 0.5, true},
		// No overlap
		{"example.com", "other.com", 0, 0, false},
		{"sub.example.com", "sub.other.com", 0, 0, false},
		// Same host
		{"example.com", "example.com", 0, 0, false},
	}
	for _, tt := range tests {
		got := assetOverlapConfidence(tt.a, tt.b)
		if tt.wantNonZero && got == 0 {
			t.Errorf("assetOverlapConfidence(%q, %q) = 0, want nonzero", tt.a, tt.b)
		}
		if !tt.wantNonZero && got != 0 {
			t.Errorf("assetOverlapConfidence(%q, %q) = %v, want 0", tt.a, tt.b, got)
		}
		if got < tt.wantMin || got > tt.wantMax {
			t.Errorf("assetOverlapConfidence(%q, %q) = %v, want [%v, %v]", tt.a, tt.b, got, tt.wantMin, tt.wantMax)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	// Verify ordering
	ranks := []struct {
		sev  finding.Severity
		rank int
	}{
		{finding.SeverityCritical, 5},
		{finding.SeverityHigh, 4},
		{finding.SeverityMedium, 3},
		{finding.SeverityLow, 2},
		{finding.SeverityInfo, 1},
	}
	for _, tt := range ranks {
		got := severityRank(tt.sev)
		if got != tt.rank {
			t.Errorf("severityRank(%v) = %d, want %d", tt.sev, got, tt.rank)
		}
	}
	// Verify strict ordering
	for i := 1; i < len(ranks); i++ {
		if severityRank(ranks[i-1].sev) <= severityRank(ranks[i].sev) {
			t.Errorf("expected %v > %v", ranks[i-1].sev, ranks[i].sev)
		}
	}
}

func TestCrossScannerConfidence(t *testing.T) {
	tests := []struct {
		a, b    string
		wantGt0 bool
	}{
		{"nuclei.misconfigured_cors", "web.cors_misconfiguration", true},
		{"web.cors_misconfiguration", "nuclei.misconfigured_cors", true}, // symmetric
		{"nuclei.s3_bucket_exposed", "cloud.bucket_public", true},
		{"dirbust.path_found", "exposure.admin_path", true},
		{"subdomain.takeover", "dns.dangling_cname", true},
		// No known overlap
		{"tls.protocol_sslv2", "email.spf_missing", false},
		{"web.xss", "web.sqli", false},
	}
	for _, tt := range tests {
		got := crossScannerConfidence(tt.a, tt.b)
		if tt.wantGt0 && got == 0 {
			t.Errorf("crossScannerConfidence(%q, %q) = 0, want >0", tt.a, tt.b)
		}
		if !tt.wantGt0 && got != 0 {
			t.Errorf("crossScannerConfidence(%q, %q) = %v, want 0", tt.a, tt.b, got)
		}
	}
}

// --- Integration tests for FlagDuplicates ---

func TestFlagDuplicates_EmptyAndSingle(t *testing.T) {
	// Empty slice — no panic.
	FlagDuplicates(nil)
	FlagDuplicates([]finding.Finding{})

	// Single finding — nothing to duplicate.
	findings := []finding.Finding{
		makeFinding("tls.protocol_sslv2", "example.com", "SSLv2 Enabled", finding.SeverityCritical),
	}
	FlagDuplicates(findings)
	if findings[0].DuplicateOf != "" {
		t.Error("single finding should not be marked as duplicate")
	}
}

func TestFlagDuplicates_NoOverlap(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("tls.protocol_sslv2", "a.example.com", "SSLv2", finding.SeverityCritical),
		makeFinding("email.spf_missing", "b.other.com", "SPF Missing", finding.SeverityHigh),
		makeFinding("web.xss", "c.different.com", "XSS", finding.SeverityMedium),
	}
	FlagDuplicates(findings)
	for i, f := range findings {
		if f.DuplicateOf != "" {
			t.Errorf("finding[%d] should not be duplicate, got DuplicateOf=%q", i, f.DuplicateOf)
		}
	}
}

func TestFlagDuplicates_WildcardOverlap(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("tls.cert_expiry_7d", "api.example.com", "Cert Expiry", finding.SeverityHigh),
		makeFinding("tls.cert_expiry_7d", "*.example.com", "Cert Expiry", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	// The wildcard finding should be flagged as duplicate of the specific one.
	if findings[0].DuplicateOf != "" {
		t.Error("specific subdomain finding should not be flagged")
	}
	if findings[1].DuplicateOf == "" {
		t.Error("wildcard finding should be flagged as duplicate")
	}
	if findings[1].DuplicateConfidence < 0.8 {
		t.Errorf("wildcard overlap confidence should be high, got %v", findings[1].DuplicateConfidence)
	}
}

func TestFlagDuplicates_ParentDomainOverlap(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("headers.missing_hsts", "sub.example.com", "Missing HSTS", finding.SeverityMedium),
		makeFinding("headers.missing_hsts", "example.com", "Missing HSTS", finding.SeverityMedium),
	}
	FlagDuplicates(findings)

	// One of them should be flagged.
	flagged := 0
	for _, f := range findings {
		if f.DuplicateOf != "" {
			flagged++
		}
	}
	if flagged != 1 {
		t.Errorf("expected exactly 1 duplicate flag, got %d", flagged)
	}
}

func TestFlagDuplicates_CrossScanner_CORS(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("web.cors_misconfiguration", "api.example.com", "CORS Misconfiguration", finding.SeverityHigh),
		makeFinding("nuclei.misconfigured_cors", "api.example.com", "CORS Misconfigured", finding.SeverityMedium),
	}
	FlagDuplicates(findings)

	// Nuclei finding (lower severity) should be flagged as duplicate.
	if findings[0].DuplicateOf != "" {
		t.Error("higher-severity finding should not be flagged")
	}
	if findings[1].DuplicateOf == "" {
		t.Error("nuclei CORS finding should be flagged as duplicate of beacon CORS finding")
	}
	if findings[1].DuplicateConfidence < 0.9 {
		t.Errorf("CORS cross-scanner confidence should be >=0.9, got %v", findings[1].DuplicateConfidence)
	}
}

func TestFlagDuplicates_CrossScanner_S3(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("cloud.bucket_public", "acme-exports", "Public S3 Bucket", finding.SeverityCritical),
		makeFinding("nuclei.s3_bucket_exposed", "acme-exports", "S3 Bucket Exposed", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	if findings[0].DuplicateOf != "" {
		t.Error("cloud scanner finding should not be flagged")
	}
	if findings[1].DuplicateOf == "" {
		t.Error("nuclei S3 finding should be flagged as duplicate")
	}
}

func TestFlagDuplicates_CrossScanner_SubdomainTakeover(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("dns.dangling_cname", "old.example.com", "Dangling CNAME", finding.SeverityMedium),
		makeFinding("subdomain.takeover", "old.example.com", "Subdomain Takeover", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	// dangling_cname should be flagged (lower severity).
	if findings[0].DuplicateOf == "" {
		t.Error("dangling CNAME should be flagged as duplicate of takeover")
	}
	if findings[1].DuplicateOf != "" {
		t.Error("takeover finding (higher severity) should not be flagged")
	}
}

func TestFlagDuplicates_CrossScanner_DirbustAdmin(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("exposure.admin_path", "admin.example.com", "Admin Panel Exposed", finding.SeverityHigh),
		makeFinding("dirbust.path_found", "admin.example.com", "Found /admin", finding.SeverityMedium),
	}
	FlagDuplicates(findings)

	if findings[0].DuplicateOf != "" {
		t.Error("exposure finding should not be flagged")
	}
	if findings[1].DuplicateOf == "" {
		t.Error("dirbust finding should be flagged as duplicate of exposure finding")
	}
}

func TestFlagDuplicates_EvidenceFingerprint(t *testing.T) {
	evidence := map[string]any{
		"url":         "https://api.example.com/.git/config",
		"status_code": "200",
	}

	findings := []finding.Finding{
		makeWithEvidence("exposure.git_exposed", "api.example.com", "Git Exposed", finding.SeverityHigh, evidence),
		makeWithEvidence("dirbust.path_found", "api.example.com", "Found /.git/config", finding.SeverityMedium, evidence),
	}
	FlagDuplicates(findings)

	// These should be flagged via cross-scanner OR evidence overlap.
	flagged := 0
	for _, f := range findings {
		if f.DuplicateOf != "" {
			flagged++
		}
	}
	if flagged < 1 {
		t.Error("expected at least 1 finding flagged via evidence or cross-scanner overlap")
	}
}

func TestFlagDuplicates_EvidenceFingerprint_DifferentChecks(t *testing.T) {
	evidence := map[string]any{
		"url":         "https://api.example.com/debug/vars",
		"status_code": "200",
	}

	findings := []finding.Finding{
		makeWithEvidence("web.debug_endpoint", "api.example.com", "Debug Endpoint", finding.SeverityHigh, evidence),
		makeWithEvidence("exposure.spring_actuator", "api.example.com", "Spring Actuator", finding.SeverityHigh, evidence),
	}
	FlagDuplicates(findings)

	// Same URL and status from different checks — evidence dedup should fire.
	flagged := 0
	for _, f := range findings {
		if f.DuplicateOf != "" {
			flagged++
		}
	}
	if flagged != 1 {
		t.Errorf("expected 1 evidence duplicate flag, got %d", flagged)
	}
}

func TestFlagDuplicates_NoFalsePositive_DifferentAssets(t *testing.T) {
	// Same check on genuinely different assets — should NOT be flagged.
	findings := []finding.Finding{
		makeFinding("tls.cert_expiry_7d", "api.example.com", "Cert Expiry", finding.SeverityHigh),
		makeFinding("tls.cert_expiry_7d", "api.other.com", "Cert Expiry", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	for i, f := range findings {
		if f.DuplicateOf != "" {
			t.Errorf("finding[%d] on different domain should not be flagged", i)
		}
	}
}

func TestFlagDuplicates_NoFalsePositive_SameAssetDifferentChecks(t *testing.T) {
	// Different vulnerability types on same asset — NOT duplicates.
	findings := []finding.Finding{
		makeFinding("tls.protocol_sslv2", "api.example.com", "SSLv2", finding.SeverityCritical),
		makeFinding("headers.missing_hsts", "api.example.com", "Missing HSTS", finding.SeverityMedium),
		makeFinding("email.spf_missing", "api.example.com", "SPF Missing", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	for i, f := range findings {
		if f.DuplicateOf != "" {
			t.Errorf("finding[%d] (%s) should not be flagged as duplicate of unrelated check", i, f.CheckID)
		}
	}
}

func TestFlagDuplicates_MultipleOverlaps(t *testing.T) {
	// Complex scenario: multiple overlapping findings.
	findings := []finding.Finding{
		makeFinding("web.cors_misconfiguration", "api.example.com", "CORS Misconfig", finding.SeverityHigh),
		makeFinding("nuclei.misconfigured_cors", "api.example.com", "CORS Nuclei", finding.SeverityMedium),
		makeFinding("web.cors_null_origin", "api.example.com", "CORS Null Origin", finding.SeverityHigh),
		makeFinding("tls.cert_expiry_7d", "api.example.com", "Cert Expiry", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	// nuclei.misconfigured_cors should be flagged (overlaps with web.cors_misconfiguration)
	if findings[1].DuplicateOf == "" {
		t.Error("nuclei CORS should be flagged")
	}

	// TLS finding should NOT be flagged.
	if findings[3].DuplicateOf != "" {
		t.Error("TLS finding should not be flagged as CORS duplicate")
	}
}

func TestFlagDuplicates_AlreadyFlagged(t *testing.T) {
	// A finding already flagged should not be re-flagged.
	findings := []finding.Finding{
		makeFinding("web.cors_misconfiguration", "api.example.com", "CORS", finding.SeverityHigh),
		makeFinding("nuclei.misconfigured_cors", "api.example.com", "CORS", finding.SeverityMedium),
		makeFinding("web.cors_null_origin", "api.example.com", "CORS Null", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	// Count how many are flagged.
	flagged := 0
	for _, f := range findings {
		if f.DuplicateOf != "" {
			flagged++
		}
	}
	// nuclei should be flagged by cross-scanner overlap.
	// cors_null_origin might or might not be flagged (it overlaps with nuclei too).
	// But the main finding (cors_misconfiguration) should NOT be flagged.
	if findings[0].DuplicateOf != "" {
		t.Error("primary CORS finding should not be flagged")
	}
	if findings[1].DuplicateOf == "" {
		t.Error("nuclei CORS finding should be flagged")
	}
}

func TestFlagDuplicates_SeverityPreference(t *testing.T) {
	// When two findings overlap, the higher-severity one should be kept.
	findings := []finding.Finding{
		makeFinding("nuclei.misconfigured_cors", "api.example.com", "CORS Nuclei", finding.SeverityCritical),
		makeFinding("web.cors_misconfiguration", "api.example.com", "CORS Beacon", finding.SeverityMedium),
	}
	FlagDuplicates(findings)

	// The critical nuclei finding should be kept, medium beacon finding should be duplicate.
	if findings[0].DuplicateOf != "" {
		t.Error("critical-severity finding should not be flagged")
	}
	if findings[1].DuplicateOf == "" {
		t.Error("medium-severity finding should be flagged as duplicate of critical one")
	}
}

func TestFlagDuplicates_FindingKey(t *testing.T) {
	f := makeFinding("tls.cert_expiry_7d", "api.example.com", "Cert Expiry", finding.SeverityHigh)
	key := findingKey(f)
	want := "tls.cert_expiry_7d|api.example.com|Cert Expiry"
	if key != want {
		t.Errorf("findingKey() = %q, want %q", key, want)
	}
}

func TestFlagDuplicates_LargeSet(t *testing.T) {
	// Verify performance doesn't degrade badly with many findings.
	var findings []finding.Finding
	assets := []string{"api.example.com", "www.example.com", "app.example.com", "*.example.com"}
	checks := []string{"tls.cert_expiry_7d", "headers.missing_hsts", "email.spf_missing", "web.cors_misconfiguration"}

	for _, asset := range assets {
		for _, check := range checks {
			findings = append(findings, makeFinding(check, asset, "Title", finding.SeverityMedium))
		}
	}

	FlagDuplicates(findings)

	// Just verify it doesn't panic and runs in reasonable time.
	// Wildcard findings should be flagged for checks that also fire on specific subdomains.
	wildcardFlagged := 0
	for _, f := range findings {
		if f.Asset == "*.example.com" && f.DuplicateOf != "" {
			wildcardFlagged++
		}
	}
	if wildcardFlagged == 0 {
		t.Error("expected some wildcard findings to be flagged as duplicates")
	}
}

func TestFlagDuplicates_EvidenceWithoutURL(t *testing.T) {
	// Evidence without URL should not cause evidence dedup to fire.
	findings := []finding.Finding{
		makeWithEvidence("web.xss", "api.example.com", "XSS", finding.SeverityHigh, map[string]any{
			"payload": "<script>alert(1)</script>",
		}),
		makeWithEvidence("web.sqli", "api.example.com", "SQLi", finding.SeverityHigh, map[string]any{
			"payload": "' OR 1=1 --",
		}),
	}
	FlagDuplicates(findings)

	for i, f := range findings {
		if f.DuplicateOf != "" {
			t.Errorf("finding[%d] without URL evidence should not be flagged via evidence dedup", i)
		}
	}
}

func TestFlagDuplicates_SameSiblingSubdomains(t *testing.T) {
	// Same check on sibling subdomains (same base domain) — low confidence flag.
	findings := []finding.Finding{
		makeFinding("tls.cert_expiry_7d", "api.example.com", "Cert Expiry", finding.SeverityHigh),
		makeFinding("tls.cert_expiry_7d", "www.example.com", "Cert Expiry", finding.SeverityHigh),
	}
	FlagDuplicates(findings)

	// Should be flagged with low confidence since they share the same base domain.
	flagged := 0
	for _, f := range findings {
		if f.DuplicateOf != "" {
			flagged++
			if f.DuplicateConfidence > 0.5 {
				t.Errorf("sibling subdomain overlap should have low confidence, got %v", f.DuplicateConfidence)
			}
		}
	}
	if flagged != 1 {
		t.Errorf("expected exactly 1 sibling duplicate flag, got %d", flagged)
	}
}
