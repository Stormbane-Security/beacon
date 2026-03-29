package ghrepo

import (
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// -------------------------------------------------------------------------
// checkRepoConfig
// -------------------------------------------------------------------------

func TestCheckRepoConfig_SecretScanningDisabled(t *testing.T) {
	meta := ghRepoMeta{}
	meta.SecurityAndAnalysis.SecretScanning.Status = "disabled"
	meta.SecurityAndAnalysis.SecretScanningPushProtection.Status = "enabled"

	findings := checkRepoConfig(meta, "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoSecretScanning)
	assertNotHasCheckID(t, findings, finding.CheckGitHubNoPushProtection)
}

func TestCheckRepoConfig_PushProtectionDisabled(t *testing.T) {
	meta := ghRepoMeta{}
	meta.SecurityAndAnalysis.SecretScanning.Status = "enabled"
	meta.SecurityAndAnalysis.SecretScanningPushProtection.Status = "disabled"

	findings := checkRepoConfig(meta, "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoPushProtection)
	assertNotHasCheckID(t, findings, finding.CheckGitHubNoSecretScanning)
}

func TestCheckRepoConfig_BothEnabled_NoFindings(t *testing.T) {
	meta := ghRepoMeta{}
	meta.SecurityAndAnalysis.SecretScanning.Status = "enabled"
	meta.SecurityAndAnalysis.SecretScanningPushProtection.Status = "enabled"

	findings := checkRepoConfig(meta, "org/repo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when both controls enabled, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// checkBranchProtection
// -------------------------------------------------------------------------

func TestBranchProtection_ForcePushAllowed(t *testing.T) {
	bp := ghBranchProtection{}
	bp.AllowForcePushes.Enabled = true

	findings := checkBranchProtection(bp, "main", "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoBranchProtection)
}

func TestBranchProtection_NoRequiredReviewers(t *testing.T) {
	bp := ghBranchProtection{
		RequiredPullRequestReviews: nil,
	}

	findings := checkBranchProtection(bp, "main", "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoBranchProtection)
}

func TestBranchProtection_StaleReviewsNotDismissed(t *testing.T) {
	bp := ghBranchProtection{
		RequiredPullRequestReviews: &struct {
			RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
			DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		}{
			RequiredApprovingReviewCount: 1,
			DismissStaleReviews:          false,
		},
	}

	findings := checkBranchProtection(bp, "main", "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoBranchProtection)
}

func TestBranchProtection_NoRequiredStatusChecks(t *testing.T) {
	bp := ghBranchProtection{
		RequiredPullRequestReviews: &struct {
			RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
			DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		}{
			RequiredApprovingReviewCount: 1,
			DismissStaleReviews:          true,
		},
		RequiredStatusChecks: nil,
	}

	findings := checkBranchProtection(bp, "main", "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoRequiredStatusChecks)
}

func TestBranchProtection_EmptyStatusChecks(t *testing.T) {
	bp := ghBranchProtection{
		RequiredStatusChecks: &struct {
			Strict   bool     `json:"strict"`
			Contexts []string `json:"contexts"`
			Checks   []struct {
				Context string `json:"context"`
			} `json:"checks"`
		}{
			Strict:   true,
			Contexts: []string{},
		},
	}

	findings := checkBranchProtection(bp, "main", "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoRequiredStatusChecks)
}

func TestBranchProtection_RequiredStatusChecks_NoFinding(t *testing.T) {
	bp := ghBranchProtection{
		RequiredPullRequestReviews: &struct {
			RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
			DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		}{
			RequiredApprovingReviewCount: 1,
			DismissStaleReviews:          true,
		},
		RequiredStatusChecks: &struct {
			Strict   bool     `json:"strict"`
			Contexts []string `json:"contexts"`
			Checks   []struct {
				Context string `json:"context"`
			} `json:"checks"`
		}{
			Strict:   true,
			Contexts: []string{"ci/build"},
		},
		RequireSignedCommits: &struct {
			Enabled bool `json:"enabled"`
		}{Enabled: true},
	}
	bp.AllowForcePushes.Enabled = false

	findings := checkBranchProtection(bp, "main", "org/repo")
	assertNotHasCheckID(t, findings, finding.CheckGitHubNoBranchProtection)
	assertNotHasCheckID(t, findings, finding.CheckGitHubNoRequiredStatusChecks)
	assertNotHasCheckID(t, findings, finding.CheckGitHubNoSignedCommits)
}

func TestBranchProtection_NoSignedCommits(t *testing.T) {
	bp := ghBranchProtection{
		RequireSignedCommits: nil,
	}

	findings := checkBranchProtection(bp, "main", "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoSignedCommits)
}

// -------------------------------------------------------------------------
// secret pattern tests
// -------------------------------------------------------------------------

func TestSecretPattern_AWSKey(t *testing.T) {
	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_GHPToken(t *testing.T) {
	content := "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXyz1234567890"
	findings := runSecretPatternsOnContent(content, "org/repo", "config.json")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_FineGrainedPAT(t *testing.T) {
	// github_pat_ followed by 82 alphanumeric/underscore chars
	pat := "github_pat_" + repeat("A", 82)
	content := "GITHUB_TOKEN=" + pat
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_PEMKey(t *testing.T) {
	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."
	findings := runSecretPatternsOnContent(content, "org/repo", "credentials.json")
	assertHasCheckID(t, findings, finding.CheckGitHubPrivateKeyInRepo)
}

func TestSecretPattern_NoMatch_NoFinding(t *testing.T) {
	content := "DATABASE_URL=postgres://localhost/mydb"
	findings := runSecretPatternsOnContent(content, "org/repo", "config.json")
	// DB URL without credentials should not match the credentialed pattern
	for _, f := range findings {
		if f.CheckID == finding.CheckGitHubSecretInCode {
			t.Errorf("unexpected secret finding for non-credentialed DB URL")
		}
	}
}

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

// runSecretPatternsOnContent runs all secretPatterns against a synthetic content string.
func runSecretPatternsOnContent(content, repoSlug, path string) []finding.Finding {
	var findings []finding.Finding
	for _, sp := range secretPatterns {
		if m := sp.pattern.FindString(content); m != "" {
			redacted := m
			if len(m) > 8 {
				redacted = m[:4] + "****" + m[len(m)-4:]
			}
			findings = append(findings, finding.Finding{
				CheckID:      sp.checkID,
				Module:       "github",
				Scanner:      scannerName,
				Severity:     finding.SeverityCritical,
				Asset:        repoSlug,
				Title:        sp.name + " found in " + path,
				Evidence:     map[string]any{"path": path, "match_redacted": redacted},
				DiscoveredAt: time.Now(),
			})
		}
	}
	return findings
}

func assertHasCheckID(t *testing.T, findings []finding.Finding, id finding.CheckID) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			return
		}
	}
	t.Errorf("expected finding with CheckID %q but none found (got %d findings)", id, len(findings))
}

func assertNotHasCheckID(t *testing.T, findings []finding.Finding, id finding.CheckID) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			t.Errorf("unexpected finding with CheckID %q", id)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, n*len(s))
	for i := range out {
		out[i] = s[i%len(s)]
	}
	return string(out)
}

// -------------------------------------------------------------------------
// splitOwnerRepo edge cases
// -------------------------------------------------------------------------

func TestSplitOwnerRepo_ValidTarget(t *testing.T) {
	owner, repo, ok := splitOwnerRepo("myorg/myrepo")
	if !ok {
		t.Fatal("expected ok=true for valid target")
	}
	if owner != "myorg" || repo != "myrepo" {
		t.Errorf("got owner=%q repo=%q, want myorg/myrepo", owner, repo)
	}
}

func TestSplitOwnerRepo_GitHubURL(t *testing.T) {
	owner, repo, ok := splitOwnerRepo("https://github.com/myorg/myrepo")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if owner != "myorg" || repo != "myrepo" {
		t.Errorf("got owner=%q repo=%q, want myorg/myrepo", owner, repo)
	}
}

func TestSplitOwnerRepo_TrailingPath(t *testing.T) {
	// Extra path segments beyond owner/repo should be discarded.
	owner, repo, ok := splitOwnerRepo("myorg/myrepo/tree/main/src")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if owner != "myorg" || repo != "myrepo" {
		t.Errorf("got owner=%q repo=%q, want myorg/myrepo", owner, repo)
	}
}

func TestSplitOwnerRepo_PathTraversal(t *testing.T) {
	// Path traversal attempt should be percent-encoded so it doesn't
	// escape the intended URL path position.
	owner, repo, ok := splitOwnerRepo("../../../etc/passwd")
	if !ok {
		// This is fine either way -- but if ok=true the values must be safe.
		t.Skip("splitOwnerRepo rejected traversal target")
	}
	if owner == "../../.." {
		t.Errorf("path traversal sequence was not sanitized: owner=%q repo=%q", owner, repo)
	}
}

func TestSplitOwnerRepo_Empty(t *testing.T) {
	_, _, ok := splitOwnerRepo("")
	if ok {
		t.Error("expected ok=false for empty target")
	}
}

func TestSplitOwnerRepo_OwnerOnly(t *testing.T) {
	_, _, ok := splitOwnerRepo("myorg")
	if ok {
		t.Error("expected ok=false for owner-only target")
	}
}

func TestSplitOwnerRepo_EmptyRepo(t *testing.T) {
	_, _, ok := splitOwnerRepo("myorg/")
	if ok {
		t.Error("expected ok=false for empty repo name")
	}
}

// -------------------------------------------------------------------------
// Webhook secret check: InsecureSSL should not suppress the finding
// -------------------------------------------------------------------------

func TestCheckRepoConfig_BothDisabled_BothFindings(t *testing.T) {
	meta := ghRepoMeta{}
	meta.SecurityAndAnalysis.SecretScanning.Status = "disabled"
	meta.SecurityAndAnalysis.SecretScanningPushProtection.Status = "disabled"

	findings := checkRepoConfig(meta, "org/repo")
	assertHasCheckID(t, findings, finding.CheckGitHubNoSecretScanning)
	assertHasCheckID(t, findings, finding.CheckGitHubNoPushProtection)
}

// -------------------------------------------------------------------------
// Secret pattern edge cases
// -------------------------------------------------------------------------

func TestSecretPattern_SlackBotToken(t *testing.T) {
	content := "SLACK_TOKEN=xoxb-1234567890-abcdefghij"
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_SlackWebhookURL(t *testing.T) {
	content := "https://hooks.slack.com/services/T00000000/B00000000/xxxxxxxxxxxxxxxxxxxx"
	findings := runSecretPatternsOnContent(content, "org/repo", "config.json")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_DatabaseURLWithCredentials(t *testing.T) {
	content := "DATABASE_URL=postgres://admin:s3cret@db.example.com/mydb"
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_DatabaseURLWithoutCredentials_NoFinding(t *testing.T) {
	content := "DATABASE_URL=postgres://localhost/mydb"
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertNotHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_SendGridKey(t *testing.T) {
	content := "SG.1234567890abcdefghijkl.1234567890abcdefghijklmnopqrstuvwxyz1234567"
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_GoogleAPIKey(t *testing.T) {
	// AIza + exactly 35 alphanumeric/underscore/hyphen chars.
	// Must end on a word character (\b boundary requires it).
	content := "GOOGLE_KEY=AIzaSyA0123456789abcdefghijklmnopqrstuv"
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_Redaction_ShortMatch(t *testing.T) {
	// Matches <= 8 characters should not be redacted (no panic on short strings).
	content := "-----BEGIN PRIVATE KEY-----"
	findings := runSecretPatternsOnContent(content, "org/repo", "key.pem")
	assertHasCheckID(t, findings, finding.CheckGitHubPrivateKeyInRepo)
}

func TestSecretPattern_PyPIToken(t *testing.T) {
	content := "PYPI_TOKEN=pypi-" + repeat("A", 40)
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_HuggingFaceToken(t *testing.T) {
	content := "HF_TOKEN=hf_" + repeat("A", 34)
	findings := runSecretPatternsOnContent(content, "org/repo", ".env")
	assertHasCheckID(t, findings, finding.CheckGitHubSecretInCode)
}

func TestSecretPattern_EmptyContent_NoMatch(t *testing.T) {
	findings := runSecretPatternsOnContent("", "org/repo", ".env")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for empty content, got %d", len(findings))
	}
}

func TestSecretPattern_BinaryContent_NoMatch(t *testing.T) {
	// Simulated binary content with null bytes — should not match.
	content := "\x00\x01\x02\x03\xff\xfe\xfd"
	findings := runSecretPatternsOnContent(content, "org/repo", "binary.dat")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for binary content, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// Branch protection edge cases
// -------------------------------------------------------------------------

func TestBranchProtection_AllConfiguredSecure_MinimalFindings(t *testing.T) {
	bp := ghBranchProtection{
		RequiredPullRequestReviews: &struct {
			RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
			DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		}{
			RequiredApprovingReviewCount: 2,
			DismissStaleReviews:          true,
		},
		RequiredStatusChecks: &struct {
			Strict   bool     `json:"strict"`
			Contexts []string `json:"contexts"`
			Checks   []struct {
				Context string `json:"context"`
			} `json:"checks"`
		}{
			Strict:   true,
			Contexts: []string{"ci/test", "ci/build"},
		},
		RequireSignedCommits: &struct {
			Enabled bool `json:"enabled"`
		}{Enabled: true},
	}
	bp.AllowForcePushes.Enabled = false
	bp.EnforceAdmins.Enabled = true

	findings := checkBranchProtection(bp, "main", "org/repo")
	// All protections enabled — should produce zero findings.
	if len(findings) != 0 {
		t.Errorf("expected zero findings for fully protected branch, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s - %s", f.CheckID, f.Title)
		}
	}
}
