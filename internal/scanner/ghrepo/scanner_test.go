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
	content := "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012"
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
