package analyze_test

import (
	"context"
	"testing"

	"github.com/stormbane/beacon/internal/analyze"
	"github.com/stormbane/beacon/internal/finding"
	memstore "github.com/stormbane/beacon/internal/store/memory"
)

// TestDeterministicRulesSameAssetFires verifies that a sameAsset rule fires
// when both required checks appear on the same asset.
func TestDeterministicRulesSameAssetFires(t *testing.T) {
	st := memstore.New()
	domain := "example.com"
	runID := completedRun(t, st, domain)

	// Both checks on the same asset — rule should fire.
	addFinding(t, st, runID, "app.example.com", finding.CheckGHActionSecretsEchoed, finding.SeverityHigh)
	addFinding(t, st, runID, "app.example.com", finding.CheckGHActionDeployTargets, finding.SeverityInfo)

	results, err := analyze.RunDeterministicCorrelations(context.Background(), st, runID, domain)
	if err != nil {
		t.Fatalf("RunDeterministicCorrelations: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least 1 correlation; got 0")
	}

	// Verify the firing rule has the right check ID.
	found := false
	for _, r := range results {
		for _, cc := range r.ContributingChecks {
			if cc == string(finding.CheckGHActionSecretsEchoed) {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected CheckGHActionSecretsEchoed in contributing checks")
	}
}

// TestDeterministicRulesSameAssetNoFire verifies that a sameAsset rule does NOT
// fire when the required checks are spread across different assets.
func TestDeterministicRulesSameAssetNoFire(t *testing.T) {
	st := memstore.New()
	domain := "example.com"
	runID := completedRun(t, st, domain)

	// Checks on different assets — sameAsset rule must NOT fire.
	addFinding(t, st, runID, "app.example.com", finding.CheckGHActionSecretsEchoed, finding.SeverityHigh)
	addFinding(t, st, runID, "ci.example.com", finding.CheckGHActionDeployTargets, finding.SeverityInfo)

	results, err := analyze.RunDeterministicCorrelations(context.Background(), st, runID, domain)
	if err != nil {
		t.Fatalf("RunDeterministicCorrelations: %v", err)
	}
	// The sameAsset CICD rule must not have fired.
	for _, r := range results {
		for _, cc := range r.ContributingChecks {
			if cc == string(finding.CheckGHActionSecretsEchoed) {
				t.Errorf("sameAsset CICD rule should not fire when checks are on different assets; got: %v", r.Title)
			}
		}
	}
}

// TestDeterministicRulesCrossAssetFires verifies that a cross-asset rule fires
// when the required checks appear on different assets in the same scan run.
func TestDeterministicRulesCrossAssetFires(t *testing.T) {
	st := memstore.New()
	domain := "example.com"
	runID := completedRun(t, st, domain)

	// Two different assets — cross-asset StagingToProd rule should fire.
	addFinding(t, st, runID, "staging.example.com", finding.CheckDLPAPIKey, finding.SeverityHigh)
	addFinding(t, st, runID, "api.example.com", finding.CheckDLPDatabaseURL, finding.SeverityHigh)

	results, err := analyze.RunDeterministicCorrelations(context.Background(), st, runID, domain)
	if err != nil {
		t.Fatalf("RunDeterministicCorrelations: %v", err)
	}

	found := false
	for _, r := range results {
		if r.Domain == domain && r.Severity == finding.SeverityHigh {
			// Should include both assets.
			if len(r.AffectedAssets) >= 2 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected cross-asset correlation with 2+ affected assets; got %v", results)
	}
}

// TestDeterministicRulesPartialMatchNoFire verifies that a rule with only one
// of its two required checks does not produce a correlation.
func TestDeterministicRulesPartialMatchNoFire(t *testing.T) {
	st := memstore.New()
	domain := "example.com"
	runID := completedRun(t, st, domain)

	// Only one of the two required checks is present.
	addFinding(t, st, runID, "app.example.com", finding.CheckGHActionSecretsEchoed, finding.SeverityHigh)
	// CheckGHActionDeployTargets is absent.

	results, err := analyze.RunDeterministicCorrelations(context.Background(), st, runID, domain)
	if err != nil {
		t.Fatalf("RunDeterministicCorrelations: %v", err)
	}
	// No CICD correlation should fire with only one check.
	for _, r := range results {
		for _, cc := range r.ContributingChecks {
			if cc == string(finding.CheckGHActionSecretsEchoed) &&
				contains(r.ContributingChecks, string(finding.CheckGHActionDeployTargets)) {
				t.Errorf("rule should not fire with partial match; got: %v", r.Title)
			}
		}
	}
}

// TestDeterministicRulesNoFindings verifies that an empty findings list
// returns nil without error and stores nothing.
func TestDeterministicRulesNoFindings(t *testing.T) {
	st := memstore.New()
	domain := "empty.com"
	runID := completedRun(t, st, domain)

	results, err := analyze.RunDeterministicCorrelations(context.Background(), st, runID, domain)
	if err != nil {
		t.Fatalf("RunDeterministicCorrelations: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty findings; got %d", len(results))
	}
}

// TestDeterministicRulesDeduplication verifies that the same rule title is
// not emitted twice even if multiple conditions could trigger it.
func TestDeterministicRulesDeduplication(t *testing.T) {
	st := memstore.New()
	domain := "example.com"
	runID := completedRun(t, st, domain)

	// Set up conditions that would trigger the email+login rule via BOTH variants:
	// variant 1: CheckEmailDMARCMissing + CheckOAuthMissingState
	// variant 2: CheckEmailDMARCPolicyNone + CheckOAuthMissingState
	// But both variants have the same title, so only one should fire.
	addFinding(t, st, runID, "example.com", finding.CheckEmailDMARCMissing, finding.SeverityMedium)
	addFinding(t, st, runID, "example.com", finding.CheckEmailDMARCPolicyNone, finding.SeverityMedium)
	addFinding(t, st, runID, "login.example.com", finding.CheckOAuthMissingState, finding.SeverityMedium)

	results, err := analyze.RunDeterministicCorrelations(context.Background(), st, runID, domain)
	if err != nil {
		t.Fatalf("RunDeterministicCorrelations: %v", err)
	}

	titleCount := make(map[string]int)
	for _, r := range results {
		titleCount[r.Title]++
	}
	for title, count := range titleCount {
		if count > 1 {
			t.Errorf("title %q emitted %d times; want at most 1 (dedup failed)", title, count)
		}
	}
}

// TestDeterministicRulesPlainFindingSaved verifies that when a rule fires, a
// regular finding.Finding is also saved (so it appears in the TUI).
func TestDeterministicRulesPlainFindingSaved(t *testing.T) {
	st := memstore.New()
	domain := "example.com"
	runID := completedRun(t, st, domain)

	addFinding(t, st, runID, "app.example.com", finding.CheckGHActionSecretsEchoed, finding.SeverityHigh)
	addFinding(t, st, runID, "app.example.com", finding.CheckGHActionDeployTargets, finding.SeverityInfo)

	_, err := analyze.RunDeterministicCorrelations(context.Background(), st, runID, domain)
	if err != nil {
		t.Fatalf("RunDeterministicCorrelations: %v", err)
	}

	// The scan run should now contain additional findings from the correlation engine.
	allFindings, err := st.GetFindings(context.Background(), runID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	// We seeded 2 findings; after correlation, there should be more.
	if len(allFindings) <= 2 {
		t.Errorf("expected >2 findings after correlation (plain finding not saved); got %d", len(allFindings))
	}

	// The correlation finding should have scanner="deterministicrules".
	foundCorr := false
	for _, f := range allFindings {
		if f.Scanner == "deterministicrules" {
			foundCorr = true
			if f.ProofCommand == "" {
				t.Error("correlation plain finding is missing ProofCommand")
			}
			break
		}
	}
	if !foundCorr {
		t.Error("no plain finding with scanner='deterministicrules' found")
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
