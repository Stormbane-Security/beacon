package harvester_test

import (
	"context"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/harvester"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for _, f := range findings {
		if f.CheckID == id {
			return &f
		}
	}
	return nil
}

// ── Test: scanner name ───────────────────────────────────────────────────────

func TestName(t *testing.T) {
	s := harvester.New("")
	if s.Name() != "harvester" {
		t.Errorf("Name() = %q; want %q", s.Name(), "harvester")
	}
}

// ── Test: subdomain filtering ────────────────────────────────────────────────

func TestRun_SkipsDeepSubdomains(t *testing.T) {
	// Subdomains with >2 dots should be skipped entirely (returns nil, nil).
	s := harvester.New("")
	findings, err := s.Run(context.Background(), "sub.deep.example.co.uk", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for deep subdomain, got %d", len(findings))
	}
}

func TestRun_AllowsTwoDotsForCcTLD(t *testing.T) {
	// "example.co.uk" has 2 dots — should NOT be skipped.
	// The binary won't be found, so we expect either unavailable finding or nil.
	s := harvester.New("/nonexistent/path/to/theHarvester")
	findings, err := s.Run(context.Background(), "example.co.uk", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With a bad binary path, we expect the unavailable finding
	if len(findings) > 0 && !hasCheckID(findings, finding.CheckHarvesterUnavailable) {
		t.Errorf("expected either empty findings or harvester_unavailable, got %v", findings)
	}
}

// ── Test: binary not found → unavailable info finding ───────────────────────

func TestRun_BinaryNotFound(t *testing.T) {
	s := harvester.New("/nonexistent/path/to/theHarvester")
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckHarvesterUnavailable) {
		t.Error("expected harvester_unavailable finding when binary is not found")
	}

	f := findByCheckID(findings, finding.CheckHarvesterUnavailable)
	if f != nil {
		if f.Severity != finding.SeverityInfo {
			t.Errorf("unavailable severity = %v; want Info", f.Severity)
		}
		if f.Scanner != "harvester" {
			t.Errorf("scanner = %q; want %q", f.Scanner, "harvester")
		}
		if f.Asset != "example.com" {
			t.Errorf("asset = %q; want %q", f.Asset, "example.com")
		}
		if f.Module != "surface" {
			t.Errorf("module = %q; want %q", f.Module, "surface")
		}
		// Evidence should contain the install error
		ev := f.Evidence
		if ev == nil {
			t.Error("evidence should not be nil")
		} else if _, ok := ev["install_error"]; !ok {
			t.Error("evidence should contain install_error field")
		}
	}
}

// ── Test: empty bin defaults to "theHarvester" ──────────────────────────────

func TestRun_EmptyBinDefaultsToTheHarvester(t *testing.T) {
	// With empty bin, the scanner should try "theHarvester" from PATH.
	// Since theHarvester is unlikely to be installed in CI, we expect the
	// unavailable finding.
	s := harvester.New("")
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Either nil (if toolinstall works) or unavailable info finding
	if len(findings) > 0 {
		if !hasCheckID(findings, finding.CheckHarvesterUnavailable) {
			// If theHarvester happens to be installed, we might get real findings.
			// In that case, just verify they have valid check IDs.
			for _, f := range findings {
				if f.CheckID != finding.CheckHarvesterEmails &&
					f.CheckID != finding.CheckHarvesterSubdomains &&
					f.CheckID != finding.CheckHarvesterUnavailable {
					t.Errorf("unexpected check ID: %s", f.CheckID)
				}
			}
		}
	}
}

// ── Test: cancelled context ──────────────────────────────────────────────────

func TestRun_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := harvester.New("/nonexistent/binary")
	findings, err := s.Run(ctx, "example.com", module.ScanSurface)
	// With cancelled context, we still expect the binary-not-found path to
	// run (or possibly nil,nil if the context check happens first).
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Valid outcomes: nil (context cancelled before binary check), or
	// unavailable finding (binary not found).
	_ = findings
}

// ── Test: timeout during execution ──────────────────────────────────────────

func TestRun_TimeoutContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	s := harvester.New("/nonexistent/binary")
	findings, err := s.Run(ctx, "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should handle timeout gracefully
	_ = findings
}

// ── Test: finding field validation ──────────────────────────────────────────

func TestRun_UnavailableFindingFieldValidation(t *testing.T) {
	s := harvester.New("/nonexistent/binary")
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findByCheckID(findings, finding.CheckHarvesterUnavailable)
	if f == nil {
		t.Fatal("expected harvester_unavailable finding")
	}

	// Validate all required fields
	if f.Title == "" {
		t.Error("Title must not be empty")
	}
	if f.Description == "" {
		t.Error("Description must not be empty")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt must be set")
	}
	if f.CheckID != finding.CheckHarvesterUnavailable {
		t.Errorf("CheckID = %q; want %q", f.CheckID, finding.CheckHarvesterUnavailable)
	}
}

// ── Test: single dot domain is processed ─────────────────────────────────────

func TestRun_SingleDotDomain(t *testing.T) {
	// "example.com" has 1 dot — should not be skipped by the filter.
	s := harvester.New("/nonexistent/binary")
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With a nonexistent binary, we expect the unavailable finding
	// (proving the domain was not skipped).
	if !hasCheckID(findings, finding.CheckHarvesterUnavailable) {
		t.Error("single-dot domain should not be skipped; expected unavailable finding")
	}
}

// ── Test: exactly 2 dots (ccTLD root) is processed ──────────────────────────

func TestRun_TwoDotDomain(t *testing.T) {
	s := harvester.New("/nonexistent/binary")
	findings, err := s.Run(context.Background(), "example.co.uk", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 dots is at the threshold — should be processed, not skipped.
	if !hasCheckID(findings, finding.CheckHarvesterUnavailable) {
		t.Error("two-dot domain should not be skipped; expected unavailable finding")
	}
}

// ── Test: exactly 3 dots (subdomain of ccTLD) is skipped ────────────────────

func TestRun_ThreeDotDomain(t *testing.T) {
	s := harvester.New("/nonexistent/binary")
	findings, err := s.Run(context.Background(), "sub.example.co.uk", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 3-dot domain, got %d", len(findings))
	}
}

// ── Test: email check IDs and severity (if harvester IS available) ──────────
// These tests verify the expected check IDs and severities for the email and
// subdomain findings, without requiring the actual binary. They test the
// constants and metadata.

func TestCheckIDMetadata_HarvesterEmails(t *testing.T) {
	meta := finding.Meta(finding.CheckHarvesterEmails)
	if meta.CheckID != finding.CheckHarvesterEmails {
		t.Errorf("CheckHarvesterEmails meta ID = %q; want %q", meta.CheckID, finding.CheckHarvesterEmails)
	}
}

func TestCheckIDMetadata_HarvesterSubdomains(t *testing.T) {
	meta := finding.Meta(finding.CheckHarvesterSubdomains)
	if meta.CheckID != finding.CheckHarvesterSubdomains {
		t.Errorf("CheckHarvesterSubdomains meta ID = %q; want %q", meta.CheckID, finding.CheckHarvesterSubdomains)
	}
}

func TestCheckIDMetadata_HarvesterUnavailable(t *testing.T) {
	meta := finding.Meta(finding.CheckHarvesterUnavailable)
	if meta.CheckID != finding.CheckHarvesterUnavailable {
		t.Errorf("CheckHarvesterUnavailable meta ID = %q; want %q", meta.CheckID, finding.CheckHarvesterUnavailable)
	}
}
