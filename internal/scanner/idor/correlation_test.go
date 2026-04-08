package idor

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestExtractIDsFromEvidence_JSONPattern(t *testing.T) {
	findings := []finding.Finding{
		{
			Evidence: map[string]any{
				"body": `{"id": 42, "user_id": 100, "name": "test"}`,
			},
		},
	}

	ids := ExtractIDsFromEvidence(findings)
	want := map[string]bool{"42": true, "100": true}
	for _, id := range ids {
		delete(want, id)
	}
	if len(want) > 0 {
		t.Errorf("missing expected IDs: %v", want)
	}
}

func TestExtractIDsFromEvidence_URLPathPattern(t *testing.T) {
	findings := []finding.Finding{
		{
			Description: "Found endpoint /api/v1/users/789 returning user data",
			Evidence: map[string]any{
				"url": "https://example.com/api/v1/users/789",
			},
		},
	}

	ids := ExtractIDsFromEvidence(findings)
	found := false
	for _, id := range ids {
		if id == "789" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find ID '789' from URL path, got: %v", ids)
	}
}

func TestExtractIDsFromEvidence_Deduplication(t *testing.T) {
	findings := []finding.Finding{
		{
			Evidence: map[string]any{
				"body1": `{"id": 42}`,
				"body2": `{"user_id": 42}`,
			},
			Description: "Resource /users/42 found",
		},
	}

	ids := ExtractIDsFromEvidence(findings)
	count := 0
	for _, id := range ids {
		if id == "42" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected ID '42' exactly once (deduplication), got %d times in %v", count, ids)
	}
}

func TestExtractIDsFromEvidence_FiltersLargeNumbers(t *testing.T) {
	findings := []finding.Finding{
		{
			Evidence: map[string]any{
				"body": `{"id": 1234567890, "timestamp": 1680000000}`,
			},
		},
	}

	ids := ExtractIDsFromEvidence(findings)
	for _, id := range ids {
		if id == "1234567890" || id == "1680000000" {
			t.Errorf("large number %s should be filtered out (likely timestamp/hash), got: %v", id, ids)
		}
	}
}

func TestExtractIDsFromEvidence_EmptyFindings(t *testing.T) {
	ids := ExtractIDsFromEvidence(nil)
	if len(ids) != 0 {
		t.Errorf("expected empty result for nil findings, got: %v", ids)
	}

	ids = ExtractIDsFromEvidence([]finding.Finding{})
	if len(ids) != 0 {
		t.Errorf("expected empty result for empty findings, got: %v", ids)
	}
}

func TestExtractIDsFromEvidence_ProofCommand(t *testing.T) {
	findings := []finding.Finding{
		{
			ProofCommand: "curl -s 'https://example.com/api/orders/555'",
		},
	}

	ids := ExtractIDsFromEvidence(findings)
	found := false
	for _, id := range ids {
		if id == "555" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find ID '555' from ProofCommand, got: %v", ids)
	}
}

func TestExtractIDsFromEvidence_NonStringEvidence(t *testing.T) {
	// Non-string evidence values should be silently skipped.
	findings := []finding.Finding{
		{
			Evidence: map[string]any{
				"status":  200,
				"success": true,
				"data":    nil,
			},
		},
	}

	ids := ExtractIDsFromEvidence(findings)
	// Should not panic and may return empty.
	_ = ids
}

func TestExtractIDsFromEvidence_SortedOutput(t *testing.T) {
	findings := []finding.Finding{
		{
			Evidence: map[string]any{
				"body": `{"id": 300, "user_id": 100, "order_id": 200}`,
			},
		},
	}

	ids := ExtractIDsFromEvidence(findings)
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Errorf("output not sorted: %v", ids)
			break
		}
	}
}
