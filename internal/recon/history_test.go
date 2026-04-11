package recon

import (
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestFindingKey(t *testing.T) {
	f := finding.Finding{
		CheckID: "web.cors_misconfiguration",
		Asset:   "api.example.com",
		Evidence: map[string]any{
			"url":    "https://api.example.com/v1",
			"method": "GET",
		},
	}

	key1 := FindingKey(f)
	key2 := FindingKey(f)
	if key1 != key2 {
		t.Error("FindingKey should be deterministic for the same finding")
	}

	// Different asset should produce different key.
	f2 := f
	f2.Asset = "other.example.com"
	if FindingKey(f) == FindingKey(f2) {
		t.Error("different assets should produce different keys")
	}

	// Different evidence should produce different key.
	f3 := f
	f3.Evidence = map[string]any{"url": "https://api.example.com/v2", "method": "POST"}
	if FindingKey(f) == FindingKey(f3) {
		t.Error("different evidence should produce different keys")
	}
}

func TestEvidenceHash(t *testing.T) {
	f := finding.Finding{
		Evidence: map[string]any{
			"url":    "https://example.com",
			"method": "GET",
		},
	}

	h1 := EvidenceHash(f)
	h2 := EvidenceHash(f)
	if h1 != h2 {
		t.Error("EvidenceHash should be deterministic")
	}

	// Nil evidence should return "empty".
	f2 := finding.Finding{}
	if EvidenceHash(f2) != "empty" {
		t.Error("nil evidence should return 'empty'")
	}
}

func TestFilterNewFindings(t *testing.T) {
	prev := []finding.Finding{
		{
			CheckID:     "web.cors_misconfiguration",
			Asset:       "api.example.com",
			Title:       "CORS Misconfiguration",
			DiscoveredAt: time.Now().Add(-24 * time.Hour),
			Evidence: map[string]any{
				"url":    "https://api.example.com",
				"method": "GET",
			},
		},
		{
			CheckID:     "tls.expired_cert",
			Asset:       "api.example.com",
			Title:       "Expired TLS Certificate",
			DiscoveredAt: time.Now().Add(-24 * time.Hour),
			Evidence: map[string]any{
				"endpoint": "https://api.example.com",
			},
		},
	}

	current := []finding.Finding{
		// Same as previous — should be filtered.
		{
			CheckID:     "web.cors_misconfiguration",
			Asset:       "api.example.com",
			Title:       "CORS Misconfiguration",
			DiscoveredAt: time.Now(),
			Evidence: map[string]any{
				"url":    "https://api.example.com",
				"method": "GET",
			},
		},
		// New finding — should be kept.
		{
			CheckID:     "web.xss_reflected",
			Asset:       "api.example.com",
			Title:       "Reflected XSS",
			DiscoveredAt: time.Now(),
			Evidence: map[string]any{
				"url":       "https://api.example.com/search",
				"parameter": "q",
			},
		},
		// Same check, different asset — should be kept.
		{
			CheckID:     "tls.expired_cert",
			Asset:       "www.example.com",
			Title:       "Expired TLS Certificate",
			DiscoveredAt: time.Now(),
			Evidence: map[string]any{
				"endpoint": "https://www.example.com",
			},
		},
	}

	newFindings := FilterNewFindings(current, prev)
	if len(newFindings) != 2 {
		t.Errorf("FilterNewFindings returned %d findings, want 2", len(newFindings))
		for _, f := range newFindings {
			t.Logf("  %s on %s", f.CheckID, f.Asset)
		}
	}
}

func TestFilterNewFindingsNoPrevious(t *testing.T) {
	current := []finding.Finding{
		{CheckID: "test.check", Asset: "example.com"},
	}

	// No previous findings — all current findings are "new".
	got := FilterNewFindings(current, nil)
	if len(got) != 1 {
		t.Errorf("with no previous findings, all current should be returned, got %d", len(got))
	}
}
