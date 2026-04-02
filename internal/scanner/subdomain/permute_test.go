package subdomain

import (
	"sort"
	"strings"
	"testing"
)

func TestPermuteSubdomains_BasicPermutations(t *testing.T) {
	discovered := []string{"api.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	resultSet := toSet(results)

	// Should generate env-prefix variations
	expect := []string{
		"dev-api.example.com",
		"staging-api.example.com",
		"qa-api.example.com",
		"test-api.example.com",
	}
	for _, e := range expect {
		if _, ok := resultSet[e]; !ok {
			t.Errorf("expected permutation %q not found", e)
		}
	}

	// Should generate env-suffix variations
	suffixExpect := []string{
		"api-dev.example.com",
		"api-staging.example.com",
		"api-qa.example.com",
	}
	for _, e := range suffixExpect {
		if _, ok := resultSet[e]; !ok {
			t.Errorf("expected suffix permutation %q not found", e)
		}
	}

	// Should generate version variations
	versionExpect := []string{
		"api-v2.example.com",
		"api-v3.example.com",
		"api-new.example.com",
	}
	for _, e := range versionExpect {
		if _, ok := resultSet[e]; !ok {
			t.Errorf("expected version permutation %q not found", e)
		}
	}
}

func TestPermuteSubdomains_SubSubdomain(t *testing.T) {
	discovered := []string{"api.us-east.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	resultSet := toSet(results)

	// Should permute the full prefix "api.us-east"
	expect := []string{
		"dev-api.us-east.example.com",
		"api.us-east-dev.example.com",
	}
	for _, e := range expect {
		if _, ok := resultSet[e]; !ok {
			t.Errorf("expected sub-subdomain permutation %q not found", e)
		}
	}
}

func TestPermuteSubdomains_NoDuplicates(t *testing.T) {
	discovered := []string{"api.example.com", "dev.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	seen := make(map[string]bool)
	for _, r := range results {
		if seen[r] {
			t.Errorf("duplicate permutation: %q", r)
		}
		seen[r] = true
	}
}

func TestPermuteSubdomains_ExcludesDiscovered(t *testing.T) {
	discovered := []string{"api.example.com", "dev-api.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	resultSet := toSet(results)

	// dev-api.example.com was already discovered, should not appear in permutations
	if _, ok := resultSet["dev-api.example.com"]; ok {
		t.Error("already-discovered subdomain should not appear in permutations")
	}
}

func TestPermuteSubdomains_ExcludesCrossDomain(t *testing.T) {
	discovered := []string{"api.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	for _, r := range results {
		if r == "api.other.com" || !isValidHostname(r) {
			t.Errorf("invalid permutation leaked through: %q", r)
		}
	}
}

func TestPermuteSubdomains_EmptyInput(t *testing.T) {
	results := permuteSubdomains(nil, "example.com")
	if len(results) != 0 {
		t.Errorf("expected 0 permutations for nil input, got %d", len(results))
	}

	results = permuteSubdomains([]string{}, "example.com")
	if len(results) != 0 {
		t.Errorf("expected 0 permutations for empty input, got %d", len(results))
	}
}

func TestPermuteSubdomains_DomainItself(t *testing.T) {
	// If only the root domain is "discovered", prefix extraction returns ""
	// and no permutations should be generated from it.
	discovered := []string{"example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	if len(results) != 0 {
		t.Errorf("expected 0 permutations for root domain only, got %d", len(results))
	}
}

func TestPermuteSubdomains_InfraKeywords(t *testing.T) {
	discovered := []string{"www.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	resultSet := toSet(results)

	// Since www is a single-label prefix, infra keywords should be tried
	infraExpect := []string{
		"api.example.com",
		"admin.example.com",
		"vpn.example.com",
		"mail.example.com",
	}
	for _, e := range infraExpect {
		if _, ok := resultSet[e]; !ok {
			t.Errorf("expected infra keyword permutation %q not found", e)
		}
	}
}

func TestPermuteSubdomains_AllLowercase(t *testing.T) {
	discovered := []string{"API.Example.Com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	for _, r := range results {
		if r != strings.ToLower(r) {
			t.Errorf("permutation %q should be lowercase", r)
		}
	}
}

func TestPermuteSubdomains_ValidHostnames(t *testing.T) {
	discovered := []string{"api.example.com", "test-app.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	for _, r := range results {
		if !isValidHostname(r) {
			t.Errorf("permutation %q is not a valid hostname", r)
		}
	}
}

func TestExtractPrefix(t *testing.T) {
	tests := []struct {
		sub, domain, want string
	}{
		{"api.example.com", "example.com", "api"},
		{"api.sub.example.com", "example.com", "api.sub"},
		{"example.com", "example.com", ""},
		{"other.com", "example.com", ""},
		{"dev.api.prod.example.com", "example.com", "dev.api.prod"},
	}
	for _, tt := range tests {
		got := extractPrefix(tt.sub, tt.domain)
		if got != tt.want {
			t.Errorf("extractPrefix(%q, %q) = %q, want %q", tt.sub, tt.domain, got, tt.want)
		}
	}
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func TestPermuteSubdomains_ReasonableCount(t *testing.T) {
	// For a single discovered subdomain, permutations should be bounded
	// and not explode into millions like dnsgen.
	discovered := []string{"api.example.com"}
	domain := "example.com"

	results := permuteSubdomains(discovered, domain)
	// With our wordlists: ~21 env-prefixes + 21 env-dot-prefixes + 16 env-suffixes
	// + 7 version-suffixes + ~50 infra keywords ≈ ~115 max per subdomain
	if len(results) > 200 {
		t.Errorf("too many permutations for single subdomain: %d (should be < 200)", len(results))
	}
	if len(results) < 20 {
		t.Errorf("too few permutations: %d (should be at least 20)", len(results))
	}

	// Verify they're all unique
	sort.Strings(results)
	for i := 1; i < len(results); i++ {
		if results[i] == results[i-1] {
			t.Errorf("duplicate in sorted output: %q", results[i])
		}
	}
}
