// Package idor — cross-endpoint correlation for IDOR/BOLA testing.
//
// ExtractIDsFromEvidence scans findings from other scanners (e.g. crawler,
// webcontent) for numeric IDs embedded in evidence fields, URL paths, and
// JSON-like bodies. The extracted IDs are fed into the IDOR scanner's seed
// list so that testing targets real resource IDs discovered during the scan
// rather than only hardcoded guesses.
package idor

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

// Patterns that match numeric IDs in JSON-like evidence and URL paths.
var (
	// "id": 123, "user_id": 456, "account_id": 789, etc.
	jsonIDPattern = regexp.MustCompile(`"[a-zA-Z_]*id"\s*:\s*(\d+)`)

	// /users/789, /api/v1/orders/42, /accounts/1001
	pathIDPattern = regexp.MustCompile(`/(?:users|accounts|orders|profiles|items|messages|tickets|invoices|documents)/(\d+)`)
)

// ExtractIDsFromEvidence scans all findings' evidence for fields containing
// numeric IDs. It looks for JSON "id" patterns and URL path patterns, then
// returns a deduplicated, sorted list of discovered ID strings.
func ExtractIDsFromEvidence(findings []finding.Finding) []string {
	seen := make(map[string]struct{})

	for _, f := range findings {
		// Scan all string values in the evidence map.
		for _, v := range f.Evidence {
			s, ok := v.(string)
			if !ok {
				continue
			}
			extractFromText(s, seen)
		}

		// Also scan the description and title — crawlers often embed
		// discovered URLs in these fields.
		extractFromText(f.Description, seen)
		extractFromText(f.Title, seen)

		// Check for proof commands which often contain full URLs with IDs.
		extractFromText(f.ProofCommand, seen)
	}

	// Filter out trivially small or very large IDs that are unlikely to be
	// meaningful resource identifiers (timestamps, hash fragments, etc.).
	var ids []string
	for id := range seen {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			continue
		}
		// Keep IDs in the range [1, 10_000_000] — covers typical DB primary
		// keys while excluding timestamps and large random numbers.
		if n >= 1 && n <= 10_000_000 {
			ids = append(ids, id)
		}
	}

	sort.Strings(ids)
	return ids
}

// extractFromText applies all ID-extraction patterns to a text string and
// adds matches to the seen map.
func extractFromText(text string, seen map[string]struct{}) {
	if text == "" {
		return
	}

	// JSON-style "id": 123 patterns.
	for _, m := range jsonIDPattern.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			seen[m[1]] = struct{}{}
		}
	}

	// URL path patterns like /users/789.
	for _, m := range pathIDPattern.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			seen[m[1]] = struct{}{}
		}
	}

	// Also look for bare numeric path segments in URLs.
	// e.g., /api/v1/resources/12345
	for _, part := range strings.Split(text, "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := strconv.ParseInt(part, 10, 64); err == nil {
			seen[part] = struct{}{}
		}
	}
}
