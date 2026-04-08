// Package diffing provides statistical response comparison for detecting subtle
// injection indicators. Scanners use it to compare a baseline response against a
// probed response and decide whether the difference is meaningful (not caused by
// timestamps, CSRF tokens, or other dynamic content).
package diffing

import (
	"regexp"
	"strings"
)

// dynamicPatterns matches content that typically changes between requests:
// timestamps, CSRF tokens, nonces, session IDs, UUIDs, and random hex strings.
var dynamicPatterns = []*regexp.Regexp{
	// UUIDs — must come before digit-only patterns so the last UUID segment
	// (which can be all digits) is not consumed by the Unix timestamp rule.
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	// ISO 8601 timestamps: 2024-01-15T10:30:00Z
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\dZ+\-:]*`),
	// Unix timestamps (10 or 13 digits)
	regexp.MustCompile(`\b\d{10,13}\b`),
	// Common date formats: 15 Jan 2024, 01/15/2024, etc.
	regexp.MustCompile(`\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b`),
	// CSRF tokens / nonces (hex strings 16+ chars)
	regexp.MustCompile(`[0-9a-fA-F]{16,}`),
	// Base64-ish tokens (32+ chars of alphanumeric + /+=)
	regexp.MustCompile(`[A-Za-z0-9+/=]{32,}`),
	// Common token attribute patterns in HTML: value="...", token="...", nonce="..."
	regexp.MustCompile(`(?i)(csrf|token|nonce|session|sid|_t|_ts|timestamp)["']?\s*[:=]\s*["']?[^"'\s,;<>]+`),
}

// StripDynamic removes common dynamic content (timestamps, CSRF tokens,
// session IDs, nonces, UUIDs) before comparison.
func StripDynamic(body []byte) []byte {
	result := string(body)
	for _, re := range dynamicPatterns {
		result = re.ReplaceAllString(result, "")
	}
	return []byte(result)
}

// tokenize splits text into whitespace-delimited words for Jaccard comparison.
func tokenize(data []byte) map[string]struct{} {
	words := strings.Fields(string(data))
	set := make(map[string]struct{}, len(words))
	for _, w := range words {
		set[w] = struct{}{}
	}
	return set
}

// jaccard returns the Jaccard similarity coefficient between two token sets.
// Returns 1.0 when both sets are empty (two empty responses are identical).
func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	intersection := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// Compare returns a similarity score (0.0–1.0) between two HTTP response bodies.
// It strips dynamic content first, then calculates Jaccard similarity on
// word-level tokens. A score of 1.0 means the responses are identical after
// stripping dynamic content; 0.0 means they share no tokens.
func Compare(baseline, probe []byte) float64 {
	a := StripDynamic(baseline)
	b := StripDynamic(probe)

	tokensA := tokenize(a)
	tokensB := tokenize(b)

	return jaccard(tokensA, tokensB)
}

// SignificantDiff returns true if the baseline and probe responses differ
// meaningfully (after stripping dynamic content). The threshold controls
// sensitivity: a threshold of 0.7 means responses sharing fewer than 70% of
// tokens are considered significantly different.
func SignificantDiff(baseline, probe []byte, threshold float64) bool {
	return Compare(baseline, probe) < threshold
}
