package enrichment

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/stormbane-security/beacon/internal/finding"
)

// ipv4Re matches IPv4 addresses embedded in text.
var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// Anonymizer builds a deterministic, bidirectional mapping between real
// identifiers (IPs, hostnames, domains) and opaque tokens like [HOST-1],
// [IP-2]. Use it to strip identifying data from findings before they are
// sent to an external AI provider for enrichment.
type Anonymizer struct {
	mu       sync.Mutex
	forward  map[string]string // real → token
	reverse  map[string]string // token → real
	hostSeq  int
	ipSeq    int
	emailSeq int
}

// NewAnonymizer creates an empty Anonymizer.
func NewAnonymizer() *Anonymizer {
	return &Anonymizer{
		forward: make(map[string]string),
		reverse: make(map[string]string),
	}
}

// tokenFor returns the anonymized token for a real value, creating one if needed.
func (a *Anonymizer) tokenFor(real string, kind string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if tok, ok := a.forward[real]; ok {
		return tok
	}
	var tok string
	switch kind {
	case "ip":
		a.ipSeq++
		tok = fmt.Sprintf("[IP-%d]", a.ipSeq)
	case "email":
		a.emailSeq++
		tok = fmt.Sprintf("[EMAIL-%d]", a.emailSeq)
	default:
		a.hostSeq++
		tok = fmt.Sprintf("[HOST-%d]", a.hostSeq)
	}
	a.forward[real] = tok
	a.reverse[tok] = real
	return tok
}

// isIPv4 returns true if s looks like a valid IPv4 address.
func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// collectIdentifiers scans findings and the domain for values to anonymize.
// It returns the set of unique identifiers found, categorized by kind.
func collectIdentifiers(findings []finding.Finding, domain string) map[string]string {
	ids := make(map[string]string)

	// Always include the scan domain.
	if domain != "" {
		if isIPv4(domain) {
			ids[domain] = "ip"
		} else {
			ids[domain] = "host"
		}
	}

	// Collect all asset values.
	for _, f := range findings {
		asset := f.Asset
		if asset == "" {
			continue
		}
		// Strip port if present (e.g. "10.0.0.1:8080" → "10.0.0.1")
		host := asset
		if h, _, err := net.SplitHostPort(asset); err == nil {
			host = h
		}
		if isIPv4(host) {
			ids[host] = "ip"
		} else if host != "" {
			ids[host] = "host"
		}
	}

	// Scan text fields for embedded IPv4 addresses not already collected.
	for _, f := range findings {
		for _, text := range []string{f.Title, f.Description, f.Asset} {
			for _, match := range ipv4Re.FindAllString(text, -1) {
				if isIPv4(match) {
					if _, exists := ids[match]; !exists {
						ids[match] = "ip"
					}
				}
			}
		}
	}

	return ids
}

// AnonymizeFindings replaces all IPs, hostnames, and domains in finding fields
// with opaque tokens. Returns copies — the original findings are not modified.
func (a *Anonymizer) AnonymizeFindings(findings []finding.Finding, domain string) ([]finding.Finding, string) {
	ids := collectIdentifiers(findings, domain)

	// Register all identifiers to get stable tokens.
	for real, kind := range ids {
		a.tokenFor(real, kind)
	}

	// Build a replacer from longest-match-first to avoid partial substitutions.
	// e.g. "api.example.com" must be replaced before "example.com".
	pairs := a.replacerPairs()
	if len(pairs) == 0 {
		return findings, domain
	}
	replacer := strings.NewReplacer(pairs...)

	out := make([]finding.Finding, len(findings))
	for i, f := range findings {
		f.Asset = replacer.Replace(f.Asset)
		f.Title = replacer.Replace(f.Title)
		f.Description = replacer.Replace(f.Description)
		out[i] = f
	}

	anonDomain := domain
	if domain != "" {
		anonDomain = replacer.Replace(domain)
	}

	return out, anonDomain
}

// AnonymizeEnrichedFindings replaces identifiers in enriched finding fields.
func (a *Anonymizer) AnonymizeEnrichedFindings(enriched []EnrichedFinding, domain string) ([]EnrichedFinding, string) {
	// Ensure the domain is registered even if it wasn't seen in findings.
	if domain != "" {
		if isIPv4(domain) {
			a.tokenFor(domain, "ip")
		} else {
			a.tokenFor(domain, "host")
		}
	}

	pairs := a.replacerPairs()
	if len(pairs) == 0 {
		return enriched, domain
	}
	replacer := strings.NewReplacer(pairs...)

	out := make([]EnrichedFinding, len(enriched))
	for i, ef := range enriched {
		ef.Finding.Asset = replacer.Replace(ef.Finding.Asset)
		ef.Finding.Title = replacer.Replace(ef.Finding.Title)
		ef.Finding.Description = replacer.Replace(ef.Finding.Description)
		out[i] = ef
	}

	anonDomain := domain
	if domain != "" {
		anonDomain = replacer.Replace(domain)
	}

	return out, anonDomain
}

// Deanonymize replaces all tokens in text with their original values.
func (a *Anonymizer) Deanonymize(text string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.reverse) == 0 {
		return text
	}
	// Build reverse replacer pairs (token → real).
	pairs := make([]string, 0, len(a.reverse)*2)
	for tok, real := range a.reverse {
		pairs = append(pairs, tok, real)
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

// DeanonymizeEnrichedFindings restores original identifiers in all text fields
// of enriched findings.
func (a *Anonymizer) DeanonymizeEnrichedFindings(enriched []EnrichedFinding) []EnrichedFinding {
	a.mu.Lock()
	if len(a.reverse) == 0 {
		a.mu.Unlock()
		return enriched
	}
	pairs := make([]string, 0, len(a.reverse)*2)
	for tok, real := range a.reverse {
		pairs = append(pairs, tok, real)
	}
	a.mu.Unlock()

	replacer := strings.NewReplacer(pairs...)

	out := make([]EnrichedFinding, len(enriched))
	for i, ef := range enriched {
		ef.Finding.Asset = replacer.Replace(ef.Finding.Asset)
		ef.Finding.Title = replacer.Replace(ef.Finding.Title)
		ef.Finding.Description = replacer.Replace(ef.Finding.Description)
		ef.Explanation = replacer.Replace(ef.Explanation)
		ef.Impact = replacer.Replace(ef.Impact)
		ef.Remediation = replacer.Replace(ef.Remediation)
		ef.MitigatedBy = replacer.Replace(ef.MitigatedBy)
		ef.CrossAssetNote = replacer.Replace(ef.CrossAssetNote)
		ef.TechSpecificRemediation = replacer.Replace(ef.TechSpecificRemediation)
		ef.TerraformFix = replacer.Replace(ef.TerraformFix)
		out[i] = ef
	}
	return out
}

// replacerPairs returns old/new pairs sorted by key length descending so that
// "api.example.com" is replaced before "example.com".
func (a *Anonymizer) replacerPairs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	keys := make([]string, 0, len(a.forward))
	for k := range a.forward {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	pairs := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		pairs = append(pairs, k, a.forward[k])
	}
	return pairs
}

// AnonymizingEnricher wraps any Enricher to strip identifying data (IPs,
// hostnames, domains) before sending findings to an external AI provider and
// restores them in the response. Enable via --anonymize or BEACON_ANONYMIZE=true.
type AnonymizingEnricher struct {
	inner Enricher
	anon  *Anonymizer
}

// NewAnonymizingEnricher wraps an existing enricher with anonymization.
func NewAnonymizingEnricher(inner Enricher) *AnonymizingEnricher {
	return &AnonymizingEnricher{
		inner: inner,
		anon:  NewAnonymizer(),
	}
}

func (ae *AnonymizingEnricher) Enrich(ctx context.Context, findings []finding.Finding) ([]EnrichedFinding, error) {
	anonFindings, _ := ae.anon.AnonymizeFindings(findings, "")
	enriched, err := ae.inner.Enrich(ctx, anonFindings)
	if err != nil {
		return nil, err
	}
	return ae.anon.DeanonymizeEnrichedFindings(enriched), nil
}

func (ae *AnonymizingEnricher) ContextualizeAndSummarize(ctx context.Context, enriched []EnrichedFinding, domain string) ([]EnrichedFinding, string, error) {
	anonEnriched, anonDomain := ae.anon.AnonymizeEnrichedFindings(enriched, domain)
	result, summary, err := ae.inner.ContextualizeAndSummarize(ctx, anonEnriched, anonDomain)
	if err != nil {
		return nil, "", err
	}
	return ae.anon.DeanonymizeEnrichedFindings(result), ae.anon.Deanonymize(summary), nil
}

func (ae *AnonymizingEnricher) AnalyzeAttackPaths(ctx context.Context, enriched []EnrichedFinding, domain string) (string, error) {
	anonEnriched, anonDomain := ae.anon.AnonymizeEnrichedFindings(enriched, domain)
	result, err := ae.inner.AnalyzeAttackPaths(ctx, anonEnriched, anonDomain)
	if err != nil {
		return "", err
	}
	return ae.anon.Deanonymize(result), nil
}

func (ae *AnonymizingEnricher) GenerateFollowUpProbes(ctx context.Context, enriched []EnrichedFinding, domain string) ([]FollowUpProbe, error) {
	anonEnriched, anonDomain := ae.anon.AnonymizeEnrichedFindings(enriched, domain)
	probes, err := ae.inner.GenerateFollowUpProbes(ctx, anonEnriched, anonDomain)
	if err != nil {
		return nil, err
	}
	for i := range probes {
		probes[i].Asset = ae.anon.Deanonymize(probes[i].Asset)
		probes[i].Reason = ae.anon.Deanonymize(probes[i].Reason)
	}
	return probes, nil
}

func (ae *AnonymizingEnricher) EnrichFingerprints(ctx context.Context, inputs []FingerprintInput) (*FingerprintResult, error) {
	return ae.inner.EnrichFingerprints(ctx, inputs)
}
