// Package typosquat detects registered lookalike domains that could be used for
// phishing, brand impersonation, or credential harvesting attacks.
// Detection is pure Go — no external tools required. Only DNS lookups are made.
package typosquat

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "typosquat"

// Scanner checks for registered lookalike domains.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Only run on the root domain (not subdomains — we'd generate noise).
	if strings.Count(asset, ".") != 1 {
		return nil, nil
	}

	candidates := permutations(asset)

	type result struct {
		domain string
		ips    []string
	}

	// Probe up to 5 candidates concurrently. Typosquat domains are all
	// non-existent for a legitimate target, so 20 simultaneous NXDOMAIN
	// queries hammer root nameservers unnecessarily; 5 is plenty fast.
	sem := make(chan struct{}, 5)
	var mu sync.Mutex
	var hits []result
	var wg sync.WaitGroup

	for _, cand := range candidates {
		if cand == asset {
			continue
		}
		cand := cand
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			addrs, err := net.DefaultResolver.LookupHost(ctx, cand)
			if err != nil || len(addrs) == 0 {
				return
			}
			mu.Lock()
			hits = append(hits, result{cand, addrs})
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(hits) == 0 {
		return nil, nil
	}

	now := time.Now()

	// Build a sorted domain list and a resolves_to map for the evidence.
	domainList := make([]string, 0, len(hits))
	resolvesTo := make(map[string][]string, len(hits))
	for _, h := range hits {
		domainList = append(domainList, h.domain)
		resolvesTo[h.domain] = h.ips
	}

	// Truncate the title list at 5 domains to keep it readable.
	titleDomains := domainList
	if len(titleDomains) > 5 {
		titleDomains = titleDomains[:5]
	}
	title := fmt.Sprintf("%d lookalike domains registered: %s", len(hits), strings.Join(titleDomains, ", "))
	if len(hits) > 5 {
		title += fmt.Sprintf(" (+%d more)", len(hits)-5)
	}

	return []finding.Finding{{
		CheckID:  finding.CheckDomainTyposquat,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    title,
		Description: fmt.Sprintf(
			"%d domains similar to %s are registered and resolving. Lookalike domains are commonly used for phishing, "+
				"business email compromise, and brand impersonation. Review the full list and consider registering "+
				"the most plausible variants defensively.",
			len(hits), asset),
		Asset: asset,
		Evidence: map[string]any{
			"count":          len(hits),
			"domains":        domainList,
			"resolves_to":    resolvesTo,
		},
		ProofCommand: fmt.Sprintf("for d in %s; do echo -n \"$d: \"; dig +short $d; done",
			strings.Join(domainList, " ")),
		DiscoveredAt: now,
	}}, nil
}

// permutations generates a deduplicated set of lookalike domain candidates for the given
// domain (e.g. "example.com"). Techniques: character omission, transposition, adjacent-key
// substitution, common TLD swaps, and homoglyph substitution.
func permutations(domain string) []string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return nil
	}
	name, tld := parts[0], parts[1]

	seen := map[string]bool{domain: true}
	var out []string

	add := func(d string) {
		if !seen[d] && isValidDomainName(d) {
			seen[d] = true
			out = append(out, d)
		}
	}

	// TLD swaps
	for _, alt := range altTLDs(tld) {
		add(name + "." + alt)
	}

	// Character omission: drop each character in turn
	for i := range name {
		add(name[:i]+name[i+1:] + "." + tld)
	}

	// Character transposition: swap adjacent characters
	nb := []byte(name)
	for i := 0; i < len(nb)-1; i++ {
		nb[i], nb[i+1] = nb[i+1], nb[i]
		add(string(nb) + "." + tld)
		nb[i], nb[i+1] = nb[i+1], nb[i] // swap back
	}

	// Adjacent-key substitution (QWERTY keyboard)
	for i, ch := range name {
		for _, sub := range adjacentKeys(ch) {
			add(name[:i]+string(sub)+name[i+1:] + "." + tld)
		}
	}

	// Character doubling: double each character
	for i, ch := range name {
		add(name[:i]+string(ch)+string(ch)+name[i+1:] + "." + tld)
	}

	// Homoglyphs: visually similar characters
	for i, ch := range name {
		for _, sub := range homoglyphs(ch) {
			add(name[:i]+string(sub)+name[i+1:] + "." + tld)
		}
	}

	// Common prefix/suffix additions
	for _, pre := range []string{"my", "get", "app", "the", "go", "use"} {
		add(pre+name + "." + tld)
	}
	for _, suf := range []string{"app", "hq", "io", "ai", "co"} {
		add(name+suf + "." + tld)
	}
	// Hyphen insertions
	for i := 1; i < len(name); i++ {
		add(name[:i]+"-"+name[i:] + "." + tld)
	}

	return out
}

func altTLDs(tld string) []string {
	all := []string{"com", "net", "org", "io", "co", "app", "dev", "xyz", "info", "biz", "us", "co.uk", "com.au"}
	var out []string
	for _, t := range all {
		if t != tld {
			out = append(out, t)
		}
	}
	return out
}

// adjacentKeys returns the QWERTY keyboard neighbors of a character.
func adjacentKeys(r rune) []rune {
	neighbors := map[rune]string{
		'q': "wa", 'w': "qeasd", 'e': "wrsd", 'r': "etdf", 't': "ryfg",
		'y': "tugh", 'u': "yihj", 'i': "uojk", 'o': "ipkl", 'p': "ol",
		'a': "qwsz", 's': "awedxz", 'd': "serfcx", 'f': "drtgvc", 'g': "ftyhbv",
		'h': "gyujnb", 'j': "huikmn", 'k': "jiolm", 'l': "kop",
		'z': "asx", 'x': "zsdc", 'c': "xdfv", 'v': "cfgb", 'b': "vghn",
		'n': "bhjm", 'm': "njk",
		'0': "9", '1': "2q", '2': "13qw", '3': "24we", '4': "35er",
		'5': "46rt", '6': "57ty", '7': "68yu", '8': "79ui", '9': "80io",
	}
	var out []rune
	if adj, ok := neighbors[unicode.ToLower(r)]; ok {
		for _, a := range adj {
			out = append(out, a)
		}
	}
	return out
}

// homoglyphs returns visually similar ASCII replacements for a character.
func homoglyphs(r rune) []rune {
	table := map[rune][]rune{
		'a': {'4', '@'},
		'e': {'3'},
		'i': {'1', 'l'},
		'l': {'1', 'i'},
		'o': {'0'},
		's': {'5'},
		'b': {'6'},
		'g': {'9'},
		'q': {'9'},
		't': {'7'},
		'z': {'2'},
	}
	if subs, ok := table[unicode.ToLower(r)]; ok {
		return subs
	}
	return nil
}

// isValidDomainName returns true if the domain label has at least 1 character
// and contains only valid hostname characters.
func isValidDomainName(domain string) bool {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts[0]) == 0 {
		return false
	}
	for _, ch := range parts[0] {
		if !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && ch != '-' {
			return false
		}
	}
	return true
}
