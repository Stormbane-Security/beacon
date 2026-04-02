package subdomain

import (
	"fmt"
	"strings"
)

// Common prefixes/suffixes used by organizations for internal infrastructure.
// Kept small and targeted — unlike dnsgen's millions of permutations, we only
// generate variations of actually-discovered subdomains (< 1000 DNS queries).
var (
	envPrefixes = []string{
		"dev", "staging", "stage", "stg", "uat", "qa", "test", "testing",
		"demo", "sandbox", "beta", "alpha", "preview", "pre-prod", "preprod",
		"int", "internal", "local", "lab", "canary",
	}

	envSuffixes = []string{
		"-dev", "-staging", "-stage", "-stg", "-uat", "-qa", "-test",
		"-demo", "-sandbox", "-beta", "-alpha", "-preview", "-preprod",
		"-int", "-internal", "-canary",
	}

	versionSuffixes = []string{
		"-v2", "-v3", "-v1", "-new", "-old", "-legacy", "-next",
		"2", "3",
	}

	infraPrefixes = []string{
		"api", "admin", "app", "backend", "frontend", "web", "www",
		"mail", "smtp", "imap", "pop", "mx",
		"vpn", "remote", "gateway", "gw",
		"cdn", "static", "assets", "media", "img", "images",
		"db", "database", "mysql", "postgres", "redis", "mongo",
		"ci", "cd", "jenkins", "gitlab", "git",
		"monitor", "grafana", "prometheus", "kibana", "logs",
		"auth", "login", "sso", "idp", "identity",
		"docs", "wiki", "help", "support",
		"status", "health",
	}
)

// permuteSubdomains generates permutations of discovered subdomains by applying
// environment prefixes/suffixes, version tags, and infrastructure prefixes.
// Only permutations under the given root domain are returned.
//
// Strategy: targeted permutation of real discoveries. If we found "api.example.com",
// we generate "api-dev.example.com", "staging-api.example.com", "api-v2.example.com" etc.
// This yields ~50x fewer queries than blind wordlist approaches while finding the
// same infrastructure subdomains that actually exist.
func permuteSubdomains(discovered []string, domain string) []string {
	seen := make(map[string]struct{}, len(discovered)*20)
	for _, d := range discovered {
		seen[d] = struct{}{}
	}

	var permuted []string
	add := func(s string) {
		s = strings.ToLower(s)
		if _, exists := seen[s]; exists {
			return
		}
		if !strings.HasSuffix(s, "."+domain) {
			return
		}
		if !isValidHostname(s) {
			return
		}
		seen[s] = struct{}{}
		permuted = append(permuted, s)
	}

	for _, sub := range discovered {
		// Extract the leftmost label (e.g., "api" from "api.example.com")
		prefix := extractPrefix(sub, domain)
		if prefix == "" {
			continue
		}

		// parent is the part after the first label: "example.com" or "sub.example.com"
		parent := sub[len(prefix)+1:]

		// 1. Environment prefixes: dev-api.example.com, staging-api.example.com
		for _, ep := range envPrefixes {
			add(fmt.Sprintf("%s-%s.%s", ep, prefix, parent))
			add(fmt.Sprintf("%s.%s", ep, sub)) // dev.api.example.com
		}

		// 2. Environment suffixes: api-dev.example.com, api-staging.example.com
		for _, es := range envSuffixes {
			add(fmt.Sprintf("%s%s.%s", prefix, es, parent))
		}

		// 3. Version suffixes: api-v2.example.com, api2.example.com
		for _, vs := range versionSuffixes {
			add(fmt.Sprintf("%s%s.%s", prefix, vs, parent))
		}

		// 4. If the prefix is an infra keyword, try env combinations of it
		// (already covered above), but also try the infra keywords against the parent
		if len(strings.Split(prefix, "-")) == 1 {
			for _, ip := range infraPrefixes {
				if ip != prefix {
					add(fmt.Sprintf("%s.%s", ip, parent))
				}
			}
		}
	}

	return permuted
}

// extractPrefix returns the leftmost label(s) before the root domain.
// e.g., extractPrefix("api.sub.example.com", "example.com") → "api.sub"
// Returns "" if sub == domain or sub doesn't end with .domain.
func extractPrefix(sub, domain string) string {
	if sub == domain {
		return ""
	}
	suffix := "." + domain
	if !strings.HasSuffix(sub, suffix) {
		return ""
	}
	return sub[:len(sub)-len(suffix)]
}
