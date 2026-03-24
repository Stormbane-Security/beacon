// Package assetintel performs passive asset intelligence gathering:
// reverse IP lookup (co-tenancy) via HackerTarget and SSL cert org search via crt.sh.
// Both services are free and require no API keys.
package assetintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "assetintel"

// Scanner performs passive asset intelligence gathering.
// All API keys are optional; their respective lookups are skipped when empty.
type Scanner struct {
	shodanKey          string
	virusTotalKey      string
	securityTrailsKey  string
	censysID           string
	censysSecret       string
	greyNoiseKey       string
}

// New creates a scanner with only a Shodan key (backwards compatible).
func New(shodanKey string) *Scanner { return &Scanner{shodanKey: shodanKey} }

// NewWithKeys creates a scanner with all optional API keys.
func NewWithKeys(shodanKey, virusTotalKey, securityTrailsKey, censysID, censysSecret, greyNoiseKey string) *Scanner {
	return &Scanner{
		shodanKey:         shodanKey,
		virusTotalKey:     virusTotalKey,
		securityTrailsKey: securityTrailsKey,
		censysID:          censysID,
		censysSecret:      censysSecret,
		greyNoiseKey:      greyNoiseKey,
	}
}

func (s *Scanner) Name() string { return scannerName }

// ActiveSources returns a human-readable list of the API sources that are
// enabled for this scanner instance (i.e. have a non-empty key). Used by the
// module to build an informative progress display string.
func (s *Scanner) ActiveSources() []string {
	var srcs []string
	srcs = append(srcs, "HackerTarget", "crt.sh") // always active (no key needed)
	if s.shodanKey != "" {
		srcs = append(srcs, "Shodan")
	}
	if s.virusTotalKey != "" {
		srcs = append(srcs, "VirusTotal")
	}
	if s.censysID != "" {
		srcs = append(srcs, "Censys")
	}
	if s.greyNoiseKey != "" {
		srcs = append(srcs, "GreyNoise")
	}
	if s.securityTrailsKey != "" {
		srcs = append(srcs, "SecurityTrails")
	}
	return srcs
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Each lookup gets its own 12s timeout so a slow provider doesn't starve others.
	// All independent lookups run in parallel; IP-dependent lookups wait only for
	// DNS resolution, not for each other.
	type lookupFn func() *finding.Finding

	// Resolve the domain to its IP first (all IP-based lookups depend on this).
	ips, err := net.DefaultResolver.LookupHost(ctx, asset)
	var ip string
	if err == nil && len(ips) > 0 {
		ip = ips[0]
	}

	var tasks []lookupFn

	// IP-dependent lookups (skip when DNS resolution failed)
	if ip != "" {
		client := &http.Client{Timeout: 12 * time.Second}
		tasks = append(tasks, func() *finding.Finding {
			return reverseIPLookup(ctx, client, asset, ip)
		})
		if s.shodanKey != "" {
			key := s.shodanKey
			tasks = append(tasks, func() *finding.Finding {
				return shodanLookup(ctx, client, asset, ip, key)
			})
		}
		if s.censysID != "" && s.censysSecret != "" {
			id, secret := s.censysID, s.censysSecret
			tasks = append(tasks, func() *finding.Finding {
				return censysLookup(ctx, client, asset, ip, id, secret)
			})
		}
		if s.greyNoiseKey != "" {
			key := s.greyNoiseKey
			tasks = append(tasks, func() *finding.Finding {
				return greyNoiseLookup(ctx, client, asset, ip, key)
			})
		}
	}

	// Domain-only lookups (no IP required — run regardless of DNS result)
	{
		client := &http.Client{Timeout: 12 * time.Second}
		tasks = append(tasks, func() *finding.Finding {
			return certOrgSearch(ctx, client, asset)
		})
		if s.virusTotalKey != "" {
			key := s.virusTotalKey
			tasks = append(tasks, func() *finding.Finding {
				return virusTotalLookup(ctx, client, asset, key)
			})
		}
		if s.securityTrailsKey != "" {
			key := s.securityTrailsKey
			tasks = append(tasks, func() *finding.Finding {
				return securityTrailsLookup(ctx, client, asset, key)
			})
		}
	}

	// Run all lookups concurrently and collect results.
	results := make([]*finding.Finding, len(tasks))
	var wg sync.WaitGroup
	for i, task := range tasks {
		i, task := i, task
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = task()
		}()
	}
	wg.Wait()

	var findings []finding.Finding
	for _, f := range results {
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

// reverseIPLookup queries HackerTarget's reverse IP API to find other domains
// hosted on the same IP. A large number of co-tenants can indicate shared hosting,
// which is relevant to attack surface assessment.
func reverseIPLookup(ctx context.Context, client *http.Client, asset, ip string) *finding.Finding {
	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) // 64KB
	if err != nil {
		return nil
	}

	text := strings.TrimSpace(string(body))

	// HackerTarget returns error strings on failure
	if strings.HasPrefix(text, "error") || strings.Contains(text, "API count exceeded") {
		return nil
	}

	lines := strings.Split(text, "\n")
	var domains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != asset {
			domains = append(domains, line)
		}
	}

	if len(domains) == 0 {
		return nil
	}

	// Only report when there are meaningful co-tenants (>1 to avoid noise)
	if len(domains) < 2 {
		return nil
	}

	// Cap the evidence list at 20 to keep findings readable
	shown := domains
	if len(shown) > 20 {
		shown = shown[:20]
	}

	return &finding.Finding{
		CheckID:     finding.CheckAssetReverseIP,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("Shared hosting detected: %d co-tenants on same IP (%s)", len(domains), ip),
		Description: fmt.Sprintf("%s resolves to IP %s which hosts %d other domains. Shared hosting increases attack surface — a compromise of any co-tenant could affect your environment.", asset, ip, len(domains)),
		Asset:       asset,
		Evidence: map[string]any{
			"ip":          ip,
			"co_tenants":  shown,
			"total_count": len(domains),
		},
		DiscoveredAt: time.Now(),
	}
}

// crtshOrgResult is a single row from crt.sh's JSON API.
type crtshOrgResult struct {
	NameValue string `json:"name_value"`
	IssuerOrg string `json:"issuer_o"`
}

// certOrgSearch queries crt.sh to find other domains with certificates issued
// to the same organization. Helps map the full attack surface beyond just subdomains.
func certOrgSearch(ctx context.Context, client *http.Client, asset string) *finding.Finding {
	// First, fetch a cert for the asset to get its organization name
	orgName := resolveCertOrg(ctx, client, asset)
	if orgName == "" {
		return nil
	}

	// Now search for all certs issued to that org
	url := fmt.Sprintf("https://crt.sh/?o=%s&output=json", urlEncode(orgName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256KB
	if err != nil {
		return nil
	}

	var results []crtshOrgResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil
	}

	// Collect unique domain names, excluding the asset itself
	seen := make(map[string]struct{})
	var relatedDomains []string
	for _, r := range results {
		// name_value can be multi-line (SANs)
		for _, name := range strings.Split(r.NameValue, "\n") {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name == "" || name == asset || strings.HasSuffix(name, "."+asset) {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				relatedDomains = append(relatedDomains, name)
			}
		}
	}

	if len(relatedDomains) == 0 {
		return nil
	}

	shown := relatedDomains
	if len(shown) > 30 {
		shown = shown[:30]
	}

	return &finding.Finding{
		CheckID:     finding.CheckAssetOrgDomains,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("Related domains found via SSL certificate org search (%s)", orgName),
		Description: fmt.Sprintf("Certificates issued to organization '%s' include %d domains beyond %s. These may be additional assets in your organization's attack surface that should be scanned.", orgName, len(relatedDomains), asset),
		Asset:       asset,
		Evidence: map[string]any{
			"org_name":        orgName,
			"related_domains": shown,
			"total_count":     len(relatedDomains),
		},
		DiscoveredAt: time.Now(),
	}
}

// resolveCertOrg fetches the most recent cert entry for an asset and extracts
// the issuer organization from crt.sh.
func resolveCertOrg(ctx context.Context, client *http.Client, asset string) string {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return ""
	}

	var results []crtshOrgResult
	if err := json.Unmarshal(body, &results); err != nil {
		return ""
	}

	for _, r := range results {
		org := strings.TrimSpace(r.IssuerOrg)
		if org != "" {
			return org
		}
	}
	return ""
}

// shodanLookup queries the Shodan host API for the resolved IP and returns
// an info finding with open ports, service banners, and known CVEs.
// Requires a valid Shodan API key (free tier is sufficient).
func shodanLookup(ctx context.Context, client *http.Client, asset, ip, apiKey string) *finding.Finding {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256KB
	if err != nil {
		return nil
	}

	// Parse a minimal subset of the Shodan response without a full JSON library.
	// We extract: open ports, hostnames, org, os, and CVE list.
	raw := string(body)

	ports := extractShodanIntArray(raw, "ports")
	hostnames := extractShodanStringArray(raw, "hostnames")
	org := extractShodanString(raw, "org")
	os := extractShodanString(raw, "os")
	// Shodan "vulns" is an object {"CVE-...": {...}, ...} not an array.
	// Extract CVE keys by finding all "CVE-" prefixed keys in the vulns object.
	var vulns []string
	if vidx := strings.Index(raw, `"vulns":{`); vidx != -1 {
		chunk := raw[vidx+len(`"vulns":`):]
		for {
			ci := strings.Index(chunk, `"CVE-`)
			if ci == -1 {
				break
			}
			chunk = chunk[ci+1:]
			end := strings.IndexByte(chunk, '"')
			if end == -1 {
				break
			}
			vulns = append(vulns, chunk[:end])
			chunk = chunk[end+1:]
		}
	}

	if len(ports) == 0 && org == "" {
		return nil // empty or error response
	}

	title := fmt.Sprintf("Shodan: %d open port(s) on %s", len(ports), ip)
	if org != "" {
		title += fmt.Sprintf(" (%s)", org)
	}

	var descParts []string
	if len(ports) > 0 {
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = fmt.Sprintf("%d", p)
		}
		descParts = append(descParts, "open ports: "+strings.Join(portStrs, ", "))
	}
	if len(hostnames) > 0 {
		descParts = append(descParts, "hostnames: "+strings.Join(hostnames, ", "))
	}
	if os != "" {
		descParts = append(descParts, "OS: "+os)
	}
	if len(vulns) > 0 {
		descParts = append(descParts, fmt.Sprintf("known CVEs: %s", strings.Join(vulns, ", ")))
	}

	severity := finding.SeverityInfo
	if len(vulns) > 0 {
		severity = finding.SeverityHigh // known CVEs on this IP
	}

	return &finding.Finding{
		CheckID:  finding.CheckShodanHostInfo,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: severity,
		Asset:    asset,
		Title:    title,
		Description: fmt.Sprintf(
			"Shodan has indexed %s (IP: %s): %s. "+
				"Use this data to cross-reference with your own port scan findings and to identify services "+
				"that may not be discoverable from your current network location.",
			asset, ip, strings.Join(descParts, "; ")),
		Evidence: map[string]any{
			"ip":        ip,
			"ports":     ports,
			"hostnames": hostnames,
			"org":       org,
			"os":        os,
			"vulns":     vulns,
		},
		DiscoveredAt: time.Now(),
	}
}

// extractShodanString pulls a simple string field from a JSON blob without
// a full JSON parse. Returns "" if the field is absent or null.
func extractShodanString(s, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(s, needle)
	if idx == -1 {
		return ""
	}
	rest := s[idx+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end == -1 {
		return ""
	}
	return rest[:end]
}

// extractShodanStringArray extracts a JSON string array field value.
func extractShodanStringArray(s, key string) []string {
	needle := `"` + key + `":[`
	idx := strings.Index(s, needle)
	if idx == -1 {
		return nil
	}
	rest := s[idx+len(needle):]
	end := strings.IndexByte(rest, ']')
	if end == -1 {
		return nil
	}
	chunk := rest[:end]
	var out []string
	for _, part := range strings.Split(chunk, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// extractShodanIntArray extracts a JSON integer array field value.
func extractShodanIntArray(s, key string) []int {
	needle := `"` + key + `":[`
	idx := strings.Index(s, needle)
	if idx == -1 {
		return nil
	}
	rest := s[idx+len(needle):]
	end := strings.IndexByte(rest, ']')
	if end == -1 {
		return nil
	}
	chunk := rest[:end]
	var out []int
	for _, part := range strings.Split(chunk, ",") {
		part = strings.TrimSpace(part)
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// urlEncode performs minimal URL encoding for the org name query parameter.
// extractNum extracts a JSON numeric (integer) field value as a string.
// Handles `"key":123` and `"key": 123` patterns.
func extractNum(s, key string) string {
	needle := `"` + key + `":`
	idx := strings.Index(s, needle)
	if idx == -1 {
		return ""
	}
	rest := strings.TrimLeft(s[idx+len(needle):], " ")
	end := strings.IndexAny(rest, ",} \n\t")
	if end == -1 {
		end = len(rest)
	}
	v := strings.TrimSpace(rest[:end])
	// Strip surrounding quotes if present (handles both string and numeric).
	v = strings.Trim(v, `"`)
	return v
}

// extractBool extracts a JSON boolean field as "true" or "false" string.
func extractBool(s, key string) string {
	needle := `"` + key + `":`
	idx := strings.Index(s, needle)
	if idx == -1 {
		return ""
	}
	rest := strings.TrimLeft(s[idx+len(needle):], " ")
	if strings.HasPrefix(rest, "true") {
		return "true"
	}
	if strings.HasPrefix(rest, "false") {
		return "false"
	}
	return ""
}

func urlEncode(s string) string {
	s = strings.ReplaceAll(s, " ", "%20")
	s = strings.ReplaceAll(s, "&", "%26")
	s = strings.ReplaceAll(s, "=", "%3D")
	s = strings.ReplaceAll(s, "+", "%2B")
	return s
}

// virusTotalLookup queries the VirusTotal API for domain reputation data.
// Reports malicious/suspicious vote counts and last analysis stats.
func virusTotalLookup(ctx context.Context, client *http.Client, asset, apiKey string) *finding.Finding {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil
	}

	raw := string(body)
	// VirusTotal returns integer counts, not quoted strings.
	malicious := extractNum(raw, "malicious")
	suspicious := extractNum(raw, "suspicious")
	reputation := extractNum(raw, "reputation")

	// Only emit a finding when there are malicious or suspicious votes.
	if malicious == "" || malicious == "0" {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckVirusTotalReputation,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("VirusTotal: %s flagged as malicious/suspicious by %s vendor(s)", asset, malicious),
		Description: fmt.Sprintf(
			"VirusTotal analysis of %s: %s vendor(s) flagged as malicious, %s as suspicious. "+
				"Reputation score: %s. This may indicate the domain has been used for phishing, "+
				"malware distribution, or command-and-control. Verify before concluding — "+
				"false positives occur with aggressive scanners or newly registered domains.",
			asset, malicious, suspicious, reputation),
		Asset: asset,
		Evidence: map[string]any{
			"malicious":  malicious,
			"suspicious": suspicious,
			"reputation": reputation,
		},
		ProofCommand: fmt.Sprintf(
			`curl -s "https://www.virustotal.com/api/v3/domains/%s" -H "x-apikey: $BEACON_VIRUSTOTAL_API_KEY" | python3 -m json.tool | head -40`,
			asset),
		DiscoveredAt: time.Now(),
	}
}

// censysLookup queries the Censys Search API for host data on the resolved IP.
func censysLookup(ctx context.Context, client *http.Client, asset, ip, apiID, apiSecret string) *finding.Finding {
	url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.SetBasicAuth(apiID, apiSecret)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return nil
	}

	raw := string(body)
	// Censys v2 uses "asn" as integer and "name" for org inside "autonomous_system".
	asn := extractNum(raw, "asn")
	org := extractShodanString(raw, "name") // "name" inside autonomous_system
	os := extractShodanString(raw, "os")

	if asn == "" && org == "" {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckCensysHostData,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Title:    fmt.Sprintf("Censys: host data for %s (IP: %s)", asset, ip),
		Description: fmt.Sprintf(
			"Censys internet-wide scan data for %s (IP: %s): ASN %s, org: %s, OS: %s. "+
				"Cross-reference with your own port scan results to identify discrepancies.",
			asset, ip, asn, org, os),
		Asset: asset,
		Evidence: map[string]any{
			"ip":  ip,
			"asn": asn,
			"org": org,
			"os":  os,
		},
		ProofCommand: fmt.Sprintf(
			`curl -s -u "$BEACON_CENSYS_API_ID:$BEACON_CENSYS_API_SECRET" "https://search.censys.io/api/v2/hosts/%s" | python3 -m json.tool`,
			ip),
		DiscoveredAt: time.Now(),
	}
}

// greyNoiseLookup queries the GreyNoise API to determine if an IP is a known
// internet scanner, crawler, or noise source. This reduces false positives when
// reviewing port scan findings.
func greyNoiseLookup(ctx context.Context, client *http.Client, asset, ip, apiKey string) *finding.Finding {
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("key", apiKey)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return nil
	}

	raw := string(body)
	// GreyNoise returns booleans for noise/riot, strings for classification/name.
	noise := extractBool(raw, "noise")
	riot := extractBool(raw, "riot")
	classification := extractShodanString(raw, "classification")
	name := extractShodanString(raw, "name")

	// Only report when the IP is classified as malicious or a known scanner.
	if classification != "malicious" && noise != "true" {
		return nil
	}

	severity := finding.SeverityInfo
	if classification == "malicious" {
		severity = finding.SeverityHigh
	}

	title := fmt.Sprintf("GreyNoise: %s (%s) — %s", ip, asset, classification)
	if name != "" {
		title = fmt.Sprintf("GreyNoise: %s (%s) — %s [%s]", ip, asset, classification, name)
	}

	return &finding.Finding{
		CheckID:  finding.CheckGreyNoiseContext,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: severity,
		Title:    title,
		Description: fmt.Sprintf(
			"GreyNoise classifies IP %s (resolving to %s) as '%s'. Noise: %s, RIOT: %s. "+
				"If malicious: investigate traffic from this IP immediately. "+
				"If noise scanner: findings from this IP may have lower credibility in logs.",
			ip, asset, classification, noise, riot),
		Asset: asset,
		Evidence: map[string]any{
			"ip":             ip,
			"classification": classification,
			"noise":          noise,
			"riot":           riot,
			"name":           name,
		},
		ProofCommand: fmt.Sprintf(
			`curl -s "https://api.greynoise.io/v3/community/%s" -H "key: $BEACON_GREYNOISE_API_KEY"`,
			ip),
		DiscoveredAt: time.Now(),
	}
}

// securityTrailsLookup queries SecurityTrails for historical subdomains and DNS records.
func securityTrailsLookup(ctx context.Context, client *http.Client, asset, apiKey string) *finding.Finding {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=true", asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return nil
	}

	// Parse subdomain list from JSON response.
	var result struct {
		Subdomains []string `json:"subdomains"`
		Endpoint   string   `json:"endpoint"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Subdomains) == 0 {
		return nil
	}

	shown := result.Subdomains
	if len(shown) > 50 {
		shown = shown[:50]
	}
	// Build FQDN list
	fqdns := make([]string, len(shown))
	for i, sub := range shown {
		fqdns[i] = sub + "." + asset
	}

	return &finding.Finding{
		CheckID:  finding.CheckAssetPassiveDNS,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Title:    fmt.Sprintf("SecurityTrails: %d subdomains found for %s (including inactive)", len(result.Subdomains), asset),
		Description: fmt.Sprintf(
			"SecurityTrails historical data reveals %d subdomains for %s, including inactive/decommissioned ones. "+
				"Inactive subdomains are common targets for subdomain takeover attacks.",
			len(result.Subdomains), asset),
		Asset: asset,
		Evidence: map[string]any{
			"subdomains":  fqdns,
			"total_count": len(result.Subdomains),
			"source":      "securitytrails",
		},
		ProofCommand: fmt.Sprintf(
			`curl -s "https://api.securitytrails.com/v1/domain/%s/subdomains" -H "APIKEY: $BEACON_SECURITYTRAILS_API_KEY" | python3 -m json.tool | head -50`,
			asset),
		DiscoveredAt: time.Now(),
	}
}
