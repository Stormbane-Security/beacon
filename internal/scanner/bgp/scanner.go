// Package bgp discovers the IP ranges (prefixes) owned by an organization
// by resolving the domain to all its IPs (A records, MX, NS), looking up each
// IP's ASN via ip-api.com, then fetching all prefixes announced by each unique
// ASN via bgpview.io. Both services are free and require no API keys.
package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "bgp"

// maxIPsPerScan is the total IP enumeration ceiling across all prefixes.
// At 50 concurrent probes with a 3s timeout this is ~30 minutes worst-case.
// Prevents runaway enumeration on very large ASNs.
const maxIPsPerScan = 4096

// sharedInfraASNs are cloud/CDN providers whose ASNs contain millions of IPs
// belonging to unrelated customers. Enumerating them would probe infrastructure
// we have no authorization to test and produce no useful findings for the target.
var sharedInfraASNs = map[int]bool{
	// Amazon AWS
	16509: true, 14618: true, 38895: true,
	// Microsoft Azure
	8075: true, 8069: true,
	// Google Cloud
	15169: true, 396982: true,
	// Cloudflare
	13335: true,
	// Fastly
	54113: true,
	// Akamai
	20940: true, 16625: true,
	// DigitalOcean
	14061: true,
	// Hetzner
	24940: true,
	// OVH
	16276: true,
	// Linode/Akamai
	63949: true,
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Only run on root domain to avoid duplicate ASN lookups per subdomain.
	// "example.co.uk" has 2 dots and is a valid ccTLD+SLD root domain.
	// Anything with more than 2 dots is guaranteed to be a subdomain.
	if strings.Count(asset, ".") > 2 {
		return nil, nil
	}

	// Dedicated transport for external API calls (ip-api.com, bgpview.io).
	// MaxIdleConnsPerHost matches the asnSem concurrency of 5 so connections
	// are reused rather than torn down and re-established for each lookup.
	apiTransport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: apiTransport,
	}

	// Step 1: collect all IPs associated with the domain — A records directly,
	// plus MX and NS hostnames resolved to IPs. This catches orgs that host
	// mail on a different ASN from their web infrastructure.
	allIPs := collectDomainIPs(ctx, asset)
	if len(allIPs) == 0 {
		return nil, nil
	}

	// Step 2: look up ASN for each unique IP in parallel (rate-limited).
	// An org may span multiple ASNs (e.g. web on one, mail on another).
	type asnResult struct {
		asn     int
		orgName string
		ip      string
	}
	asnCh := make(chan asnResult, len(allIPs))
	asnSem := make(chan struct{}, 5) // ip-api.com rate limit: 45 req/min free
	var asnWg sync.WaitGroup
	for _, ip := range allIPs {
		ip := ip
		asnWg.Add(1)
		go func() {
			defer asnWg.Done()
			asnSem <- struct{}{}
			defer func() { <-asnSem }()
			asn, org, err := lookupASN(ctx, client, ip)
			if err == nil && asn != 0 {
				asnCh <- asnResult{asn: asn, orgName: org, ip: ip}
			}
		}()
	}
	asnWg.Wait()
	close(asnCh)

	// Step 3: deduplicate ASNs and collect per-ASN org names.
	asnOrg := map[int]string{}
	for r := range asnCh {
		if _, seen := asnOrg[r.asn]; !seen {
			asnOrg[r.asn] = r.orgName
		}
	}
	if len(asnOrg) == 0 {
		return nil, nil
	}

	// Step 4: fetch prefixes for all non-shared ASNs.
	// Shared cloud/CDN ASNs are skipped with an informational finding.
	var results []finding.Finding
	allPrefixes := []string{}
	prefixSeen := map[string]bool{}

	for asn, orgName := range asnOrg {
		if sharedInfraASNs[asn] {
			results = append(results, finding.Finding{
				CheckID:  finding.CheckAssetASNRanges,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityInfo,
				Title:    fmt.Sprintf("ASN%d (%s) is shared infrastructure — IP enumeration skipped", asn, orgName),
				Description: fmt.Sprintf(
					"%s resolves to a shared-infrastructure ASN (ASN%d, %s). "+
						"This provider hosts many tenants; enumerating IP ranges would probe unrelated systems. "+
						"IP range scanning is only performed for dedicated company ASNs.",
					asset, asn, orgName,
				),
				Asset:        asset,
				Evidence:     map[string]any{"asn": asn, "org_name": orgName},
				DiscoveredAt: time.Now(),
			})
			continue
		}

		prefixes, err := fetchASNPrefixes(ctx, client, asn)
		if err != nil || len(prefixes) == 0 {
			continue
		}

		results = append(results, finding.Finding{
			CheckID:     finding.CheckAssetASNRanges,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityInfo,
			Title:       fmt.Sprintf("ASN%d (%s) owns %d IP prefixes", asn, orgName, len(prefixes)),
			Description: fmt.Sprintf("%s has infrastructure in ASN%d (%s). This ASN announces %d IP prefixes — these are all IP ranges potentially owned by the organization.", asset, asn, orgName, len(prefixes)),
			Asset:       asset,
			Evidence: map[string]any{
				"asn":      asn,
				"org_name": orgName,
				"prefixes": prefixes,
			},
			DiscoveredAt: time.Now(),
		})

		for _, p := range prefixes {
			if !prefixSeen[p] {
				prefixSeen[p] = true
				allPrefixes = append(allPrefixes, p)
			}
		}
	}

	if len(allPrefixes) == 0 {
		return results, nil
	}

	// Derive the root domain for PTR matching (last two labels of asset).
	rootDomain := asset
	if parts := strings.Split(asset, "."); len(parts) > 2 {
		rootDomain = strings.Join(parts[len(parts)-2:], ".")
	}

	results = append(results, probeASNIPRange(ctx, allPrefixes)...)
	results = append(results, probeASNPTRRecords(ctx, allPrefixes, rootDomain)...)

	return results, nil
}

// collectDomainIPs resolves the domain's A records, and also resolves MX and NS
// hostnames to IPs. Returns deduplicated IP strings.
func collectDomainIPs(ctx context.Context, domain string) []string {
	seen := map[string]bool{}
	var ips []string

	addIP := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}

	// A records — direct IPs for the domain.
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err == nil {
		for _, a := range addrs {
			// Filter IPv4 only (IPv6 not useful for ASN range probing).
			if net.ParseIP(a).To4() != nil {
				addIP(a)
			}
		}
	}

	// MX records — mail servers may be on a different ASN.
	mxRecs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxRecs {
			host := strings.TrimSuffix(mx.Host, ".")
			if host == "" {
				continue
			}
			mxCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			mxAddrs, err := net.DefaultResolver.LookupHost(mxCtx, host)
			cancel()
			if err == nil {
				for _, a := range mxAddrs {
					if net.ParseIP(a).To4() != nil {
						addIP(a)
					}
				}
			}
		}
	}

	// NS records — authoritative name servers may be on a separate ASN.
	nsRecs, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err == nil {
		for _, ns := range nsRecs {
			host := strings.TrimSuffix(ns.Host, ".")
			if host == "" {
				continue
			}
			nsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			nsAddrs, err := net.DefaultResolver.LookupHost(nsCtx, host)
			cancel()
			if err == nil {
				for _, a := range nsAddrs {
					if net.ParseIP(a).To4() != nil {
						addIP(a)
					}
				}
			}
		}
	}

	return ips
}

// probeASNIPRange HTTP-probes IPs across all IPv4 prefixes announced by the ASN.
// Skips IPv6 prefixes (contain ":"). Stops after maxIPsPerScan total IPs to prevent
// runaway enumeration on large dedicated ASNs. For each responding IP it emits a finding.
func probeASNIPRange(ctx context.Context, prefixes []string) []finding.Finding {
	var mu sync.Mutex
	var findings []finding.Finding

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	// DisableKeepAlives: each probe target is a different IP, so connection
	// reuse has no value and holding idle connections wastes file descriptors.
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	probe := func(ip, scheme, prefix string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		url := scheme + "://" + ip
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode > 599 {
			return
		}

		port := "80"
		if scheme == "https" {
			port = "443"
		}

		f := finding.Finding{
			CheckID:  finding.CheckASNIPService,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    fmt.Sprintf("Web service on org IP %s (port %s)", ip, port),
			Description: fmt.Sprintf(
				"IP %s is within the organisation's ASN-announced prefix %s and responds to HTTP requests on port %s. "+
					"This host may not have a DNS record and could be an unmonitored asset.",
				ip, prefix, port,
			),
			Evidence: map[string]any{
				"ip":          ip,
				"scheme":      scheme,
				"status_code": resp.StatusCode,
				"prefix":      prefix,
			},
			DiscoveredAt: time.Now(),
		}
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	totalIPs := 0
	for _, prefix := range prefixes {
		if strings.Contains(prefix, ":") {
			continue // skip IPv6
		}
		ipNet, _, ok := parseCIDR(prefix)
		if !ok {
			continue
		}
		for _, ip := range enumerateIPs(ipNet) {
			if totalIPs >= maxIPsPerScan {
				break
			}
			totalIPs++
			for _, scheme := range []string{"http", "https"} {
				wg.Add(1)
				go probe(ip, scheme, prefix)
			}
		}
		if totalIPs >= maxIPsPerScan {
			break
		}
	}

	wg.Wait()
	return findings
}

// probeASNPTRRecords performs reverse DNS lookups on every IP across all IPv4
// prefixes. IPs whose PTR name matches rootDomain are emitted as findings.
// Stops after maxIPsPerScan total IPs.
func probeASNPTRRecords(ctx context.Context, prefixes []string, rootDomain string) []finding.Finding {
	var mu sync.Mutex
	var findings []finding.Finding

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	lookup := func(ip, prefix string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		ptrs, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
		if err != nil || len(ptrs) == 0 {
			return
		}

		for _, ptr := range ptrs {
			name := strings.TrimSuffix(ptr, ".")
			if !strings.HasSuffix(name, "."+rootDomain) && !strings.Contains(name, rootDomain) {
				continue
			}
			f := finding.Finding{
				CheckID:  finding.CheckPTRRecord,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityInfo,
				Title:    fmt.Sprintf("PTR record found: %s → %s", ip, name),
				Description: fmt.Sprintf(
					"IP %s (in prefix %s) has a reverse DNS name %s that matches the target domain %s. "+
						"This reveals an asset not present in forward DNS that may not be actively monitored.",
					ip, prefix, name, rootDomain,
				),
				Evidence: map[string]any{
					"ip":       ip,
					"ptr_name": name,
					"prefix":   prefix,
				},
				DiscoveredAt: time.Now(),
			}
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
			break // one finding per IP is sufficient
		}
	}

	totalIPs := 0
	for _, prefix := range prefixes {
		if strings.Contains(prefix, ":") {
			continue // skip IPv6
		}
		ipNet, _, ok := parseCIDR(prefix)
		if !ok {
			continue
		}
		for _, ip := range enumerateIPs(ipNet) {
			if totalIPs >= maxIPsPerScan {
				break
			}
			totalIPs++
			wg.Add(1)
			go lookup(ip, prefix)
		}
		if totalIPs >= maxIPsPerScan {
			break
		}
	}

	wg.Wait()
	return findings
}

// parseCIDR parses a CIDR string and returns the network, prefix length, and
// whether parsing succeeded.
func parseCIDR(cidr string) (*net.IPNet, int, bool) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, false
	}
	ones, _ := ipNet.Mask.Size()
	return ipNet, ones, true
}

// enumerateIPs returns all host IP strings in ipNet.
// No internal cap — callers control the total via maxIPsPerScan.
func enumerateIPs(ipNet *net.IPNet) []string {
	var ips []string
	ip := cloneIP(ipNet.IP.To4())
	if ip == nil {
		return nil
	}
	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		incrementIP(ip)
	}
	return ips
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// ipAPIResponse is the relevant subset of ip-api.com's JSON response.
type ipAPIResponse struct {
	AS     string `json:"as"`     // e.g. "AS13335 Cloudflare, Inc."
	Org    string `json:"org"`    // e.g. "AS13335 Cloudflare, Inc."
	Status string `json:"status"` // "success" or "fail"
}

// retryGet executes an HTTP GET with exponential back-off on 429 and 5xx
// responses. It respects the Retry-After header when present and retries
// up to maxAttempts times before returning the last response.
func retryGet(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	const maxAttempts = 3
	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s
			// Honour Retry-After if the server provided one.
			if lastResp != nil {
				if ra := lastResp.Header.Get("Retry-After"); ra != "" {
					if secs, err := strconv.Atoi(ra); err == nil && secs > 0 && secs < 120 {
						delay = time.Duration(secs) * time.Second
					}
				}
				lastResp.Body.Close()
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			// Clone request for retry (Body is nil for GETs so cloning is safe).
			clone := req.Clone(ctx)
			req = clone
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastResp = resp
			continue
		}
		return resp, nil
	}
	if lastResp != nil {
		return lastResp, nil // return last response so callers can inspect the status
	}
	return nil, lastErr
}

func lookupASN(ctx context.Context, client *http.Client, ip string) (int, string, error) {
	url := fmt.Sprintf("https://ip-api.com/json/%s?fields=status,as,org", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}

	resp, err := retryGet(ctx, client, req)
	if err != nil {
		return 0, "", fmt.Errorf("ip-api lookup failed")
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return 0, "", fmt.Errorf("ip-api lookup failed")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return 0, "", err
	}

	var result ipAPIResponse
	if err := json.Unmarshal(body, &result); err != nil || result.Status != "success" {
		return 0, "", fmt.Errorf("ip-api parse error")
	}

	// Parse ASN number from "AS13335 Cloudflare, Inc."
	asnStr := result.AS
	var asn int
	if _, err := fmt.Sscanf(asnStr, "AS%d", &asn); err != nil {
		return 0, "", fmt.Errorf("could not parse ASN from %q", asnStr)
	}

	// Extract org name (everything after the ASN number)
	orgName := result.Org
	if idx := strings.Index(orgName, " "); idx >= 0 {
		orgName = strings.TrimSpace(orgName[idx+1:])
	}

	return asn, orgName, nil
}

// bgpviewPrefixResponse is the relevant subset of bgpview.io's ASN prefixes response.
type bgpviewPrefixResponse struct {
	Data struct {
		IPv4Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv4_prefixes"`
		IPv6Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv6_prefixes"`
	} `json:"data"`
	Status string `json:"status"`
}

func fetchASNPrefixes(ctx context.Context, client *http.Client, asn int) ([]string, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", asn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := retryGet(ctx, client, req)
	if err != nil {
		return nil, fmt.Errorf("bgpview fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bgpview fetch failed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}

	var result bgpviewPrefixResponse
	if err := json.Unmarshal(body, &result); err != nil || result.Status != "ok" {
		return nil, fmt.Errorf("bgpview parse error")
	}

	var prefixes []string
	for _, p := range result.Data.IPv4Prefixes {
		if p.Prefix != "" {
			prefixes = append(prefixes, p.Prefix)
		}
	}
	for _, p := range result.Data.IPv6Prefixes {
		if p.Prefix != "" {
			prefixes = append(prefixes, p.Prefix)
		}
	}
	return prefixes, nil
}
