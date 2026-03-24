// Package passivedns queries HackerTarget's free passive DNS API to retrieve
// historical DNS records for a domain. Historical records often reveal
// subdomains that have been deleted but may still exist in attacker databases,
// or infrastructure that was previously exposed.
// No API key required.
package passivedns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// cdnCIDRs lists IP ranges belonging to CDN/WAF providers whose edge nodes
// commonly appear in passive DNS history. An IP in one of these ranges is a
// CDN edge node, NOT the true origin server, and must not be added as an
// asset to scan (there is no point scanning a shared Cloudflare edge IP).
//
// Sources:
//   Cloudflare: https://www.cloudflare.com/ips/
//   Fastly:     https://api.fastly.com/public-ip-list
//   CloudFront: AWS ip-ranges.json (CLOUDFRONT service)
//   Akamai:     published edge ranges (major /16s)
var cdnCIDRs = func() []*net.IPNet {
	cidrs := []string{
		// Cloudflare
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
		// Fastly
		"151.101.0.0/16",
		"199.232.0.0/16",
		"23.235.32.0/20",
		"43.249.72.0/22",
		"103.244.50.0/24",
		"104.156.80.0/20",
		"146.75.0.0/16",
		"157.52.64.0/18",
		"167.82.0.0/17",
		"185.31.16.0/22",
		"199.27.72.0/21",
		// AWS CloudFront
		"13.32.0.0/15",
		"13.35.0.0/16",
		"52.84.0.0/15",
		"54.192.0.0/16",
		"64.252.64.0/18",
		"65.9.128.0/18",
		"70.132.0.0/18",
		"99.84.0.0/16",
		"204.246.172.0/23",
		"205.251.192.0/19",
		"216.137.32.0/19",
		// Vercel
		"76.76.21.0/24",
		"76.76.22.0/24",
		"64.29.17.0/24",
		"216.150.1.0/24",
		"66.33.60.0/24",
		"66.33.61.0/24",
		// Fastly (additional ranges)
		"199.36.156.0/22",
		"199.36.158.0/23",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}()

// IsCDNIP returns true if the given IP address belongs to a known CDN/WAF
// provider. Such IPs are shared edge nodes, not origin servers.
// Exported so other scanners (BGP, classify) can skip CDN edge IPs.
func IsCDNIP(ipStr string) bool {
	return isCDNIP(ipStr)
}

// isCDNIP is the internal implementation.
func isCDNIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Normalise to 4-byte form for fast comparison.
	ip4 := ip.To4()
	if ip4 != nil {
		ip = ip4
	}
	for _, cidr := range cdnCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}


const scannerName = "passivedns"

type record struct {
	Hostname string
	IP       string
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Only run on root domains, not on deep subdomains. The heuristic counts
	// dot-separated labels: "example.com" has 1 dot, "example.co.uk" has 2
	// dots (a valid ccTLD root domain). Anything with more than 2 dots is
	// guaranteed to be a subdomain (e.g. "api.example.co.uk") and is skipped.
	if strings.Count(asset, ".") > 2 {
		return nil, nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", asset)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, nil
	}

	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "error") || strings.Contains(text, "API count exceeded") {
		return nil, nil
	}

	// HackerTarget returns "hostname,ip" per line
	seen := make(map[string]struct{})
	var records []record
	var subdomains []string

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 2 {
			continue
		}
		hostname := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])

		if hostname == asset {
			continue
		}
		if _, ok := seen[hostname]; ok {
			continue
		}
		seen[hostname] = struct{}{}
		records = append(records, record{Hostname: hostname, IP: ip})
		subdomains = append(subdomains, hostname)
	}

	if len(records) == 0 {
		return nil, nil
	}

	// Convert to evidence-friendly format
	var evidenceRecords []map[string]string
	for _, r := range records {
		evidenceRecords = append(evidenceRecords, map[string]string{
			"hostname": r.Hostname,
			"ip":       r.IP,
		})
	}

	var findings []finding.Finding
	findings = append(findings, finding.Finding{
		CheckID:     finding.CheckAssetPassiveDNS,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("%d hosts found in passive DNS history for %s", len(records), asset),
		Description: fmt.Sprintf("Passive DNS history reveals %d hostname/IP pairs previously associated with %s. These may include deleted subdomains, old infrastructure, or forgotten services that could still be live.", len(records), asset),
		Asset:       asset,
		Evidence: map[string]any{
			"records":    evidenceRecords,
			"subdomains": subdomains,
			"count":      len(records),
		},
		DiscoveredAt: time.Now(),
	})

	// CDN bypass: probe historical IPs with the asset's Host header.
	// Only runs in deep mode because each probe sends an HTTP request directly
	// to a historical IP address, leaving a connection footprint on the origin
	// server's access logs. Deep mode requires --permission-confirmed.
	if scanType == module.ScanDeep {
		findings = append(findings, cdnBypassFromHistory(ctx, client, asset, records)...)
	}

	return findings, nil
}

// cdnBypassFromHistory compares the asset's current DNS IP against historical
// IPs from passive DNS records. For each distinct historical IP, it sends an
// HTTP request with the asset in the Host header. A successful response
// (2xx or 3xx) indicates the old server is still live and reachable directly.
func cdnBypassFromHistory(ctx context.Context, client *http.Client, asset string, records []record) []finding.Finding {
	// Resolve current IP — if resolution fails, skip the check.
	currentAddrs, err := net.DefaultResolver.LookupHost(ctx, asset)
	if err != nil || len(currentAddrs) == 0 {
		return nil
	}
	current := make(map[string]struct{}, len(currentAddrs))
	for _, a := range currentAddrs {
		current[a] = struct{}{}
	}

	// Collect unique historical IPs that differ from the current IP set.
	// Skip IPs in known CDN edge ranges — those are shared infrastructure,
	// not origin servers, and probing them reveals nothing about the target.
	seenIP := make(map[string]struct{})
	var candidates []string
	for _, r := range records {
		if r.IP == "" {
			continue
		}
		if _, isCurrent := current[r.IP]; isCurrent {
			continue
		}
		if _, seen := seenIP[r.IP]; seen {
			continue
		}
		if isCDNIP(r.IP) {
			continue // shared CDN edge node, not an origin server
		}
		seenIP[r.IP] = struct{}{}
		candidates = append(candidates, r.IP)
	}

	probeClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type respondingIP struct {
		IP     string
		Status int
	}
	var responding []respondingIP

	for _, ip := range candidates {
		url := "http://" + ip + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Host = asset
		resp, err := probeClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			responding = append(responding, respondingIP{IP: ip, Status: resp.StatusCode})
		}
	}

	if len(responding) == 0 {
		return nil
	}

	// Build evidence list and proof command showing all responding IPs.
	ipList := make([]map[string]any, 0, len(responding))
	for _, r := range responding {
		ipList = append(ipList, map[string]any{
			"ip":     r.IP,
			"status": r.Status,
		})
	}

	// Proof command: curl each responding IP with the correct Host header so the
	// operator can confirm the origin server answers directly (bypassing CDN/WAF).
	var proofLines []string
	proofLines = append(proofLines, fmt.Sprintf("# Each command should return HTTP 2xx, proving direct origin access for %s (bypassing CDN/WAF)", asset))
	for _, r := range responding {
		proofLines = append(proofLines, fmt.Sprintf(
			`curl -sv -o /dev/null -w "%%{http_code}" -H "Host: %s" http://%s/`,
			asset, r.IP,
		))
	}
	proofCmd := strings.Join(proofLines, "\n")

	return []finding.Finding{{
		CheckID: finding.CheckCDNOriginFound,
		Module:  "surface",
		Scanner: scannerName,
		Severity: finding.SeverityHigh,
		Title: fmt.Sprintf("%d historical origin IPs bypass CDN/WAF for %s", len(responding), asset),
		Description: fmt.Sprintf(
			"Passive DNS history shows %d IPs that previously resolved to %s are still "+
				"reachable via HTTP with Host: %s, indicating the origin servers are "+
				"directly accessible. An attacker can bypass CDN and WAF protections "+
				"(e.g. Cloudflare, Fastly) by sending requests directly to these IPs "+
				"with the correct Host header — all filtering is skipped.",
			len(responding), asset, asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"responding_ips":   ipList,
			"current_ips":      currentAddrs,
			"discovery_method": "passive_dns_history",
			"ip_count":         len(responding),
		},
		ProofCommand: proofCmd,
		DiscoveredAt: time.Now(),
	}}
}

// Subdomains extracts the list of discovered hostnames from a passive DNS finding.
// The surface module calls this to expand the scan target list.
func Subdomains(f finding.Finding) []string {
	if f.CheckID != finding.CheckAssetPassiveDNS {
		return nil
	}
	subs, _ := f.Evidence["subdomains"].([]any)
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		if str, ok := s.(string); ok && str != "" {
			out = append(out, str)
		}
	}
	return out
}

// RespondingIPs extracts the list of live historical origin IPs from a CDN
// origin bypass finding. The surface module adds these as scan assets so the
// origin server receives the full classify + playbook + scanner treatment,
// revealing vulnerabilities that the CDN/WAF would otherwise mask.
func RespondingIPs(f finding.Finding) []string {
	if f.CheckID != finding.CheckCDNOriginFound {
		return nil
	}
	// Evidence is stored as []map[string]any but deserialised from SQLite/JSON
	// as []any containing map[string]any — handle both forms.
	raw := f.Evidence["responding_ips"]
	var out []string
	switch v := raw.(type) {
	case []map[string]any:
		for _, e := range v {
			if ip, ok := e["ip"].(string); ok && ip != "" {
				out = append(out, ip)
			}
		}
	case []any:
		for _, item := range v {
			if e, ok := item.(map[string]any); ok {
				if ip, ok := e["ip"].(string); ok && ip != "" {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}
