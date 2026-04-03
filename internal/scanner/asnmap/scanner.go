// Package asnmap maps a domain's IP addresses to their ASN (Autonomous System
// Number) and discovers the full IP ranges owned by the same organization.
// This enables scope expansion — finding other services on IP ranges owned
// by the target.
package asnmap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}

const scannerName = "asnmap"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Only run on root domains.
	if strings.Count(asset, ".") > 1 {
		return nil, nil
	}

	// Resolve the asset to IPs.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, asset)
	if err != nil || len(ips) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	seenASN := map[string]bool{}

	for _, ip := range ips {
		if ip.IP.IsPrivate() || ip.IP.IsLoopback() {
			continue
		}

		info, err := queryASN(ctx, ip.IP.String())
		if err != nil || info == nil {
			continue
		}

		key := fmt.Sprintf("AS%s", info["asn"])
		if seenASN[key] {
			continue
		}
		seenASN[key] = true

		// Query for all prefixes announced by this ASN.
		prefixes, err := queryPrefixes(ctx, info["asn"].(string))
		if err != nil {
			prefixes = []string{}
		}

		info["prefixes"] = prefixes
		info["lookup_ip"] = ip.IP.String()

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckASNRangeDiscovered,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("ASN %s (%s) — %d prefix(es)", key, info["org"], len(prefixes)),
			Description: fmt.Sprintf(
				"The IP %s (resolved from %s) belongs to %s (%s). "+
					"This ASN announces %d IP prefix(es) that may host additional services.",
				ip.IP.String(), asset, info["org"], key, len(prefixes),
			),
			Evidence:     info,
			ProofCommand: fmt.Sprintf("whois -h whois.cymru.com ' -v %s'", ip.IP.String()),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// queryASN looks up ASN info for an IP via Team Cymru's DNS-based service.
func queryASN(ctx context.Context, ip string) (map[string]any, error) {
	// Use the BGP Toolkit HTTP API for simplicity.
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://api.bgpview.io/ip/%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Fallback to DNS-based lookup via Team Cymru.
		return queryASNViaDNS(ctx, ip)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return queryASNViaDNS(ctx, ip)
	}

	// Just use the DNS fallback — more reliable and doesn't depend on bgpview.
	return queryASNViaDNS(ctx, ip)
}

// queryASNViaDNS uses Team Cymru's DNS interface to look up ASN info.
func queryASNViaDNS(ctx context.Context, ip string) (map[string]any, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("not IPv4")
	}
	// Reverse the IP for DNS query.
	reversed := fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com", parts[3], parts[2], parts[1], parts[0])

	txts, err := net.DefaultResolver.LookupTXT(ctx, reversed)
	if err != nil || len(txts) == 0 {
		return nil, err
	}

	// Format: "ASN | IP/Prefix | CC | RIR | Allocated"
	fields := strings.Split(txts[0], " | ")
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected format")
	}

	asn := strings.TrimSpace(fields[0])
	prefix := strings.TrimSpace(fields[1])
	cc := strings.TrimSpace(fields[2])

	// Look up ASN name.
	asnTXTs, err := net.DefaultResolver.LookupTXT(ctx, fmt.Sprintf("AS%s.asn.cymru.com", asn))
	org := "unknown"
	if err == nil && len(asnTXTs) > 0 {
		asnFields := strings.Split(asnTXTs[0], " | ")
		if len(asnFields) >= 5 {
			org = strings.TrimSpace(asnFields[4])
		}
	}

	return map[string]any{
		"asn":     asn,
		"prefix":  prefix,
		"country": cc,
		"org":     org,
	}, nil
}

// queryPrefixes fetches all prefixes announced by an ASN via RIPE RIS.
func queryPrefixes(ctx context.Context, asn string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var prefixes []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, `"prefix"`) {
			// Simple extraction — avoid full JSON parse for this.
			start := strings.Index(line, `"prefix": "`)
			if start >= 0 {
				start += len(`"prefix": "`)
				end := strings.Index(line[start:], `"`)
				if end >= 0 {
					prefixes = append(prefixes, line[start:start+end])
				}
			}
		}
	}

	return prefixes, nil
}
