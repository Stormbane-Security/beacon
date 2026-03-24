// Package dns checks for DNS-level misconfigurations that passive header
// observation cannot detect:
//
//   - DNSSEC missing: the zone has no DNSKEY record, meaning DNS responses
//     are unauthenticated and vulnerable to cache poisoning attacks.
//   - Wildcard DNS: a random subdomain resolves to an IP, which typically
//     means a catch-all DNS record is configured. An attacker can register
//     any subdomain (e.g. for phishing) and it will appear to resolve under
//     the target domain.
//
// Both checks use only passive DNS queries — no active probes against the
// target web server are made.
package dns

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "dns"

// Scanner checks for DNS misconfigurations.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	domain := rootDomain(asset)

	var findings []finding.Finding

	if f := checkDNSSEC(ctx, domain, asset); f != nil {
		findings = append(findings, *f)
	}

	if f := checkWildcard(ctx, domain, asset); f != nil {
		findings = append(findings, *f)
	}

	// CAA and zone transfer — only meaningful on root domains.
	if asset == domain {
		if f := checkCAA(ctx, domain, asset); f != nil {
			findings = append(findings, *f)
		}
		if f := checkZoneTransfer(ctx, domain, asset); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// checkCAA looks up CAA records for the zone. CAA records restrict which
// Certificate Authorities may issue certificates for the domain. Without CAA,
// any CA can issue a certificate — an attacker who compromises a CA can obtain
// a valid certificate for the domain without the owner's knowledge.
func checkCAA(ctx context.Context, domain, asset string) *finding.Finding {
	// Skip if the domain doesn't resolve at all.
	resolver := &net.Resolver{}
	if _, err := resolver.LookupNS(ctx, domain); err != nil {
		return nil
	}

	// Go's net package doesn't expose CAA (type 257) natively; use dig if available.
	digPath, err := exec.LookPath("dig")
	if err != nil {
		return nil // dig not installed — skip to avoid false positives
	}

	cmd := exec.CommandContext(ctx, digPath, "+short", "CAA", domain)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	if strings.TrimSpace(string(out)) != "" {
		return nil // CAA record found
	}

	return &finding.Finding{
		CheckID:  finding.CheckDNSMissingCAA,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityLow,
		Asset:    asset,
		Title:    fmt.Sprintf("No CAA record for %s", domain),
		Description: fmt.Sprintf(
			"The DNS zone for %s has no CAA (Certification Authority Authorization) record. "+
				"Without CAA, any Certificate Authority on the internet may issue TLS certificates "+
				"for this domain. Adding a CAA record restricts issuance to your approved CAs, "+
				"reducing the risk of mis-issuance or unauthorized certificate creation.",
			domain,
		),
		Evidence:     map[string]any{"domain": domain},
		DiscoveredAt: time.Now(),
	}
}

// checkDNSSEC looks up DNSKEY records for the zone via dig. If no DNSKEY
// record exists, DNSSEC is not configured and DNS responses can be forged.
// When dig is unavailable the check is skipped to avoid false positives.
func checkDNSSEC(ctx context.Context, domain, asset string) *finding.Finding {
	// Confirm the zone exists first — skip if the domain doesn't resolve at all.
	resolver := &net.Resolver{}
	if _, err := resolver.LookupNS(ctx, domain); err != nil {
		return nil
	}

	// Go's net package cannot query DNSKEY (type 48). Use dig when available.
	digPath, err := exec.LookPath("dig")
	if err != nil {
		return nil // dig not installed — skip to avoid false positives
	}

	cmd := exec.CommandContext(ctx, digPath, "+short", "DNSKEY", domain)
	out, err := cmd.Output()
	if err != nil {
		return nil // query failed — skip
	}

	if strings.TrimSpace(string(out)) != "" {
		return nil // DNSKEY record found — DNSSEC is configured
	}

	return &finding.Finding{
		CheckID:  finding.CheckDNSDNSSECMissing,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityLow,
		Asset:    asset,
		Title:    fmt.Sprintf("DNSSEC not enabled for %s", domain),
		Description: fmt.Sprintf(
			"The DNS zone for %s has no DNSKEY record, indicating DNSSEC is not configured. "+
				"Without DNSSEC, DNS responses can be forged by a network-positioned attacker "+
				"(DNS cache poisoning / Kaminsky attack), redirecting users to malicious servers "+
				"with no visible indication. Enable DNSSEC at your registrar and DNS provider.",
			domain,
		),
		Evidence:     map[string]any{"domain": domain},
		DiscoveredAt: time.Now(),
	}
}

// checkWildcard probes a randomly-named subdomain. If it resolves, a wildcard
// DNS entry is almost certainly configured — any subdomain will resolve.
func checkWildcard(ctx context.Context, domain, asset string) *finding.Finding {
	// Use a subdomain name that is extremely unlikely to be a real record.
	probe := "beacon-wildcard-probe-xq7z." + domain
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, probe)
	if err != nil || len(addrs) == 0 {
		return nil // does not resolve — no wildcard
	}

	return &finding.Finding{
		CheckID:  finding.CheckDNSWildcard,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("Wildcard DNS configured for *.%s", domain),
		Description: fmt.Sprintf(
			"The probe subdomain %s resolved to %s, indicating a wildcard DNS record "+
				"(*.%s) is configured. Wildcard records cause any subdomain to resolve, "+
				"which can be abused for phishing (e.g. login.%s looks legitimate) and "+
				"may complicate subdomain takeover detection. Review whether the wildcard "+
				"is intentional and restrict it if not.",
			probe, strings.Join(addrs, ", "), domain, domain,
		),
		Evidence: map[string]any{
			"domain":       domain,
			"probe":        probe,
			"resolved_ips": addrs,
		},
		DiscoveredAt: time.Now(),
	}
}

// checkZoneTransfer attempts a DNS zone transfer (AXFR) against each of the
// domain's authoritative nameservers. A successful transfer means the full
// DNS zone is publicly readable — all hostnames, IPs, mail servers, and
// internal infrastructure exposed to any internet host.
//
// Zone transfer is passive-read: it sends a standard DNS AXFR query (what any
// secondary nameserver sends during a legitimate zone sync). It does not modify
// any data. Misconfigured nameservers will log the connection — this is expected
// and is the same alert a legitimate secondary NS would generate.
// Skipped if dig is not installed.
func checkZoneTransfer(ctx context.Context, domain, asset string) *finding.Finding {
	f, _ := ZoneTransferDiscovery(ctx, domain, asset)
	return f
}

// ZoneTransferDiscovery attempts an AXFR against each nameserver for domain.
// It returns both the vulnerability finding (non-nil if transfer succeeded)
// and the list of hostnames discovered in the zone (used for asset discovery).
// This is exported so the surface module can feed discovered hosts into the
// asset scan queue during Phase 1 discovery.
func ZoneTransferDiscovery(ctx context.Context, domain, asset string) (*finding.Finding, []string) {
	// Get the authoritative nameservers for the zone.
	nss, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil || len(nss) == 0 {
		return nil, nil
	}

	digPath, err := exec.LookPath("dig")
	if err != nil {
		return nil, nil // dig not installed — skip
	}

	for _, ns := range nss {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		if nsHost == "" {
			continue
		}
		cmd := exec.CommandContext(ctx, digPath, "axfr", "@"+nsHost, domain)
		out, err := cmd.Output()
		if err != nil {
			continue // transfer refused — expected for correctly configured NS
		}
		output := string(out)

		// dig exits 0 even on a refused transfer; detect failure strings.
		if strings.Contains(output, "Transfer failed") ||
			strings.Contains(output, "REFUSED") ||
			strings.Contains(output, "SERVFAIL") ||
			strings.Contains(output, "connection timed out") {
			continue
		}

		// Count non-comment, non-empty record lines. A real zone transfer
		// returns at least: SOA + NS + one or more records + closing SOA = 4+.
		var records []string
		for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, ";") {
				records = append(records, line)
			}
		}
		if len(records) < 4 {
			continue // not enough content to be a real zone transfer
		}

		// Extract hostnames from A and AAAA records for asset discovery.
		// Format: <name> [TTL] IN A <ip>  or  <name> [TTL] IN AAAA <ip>
		var discovered []string
		seen := map[string]bool{}
		for _, rec := range records {
			fields := strings.Fields(rec)
			for i, f := range fields {
				if (f == "A" || f == "AAAA") && i+1 < len(fields) && i > 0 {
					name := strings.TrimSuffix(fields[0], ".")
					// Convert fully-qualified name to relative if needed.
					name = strings.TrimSuffix(name, "."+domain)
					if name != "" && name != "@" && !seen[name] {
						seen[name] = true
						// Use fully-qualified subdomain.
						if !strings.Contains(name, ".") {
							name = name + "." + domain
						}
						discovered = append(discovered, name)
					}
				}
			}
		}

		// Truncate evidence to 50 records to keep the finding concise.
		shown := records
		if len(shown) > 50 {
			shown = shown[:50]
		}

		f := &finding.Finding{
			CheckID:  finding.CheckDNSAXFRAllowed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("DNS zone transfer allowed on %s via %s", domain, nsHost),
			Description: fmt.Sprintf(
				"The nameserver %s allowed an unauthenticated DNS zone transfer (AXFR) for %s. "+
					"Zone transfers enumerate every hostname, IP address, mail server, and internal "+
					"record in the zone. This gives attackers a complete map of the infrastructure "+
					"and dramatically accelerates reconnaissance and targeting. "+
					"Restrict AXFR to authorised secondary nameservers only.",
				nsHost, domain,
			),
			Evidence: map[string]any{
				"nameserver":         nsHost,
				"record_count":       len(records),
				"records_shown":      shown,
				"discovered_hosts":   len(discovered),
			},
			DiscoveredAt: time.Now(),
		}
		return f, discovered
	}
	return nil, nil
}

// knownTwoLabelTLDs is a list of well-known second-level TLD components that
// form a two-label public suffix (e.g. "co.uk", "com.au"). When one of these
// suffixes is detected the registrable domain uses the three rightmost labels.
// This list covers the most common ccSLDs; a full PSL library would be more
// correct but introduces an external dependency.
var knownTwoLabelTLDs = map[string]bool{
	// United Kingdom
	"co.uk": true, "org.uk": true, "me.uk": true, "net.uk": true,
	"ltd.uk": true, "plc.uk": true, "gov.uk": true, "mod.uk": true,
	"sch.uk": true, "nhs.uk": true, "police.uk": true, "ac.uk": true,
	// Australia
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true,
	"gov.au": true, "asn.au": true, "id.au": true,
	// New Zealand
	"co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true,
	"geek.nz": true, "school.nz": true,
	// South Africa
	"co.za": true, "net.za": true, "org.za": true, "gov.za": true,
	"edu.za": true,
	// Japan
	"co.jp": true, "ne.jp": true, "or.jp": true, "go.jp": true,
	"ad.jp": true, "ed.jp": true, "ac.jp": true,
	// India
	"co.in": true, "net.in": true, "org.in": true, "gov.in": true,
	"nic.in": true, "ac.in": true, "res.in": true,
	// Brazil
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"edu.br": true,
	// China
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"edu.cn": true,
}

// rootDomain strips subdomains and returns the registrable domain portion.
// e.g. "sub.example.com" → "example.com"
// e.g. "sub.example.co.uk" → "example.co.uk"
//
// For known two-label public suffixes (co.uk, com.au, etc.) it uses the three
// rightmost labels. For all other cases it uses the two rightmost labels.
// A full Public Suffix List implementation would be more accurate for exotic
// ccTLDs, but this covers the vast majority of real-world cases without
// requiring an external dependency.
func rootDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}
	// Check if the two rightmost labels form a known two-label TLD.
	if len(parts) >= 3 {
		twoLabel := strings.Join(parts[len(parts)-2:], ".")
		if knownTwoLabelTLDs[twoLabel] {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
