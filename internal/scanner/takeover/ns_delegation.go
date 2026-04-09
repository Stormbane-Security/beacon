// NS delegation takeover detection.
//
// A subdomain with NS records delegating to a DNS provider the company no
// longer uses is vulnerable to takeover: an attacker registers on that
// provider, claims the zone, and controls ALL DNS for the subdomain —
// including A, MX, TXT — making this often more severe than CNAME takeover.
//
// Algorithm:
//  1. Query NS records for the asset.
//  2. If NS records exist (subdomain is delegated), check each nameserver:
//     a. Is it a known DNS provider?
//     b. Does the nameserver actually respond for this zone?
//     c. If the NS responds NXDOMAIN for the zone → zone deleted, NS remains → takeover.
//     d. If the NS doesn't respond (SERVFAIL, REFUSED, timeout) → stale delegation.
package takeover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// nsDelegationProviders maps NS hostname substrings to human-readable provider names.
// If a nameserver hostname contains one of these keys, it is a managed DNS
// provider where an attacker could potentially register and claim the zone.
var nsDelegationProviders = map[string]string{
	"awsdns":           "AWS Route53",
	"cloudflare.com":   "Cloudflare",
	"digitalocean.com": "DigitalOcean",
	"googledomains.com": "Google Domains",
	"azure-dns":        "Azure DNS",
	"fly.io":           "Fly.io",
	"nsone.net":        "NS1",
	"dnsimple.com":     "DNSimple",
	"linode.com":       "Linode",
	"vultr.com":        "Vultr",
	"he.net":           "Hurricane Electric",
}

// nsQueryStatus represents the result of querying a nameserver directly.
type nsQueryStatus int

const (
	nsActive   nsQueryStatus = iota // NOERROR with answer records
	nsEmpty                         // NOERROR but no answer (zone exists, no records)
	nsNXDomain                      // NXDOMAIN — zone not found on this provider
	nsFailed                        // SERVFAIL, REFUSED, timeout, network error
)

// Resolver abstracts DNS lookups so tests can inject mock responses.
type Resolver interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	// LookupHostDirect queries a specific nameserver for A records.
	// The default implementation uses net.Resolver with a custom dialer.
	LookupHostDirect(ctx context.Context, nameserver, host string) (nsQueryStatus, error)
}

// defaultResolver uses the standard library DNS resolver.
type defaultResolver struct{}

func (defaultResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return net.DefaultResolver.LookupNS(ctx, name)
}

func (defaultResolver) LookupHostDirect(ctx context.Context, nameserver, host string) (nsQueryStatus, error) {
	// Build a resolver that talks only to the specified nameserver.
	ns := strings.TrimSuffix(nameserver, ".")
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(ns, "53"))
		},
	}

	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		// Classify the DNS error.
		var dnsErr *net.DNSError
		if ok := errorAs(err, &dnsErr); ok {
			if dnsErr.IsNotFound {
				return nsNXDomain, nil
			}
		}
		return nsFailed, err
	}

	if len(addrs) == 0 {
		return nsEmpty, nil
	}
	return nsActive, nil
}

// errorAs is a type-assertion helper equivalent to errors.As but avoids
// importing errors just for this (net package already provides the type).
func errorAs(err error, target **net.DNSError) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*net.DNSError); ok {
		*target = e
		return true
	}
	// Unwrap one layer (e.g. *net.OpError wrapping *net.DNSError).
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return errorAs(u.Unwrap(), target)
	}
	return false
}

// matchProvider returns the provider name if the nameserver hostname matches
// a known DNS provider, or "" if unknown.
func matchProvider(nsHost string) string {
	lower := strings.ToLower(strings.TrimSuffix(nsHost, "."))
	for pattern, name := range nsDelegationProviders {
		if strings.Contains(lower, pattern) {
			return name
		}
	}
	return ""
}

// CheckNSDelegation looks for subdomain NS records pointing to DNS
// providers where the zone may be claimable.
func CheckNSDelegation(ctx context.Context, asset string) []finding.Finding {
	return checkNSDelegationWith(ctx, asset, defaultResolver{})
}

// checkNSDelegationWith is the testable core that accepts an injected resolver.
func checkNSDelegationWith(ctx context.Context, asset string, resolver Resolver) []finding.Finding {
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	nsRecords, err := resolver.LookupNS(queryCtx, asset)
	if err != nil || len(nsRecords) == 0 {
		return nil // No NS delegation — nothing to check.
	}

	var findings []finding.Finding

	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		provider := matchProvider(nsHost)

		probeCtx, probeCancel := context.WithTimeout(ctx, 8*time.Second)
		status, _ := resolver.LookupHostDirect(probeCtx, nsHost, asset)
		probeCancel()

		switch status {
		case nsActive:
			// Zone is live on this NS — not vulnerable.
			continue

		case nsNXDomain:
			// Zone doesn't exist on the provider — confirmed takeover vector.
			providerLabel := provider
			if providerLabel == "" {
				providerLabel = nsHost
			}
			desc := fmt.Sprintf(
				"The subdomain %s has NS records delegating to %s (%s), "+
					"but the zone does not exist on this nameserver (NXDOMAIN). "+
					"An attacker can register on this DNS provider, claim the zone %s, "+
					"and control ALL DNS records for the subdomain — including A, MX, and TXT. "+
					"This enables phishing, email interception, and full domain impersonation.",
				asset, nsHost, providerLabel, asset,
			)
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckSubdomainNSDelegationTakeover,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityCritical,
				Asset:       asset,
				Title:       fmt.Sprintf("NS delegation takeover: %s → %s (%s)", asset, nsHost, providerLabel),
				Description: desc,
				ProofCommand: fmt.Sprintf("dig NS %s && dig @%s %s A", asset, nsHost, asset),
				Evidence: map[string]any{
					"nameserver": nsHost,
					"provider":   providerLabel,
					"ns_status":  "NXDOMAIN",
					"all_ns":     nsHostnames(nsRecords),
				},
				DiscoveredAt: time.Now(),
			})

		case nsEmpty:
			// Zone exists but is empty — may be claimable depending on provider.
			providerLabel := provider
			if providerLabel == "" {
				providerLabel = nsHost
			}
			desc := fmt.Sprintf(
				"The subdomain %s has NS records delegating to %s (%s). "+
					"The nameserver responds but the zone appears empty (NOERROR, no answer records). "+
					"If the zone is not actively managed, an attacker may be able to claim it.",
				asset, nsHost, providerLabel,
			)
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckSubdomainNSDelegationTakeover,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Asset:       asset,
				Title:       fmt.Sprintf("NS delegation empty zone: %s → %s (%s)", asset, nsHost, providerLabel),
				Description: desc,
				ProofCommand: fmt.Sprintf("dig NS %s && dig @%s %s A", asset, nsHost, asset),
				Evidence: map[string]any{
					"nameserver": nsHost,
					"provider":   providerLabel,
					"ns_status":  "NOERROR_EMPTY",
					"all_ns":     nsHostnames(nsRecords),
				},
				DiscoveredAt: time.Now(),
			})

		case nsFailed:
			// NS is dead/unresponsive — stale delegation.
			providerLabel := provider
			if providerLabel == "" {
				providerLabel = nsHost
			}
			desc := fmt.Sprintf(
				"The subdomain %s has NS records pointing to %s (%s), "+
					"but this nameserver does not respond (SERVFAIL, REFUSED, or timeout). "+
					"This is a stale NS delegation. If the nameserver hostname can be re-registered "+
					"or the provider account reclaimed, an attacker gains full DNS control.",
				asset, nsHost, providerLabel,
			)
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckSubdomainNSDelegationStale,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Asset:       asset,
				Title:       fmt.Sprintf("Stale NS delegation: %s → %s (%s)", asset, nsHost, providerLabel),
				Description: desc,
				ProofCommand: fmt.Sprintf("dig NS %s && dig @%s %s A +timeout=5", asset, nsHost, asset),
				Evidence: map[string]any{
					"nameserver": nsHost,
					"provider":   providerLabel,
					"ns_status":  "FAILED",
					"all_ns":     nsHostnames(nsRecords),
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// nsHostnames extracts the hostname strings from a slice of NS records.
func nsHostnames(records []*net.NS) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = strings.TrimSuffix(r.Host, ".")
	}
	return out
}
