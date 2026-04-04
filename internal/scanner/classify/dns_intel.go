package classify

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/playbook"
)

// collectDNSIntel fetches TXT, NS, MX, DMARC, CAA, and AAAA records for the hostname
// and populates the DNS intelligence fields of Evidence. All lookups are standard
// DNS queries indistinguishable from what any resolver or mail server performs.
func collectDNSIntel(ctx context.Context, hostname string, e *playbook.Evidence) {
	// Run all lookups concurrently — they're independent and each may block on
	// the network. Use a short-lived WaitGroup; errors are silently swallowed
	// (partial evidence is fine — DNS is often flaky on external resolvers).
	type result struct {
		txt   []string
		ns    []string
		mx    []*net.MX
		dmarc []string
		aaaa  []net.IP
		caa   []string
	}
	ch := make(chan result, 1)

	go func() {
		var r result
		var wg sync.WaitGroup
		var mu sync.Mutex

		wg.Add(6)
		go func() {
			defer wg.Done()
			txt, err := net.DefaultResolver.LookupTXT(ctx, hostname)
			if err == nil {
				mu.Lock(); r.txt = txt; mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			ns, err := net.DefaultResolver.LookupNS(ctx, hostname)
			if err == nil {
				mu.Lock()
				for _, n := range ns {
					r.ns = append(r.ns, strings.TrimSuffix(n.Host, "."))
				}
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			mx, err := net.DefaultResolver.LookupMX(ctx, hostname)
			if err == nil {
				mu.Lock(); r.mx = mx; mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			// DMARC lives at _dmarc.<hostname>
			dmarc, err := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+hostname)
			if err == nil {
				mu.Lock(); r.dmarc = dmarc; mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", hostname)
			if err == nil {
				mu.Lock(); r.aaaa = ips; mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			// CAA records specify which CAs can issue certs for this domain.
			// Go 1.21+ net.Resolver doesn't have LookupCAA, so we use TXT
			// on the hostname and rely on the system resolver for type 257.
			// As a workaround, query via dig-style TXT on the CAA subdomain.
			caa := lookupCAARecords(ctx, hostname)
			if len(caa) > 0 {
				mu.Lock(); r.caa = caa; mu.Unlock()
			}
		}()
		wg.Wait()
		ch <- r
	}()

	r := <-ch

	// ── TXT records ───────────────────────────────────────────────────────────
	e.TXTRecords = r.txt
	for _, rec := range r.txt {
		if strings.HasPrefix(rec, "v=spf1") {
			e.SPFIPs = extractSPFIPs(rec)
			break
		}
	}

	// ── NS records ────────────────────────────────────────────────────────────
	e.NSRecords = r.ns

	// ── SOA record ───────────────────────────────────────────────────────────
	// TODO: stdlib net.Resolver does not support SOA queries directly.
	// Use a DNS library (e.g. miekg/dns) to query SOA and extract Mname.
	// Until then, leave SOARecord empty rather than populating with wrong data
	// (previously this incorrectly used NSRecords[0]).
	e.SOARecord = ""

	// ── MX records + provider detection ──────────────────────────────────────
	for _, mx := range r.mx {
		host := strings.TrimSuffix(strings.ToLower(mx.Host), ".")
		e.MXRecords = append(e.MXRecords, host)
	}
	e.MXProvider = detectMXProvider(e.MXRecords)

	// ── DMARC ─────────────────────────────────────────────────────────────────
	for _, rec := range r.dmarc {
		if strings.HasPrefix(rec, "v=DMARC1") {
			e.HasDMARC = true
			e.DMARCPolicy = extractDMARCPolicy(rec)
			break
		}
	}

	// ── AAAA records ──────────────────────────────────────────────────────────
	for _, ip := range r.aaaa {
		e.AAAARecords = append(e.AAAARecords, ip.String())
	}

	// ── CAA records ─────────────────────────────────────────────────────────
	e.CAARecords = r.caa

	// ── DNS provider detection ──────────────────────────────────────────────
	e.DNSProvider = detectDNSProvider(e.NSRecords)

	// ── SRV records ──────────────────────────────────────────────────────────
	// Discover services advertised via DNS SRV records. These reveal internal
	// infrastructure like Active Directory (LDAP/Kerberos), Exchange
	// (autodiscover), SIP, XMPP, and mail submission servers.
	e.SRVRecords = lookupSRVRecords(ctx, hostname)

	// ── CHAOS TXT records ───────────────────────────────────────────────────
	// version.bind and hostname.bind in the CHAOS class reveal DNS server
	// software identity. This is a standard technique used by dig/nslookup.
	// Only query if we have NS records to target.
	if len(e.NSRecords) > 0 {
		e.CHAOSVersion = lookupCHAOSVersion(ctx, e.NSRecords[0])
	}
}

// srvQueries are common DNS SRV record prefixes that reveal infrastructure.
var srvQueries = []string{
	"_ldap._tcp",           // Active Directory LDAP
	"_kerberos._tcp",       // Kerberos / AD authentication
	"_gc._tcp",             // Active Directory Global Catalog
	"_autodiscover._tcp",   // Exchange / Office 365 Autodiscover
	"_sip._tcp",            // SIP / VoIP
	"_sip._udp",            // SIP over UDP
	"_xmpp-server._tcp",    // XMPP / Jabber federation
	"_xmpp-client._tcp",    // XMPP client connections
	"_imaps._tcp",          // IMAP over TLS
	"_submission._tcp",     // SMTP mail submission (port 587)
	"_caldavs._tcp",        // CalDAV (calendar)
	"_carddavs._tcp",       // CardDAV (contacts)
	"_matrix._tcp",         // Matrix federation
}

// lookupSRVRecords queries common SRV record prefixes and returns any that
// resolve. Each successful lookup indicates an advertised service.
func lookupSRVRecords(ctx context.Context, hostname string) map[string][]string {
	type srvResult struct {
		query   string
		entries []string
	}

	ch := make(chan srvResult, len(srvQueries))
	for _, q := range srvQueries {
		go func(query string) {
			fqdn := query + "." + hostname
			_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "", "", fqdn)
			if err != nil || len(addrs) == 0 {
				ch <- srvResult{query: query}
				return
			}
			var entries []string
			for _, a := range addrs {
				host := strings.TrimSuffix(a.Target, ".")
				if host != "" && host != "." {
					entries = append(entries, fmt.Sprintf("%s:%d", host, a.Port))
				}
			}
			ch <- srvResult{query: query, entries: entries}
		}(q)
	}

	results := make(map[string][]string)
	for range srvQueries {
		r := <-ch
		if len(r.entries) > 0 {
			results[r.query] = r.entries
		}
	}
	if len(results) == 0 {
		return nil
	}
	return results
}

// detectMXProvider infers the email provider from MX hostnames.
// Returns a short label: "google", "microsoft", "proofpoint", "mimecast",
// "mailgun", "sendgrid", "amazon", or "" when not recognised.
func detectMXProvider(mxHosts []string) string {
	for _, h := range mxHosts {
		switch {
		case strings.Contains(h, "google.com") || strings.Contains(h, "googlemail.com"):
			return "google"
		case strings.Contains(h, "outlook.com") || strings.Contains(h, "hotmail.com") ||
			strings.Contains(h, "protection.outlook.com"):
			return "microsoft"
		case strings.Contains(h, "proofpoint.com") || strings.Contains(h, "pphosted.com"):
			return "proofpoint"
		case strings.Contains(h, "mimecast.com"):
			return "mimecast"
		case strings.Contains(h, "mailgun.org"):
			return "mailgun"
		case strings.Contains(h, "sendgrid.net"):
			return "sendgrid"
		case strings.Contains(h, "amazonses.com") || strings.Contains(h, "amazonaws.com"):
			return "amazon"
		case strings.Contains(h, "messagelabs.com") || strings.Contains(h, "symantec.com"):
			return "symantec"
		case strings.Contains(h, "barracudanetworks.com"):
			return "barracuda"
		case strings.Contains(h, "mailchannels.net"):
			return "mailchannels"
		}
	}
	return ""
}

// extractDMARCPolicy returns the p= tag value from a DMARC record string.
// Returns "none", "quarantine", "reject", or "" when the tag is absent.
func extractDMARCPolicy(rec string) string {
	for _, field := range strings.Fields(strings.ReplaceAll(rec, ";", " ")) {
		field = strings.TrimSpace(field)
		if strings.HasPrefix(strings.ToLower(field), "p=") {
			return strings.TrimPrefix(strings.ToLower(field), "p=")
		}
	}
	return ""
}

// extractSPFIPs returns all ip4: and ip6: CIDR ranges directly specified in an SPF record.
// These are the IP blocks that are explicitly authorised to send email from this domain —
// often revealing mail server infrastructure, cloud provider ranges, and third-party senders.
func extractSPFIPs(spf string) []string {
	var ips []string
	for _, field := range strings.Fields(spf) {
		field = strings.TrimLeft(field, "+-~?")
		switch {
		case strings.HasPrefix(field, "ip4:"):
			ips = append(ips, strings.TrimPrefix(field, "ip4:"))
		case strings.HasPrefix(field, "ip6:"):
			ips = append(ips, strings.TrimPrefix(field, "ip6:"))
		}
	}
	return ips
}

// EmitDNSIntelFinding returns an info finding summarising the DNS intelligence
// collected from TXT and NS records. Returns nil when nothing was collected.
// This gives the AI enricher full DNS context for every other finding on the asset.
func EmitDNSIntelFinding(ev playbook.Evidence, asset string) *finding.Finding {
	if len(ev.TXTRecords) == 0 && len(ev.NSRecords) == 0 {
		return nil
	}

	evidence := map[string]any{
		"txt_records": ev.TXTRecords,
		"ns_records":  ev.NSRecords,
	}
	if len(ev.SPFIPs) > 0 {
		evidence["spf_ip_ranges"] = ev.SPFIPs
	}

	var descParts []string
	if len(ev.NSRecords) > 0 {
		descParts = append(descParts, fmt.Sprintf("nameservers: %s", strings.Join(ev.NSRecords, ", ")))
	}
	if len(ev.SPFIPs) > 0 {
		descParts = append(descParts, fmt.Sprintf("SPF-authorized IP ranges: %s", strings.Join(ev.SPFIPs, ", ")))
	}
	descParts = append(descParts, fmt.Sprintf("%d TXT record(s) collected", len(ev.TXTRecords)))

	f := finding.Finding{
		CheckID:      finding.CheckDNSTXTHarvest,
		Module:       "surface",
		Scanner:      "classify",
		Severity:     finding.SeverityInfo,
		Asset:        asset,
		Title:        fmt.Sprintf("DNS intelligence harvested: %d TXT, %d NS record(s)", len(ev.TXTRecords), len(ev.NSRecords)),
		Description:  fmt.Sprintf("Passive DNS queries for %s revealed: %s. TXT records may contain SPF/DMARC policies, third-party service verification tokens (Google, SendGrid, HubSpot, etc.), and internal domain hints.", asset, strings.Join(descParts, "; ")),
		Evidence:     evidence,
		DiscoveredAt: time.Now(),
	}
	return &f
}

// detectDNSProvider infers the DNS hosting provider from NS record hostnames.
func detectDNSProvider(nsHosts []string) string {
	for _, h := range nsHosts {
		h = strings.ToLower(h)
		switch {
		case strings.Contains(h, "cloudflare.com"):
			return "cloudflare"
		case strings.Contains(h, "awsdns"):
			return "aws_route53"
		case strings.Contains(h, "googledomains.com") || strings.Contains(h, "google.com"):
			return "gcp_cloud_dns"
		case strings.Contains(h, "azure-dns.com") || strings.Contains(h, "azure-dns.net"):
			return "azure_dns"
		case strings.Contains(h, "domaincontrol.com"):
			return "godaddy"
		case strings.Contains(h, "registrar-servers.com"):
			return "namecheap"
		case strings.Contains(h, "dnsimple.com"):
			return "dnsimple"
		case strings.Contains(h, "nsone.net"):
			return "ns1"
		case strings.Contains(h, "cloudns.net"):
			return "cloudns"
		case strings.Contains(h, "hetzner.com") || strings.Contains(h, "hetzner.de"):
			return "hetzner"
		case strings.Contains(h, "digitalocean.com"):
			return "digitalocean"
		case strings.Contains(h, "linode.com"):
			return "linode"
		case strings.Contains(h, "dynect.net"):
			return "dyn"
		case strings.Contains(h, "ultradns.com") || strings.Contains(h, "ultradns.net"):
			return "ultradns"
		case strings.Contains(h, "dnsmadeeasy.com"):
			return "dnsmadeeasy"
		case strings.Contains(h, "verisign"):
			return "verisign"
		case strings.Contains(h, "ovh.net"):
			return "ovh"
		}
	}
	return ""
}

// lookupCAARecords queries CAA records for the given hostname.
// CAA records specify which Certificate Authorities are permitted to issue
// certificates for the domain. Go's net package doesn't have a direct CAA
// lookup, so we use a TXT query on the hostname and parse CAA-style records,
// or fall back to exec'ing dig if available.
func lookupCAARecords(ctx context.Context, hostname string) []string {
	// Try using dig for proper CAA record type (257) — it's the only reliable
	// way from pure Go without a low-level DNS library.
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	out, err := execDigCAA(ctx2, hostname)
	if err != nil || len(out) == 0 {
		return nil
	}
	return out
}

// execDigCAA shells out to dig for CAA records. Returns parsed issue/issuewild values.
func execDigCAA(ctx context.Context, hostname string) ([]string, error) {
	// Use Go's exec to run: dig +short CAA <hostname>
	// Output format: 0 issue "letsencrypt.org"
	cmd := exec.CommandContext(ctx, "dig", "+short", "CAA", hostname)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var records []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// CAA records look like: 0 issue "letsencrypt.org"
		records = append(records, line)
	}
	return records, nil
}

// lookupCHAOSVersion queries the CHAOS TXT record for version.bind against
// the given nameserver. This reveals DNS server software (BIND, PowerDNS, etc.).
// Returns empty string if the query fails or the server doesn't respond.
func lookupCHAOSVersion(ctx context.Context, nameserver string) string {
	// Use dig to query CHAOS TXT version.bind @nameserver
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// dig +short CHAOS TXT version.bind @nameserver
	cmd := exec.CommandContext(ctx2, "dig", "+short", "-c", "CH", "-t", "TXT", "version.bind", "@"+nameserver)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	result := strings.TrimSpace(string(out))
	// Strip surrounding quotes
	result = strings.Trim(result, "\"")
	if result == "" || strings.Contains(result, "REFUSED") || strings.Contains(result, "NXDOMAIN") {
		return ""
	}
	return result
}
