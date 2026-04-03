package classify

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/playbook"
)

// collectDNSIntel fetches TXT, NS, MX, DMARC, and AAAA records for the hostname
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
	}
	ch := make(chan result, 1)

	go func() {
		var r result
		var wg sync.WaitGroup
		var mu sync.Mutex

		wg.Add(5)
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

	// ── SRV records ──────────────────────────────────────────────────────────
	// Discover services advertised via DNS SRV records. These reveal internal
	// infrastructure like Active Directory (LDAP/Kerberos), Exchange
	// (autodiscover), SIP, XMPP, and mail submission servers.
	e.SRVRecords = lookupSRVRecords(ctx, hostname)
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
