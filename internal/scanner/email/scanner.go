// Package email implements the email security scanner.
// All checks are passive DNS/HTTPS lookups — no mail is sent, no permission required.
package email

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "email"

// dkimSelectors is the list of common DKIM selectors to probe.
var dkimSelectors = []string{
	"google", "default", "mail", "k1",
	"selector1", "selector2",
	"s1", "s2", "dkim", "email",
}

// Scanner checks email security configuration for a domain.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// emailRelevant returns true when the scanner should run against this asset.
// SPF/DMARC are apex-level controls — checking every subdomain produces
// dozens of identical CRIT findings for one root-cause problem. We run only
// against root/apex domains (one dot) and explicit mail-related subdomains.
func emailRelevant(asset string) bool {
	// Strip port suffix if present (e.g. "example.com:8080").
	host := asset
	if i := strings.LastIndex(host, ":"); i > strings.LastIndex(host, "]") {
		host = host[:i]
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return true // apex / root domain
	}
	// Sub-domain: only run if it looks like a mail-handling host.
	sub := strings.ToLower(parts[0])
	mailPrefixes := map[string]bool{
		"mail": true, "smtp": true, "webmail": true, "mx": true,
		"imap": true, "pop": true, "pop3": true, "email": true,
		"mailout": true, "relay": true,
	}
	return mailPrefixes[sub]
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if !emailRelevant(asset) {
		return nil, nil
	}
	domain := asset
	// Use bare hostname without port for DNS lookups.
	if i := strings.LastIndex(domain, ":"); i > strings.LastIndex(domain, "]") {
		domain = domain[:i]
	}
	var findings []finding.Finding
	now := time.Now()

	add := func(checkID finding.CheckID, sev finding.Severity, title, desc string, evidence map[string]any) {
		findings = append(findings, finding.Finding{
			CheckID:      checkID,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        title,
			Description:  desc,
			Asset:        domain,
			Evidence:     evidence,
			DiscoveredAt: now,
		})
	}

	spfRecord, spfFindings := checkSPF(ctx, domain)
	findings = append(findings, spfFindings...)
	findings = append(findings, checkSPFIncludes(ctx, domain, spfRecord)...)

	dmarcRecord, dmarcFindings := checkDMARC(ctx, domain)
	findings = append(findings, dmarcFindings...)

	// Spoofability: no SPF + no DMARC = trivially spoofable
	if spfRecord == "" && dmarcRecord == "" {
		add(finding.CheckEmailSpoofable, finding.SeverityCritical,
			"Domain can be impersonated in phishing emails",
			fmt.Sprintf("The domain %s has neither an SPF record nor a DMARC policy. Anyone can send email appearing to come from @%s without any authentication checks failing.", domain, domain),
			map[string]any{"spf": nil, "dmarc": nil},
		)
	}

	findings = append(findings, checkDKIM(ctx, domain)...)
	findings = append(findings, checkMTASTS(ctx, domain)...)
	findings = append(findings, checkTLSRPT(ctx, domain)...)
	findings = append(findings, checkBIMI(ctx, domain)...)
	findings = append(findings, checkDANE(ctx, domain)...)
	findings = append(findings, checkSMTP(ctx, domain, now, scanType)...)

	return findings, nil
}

func checkSPF(ctx context.Context, domain string) (string, []finding.Finding) {
	records, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		return "", nil
	}

	var spf string
	for _, r := range records {
		if strings.HasPrefix(r, "v=spf1") {
			spf = r
			break
		}
	}

	if spf == "" {
		return "", []finding.Finding{{
			CheckID:      finding.CheckEmailSPFMissing,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityHigh,
			Title:        "Missing SPF record",
			Description:  fmt.Sprintf("No SPF record found for %s. Without SPF, mail servers cannot verify that email from this domain is legitimate.", domain),
			Asset:        domain,
			Evidence:     map[string]any{"txt_records": records},
			DiscoveredAt: time.Now(),
		}}
	}

	var findings []finding.Finding

	// Check for soft/neutral fail policy.
	// ~all (softfail) is often intentional during SPF rollout or for forwarding
	// compatibility — report as Low. ?all (neutral) is slightly worse as it
	// explicitly opts out of any enforcement — report as Medium.
	if strings.Contains(spf, "~all") || strings.Contains(spf, "?all") {
		policy := "~all"
		sev := finding.SeverityLow
		if strings.Contains(spf, "?all") {
			policy = "?all"
			sev = finding.SeverityMedium
		}
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckEmailSPFSoftfail,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        "SPF policy does not reject unauthorized senders",
			Description:  fmt.Sprintf("SPF record uses %s (softfail/neutral). Unauthorized senders may still deliver mail. Use -all to reject.", policy),
			Asset:        domain,
			Evidence:     map[string]any{"spf_record": spf},
			DiscoveredAt: time.Now(),
		})
	}

	// Count DNS lookups in SPF record (limit is 10)
	lookupCount := countSPFLookups(spf)
	if lookupCount > 10 {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckEmailSPFLookupLimit,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityMedium,
			Title:        "SPF record exceeds DNS lookup limit",
			Description:  fmt.Sprintf("SPF record for %s requires %d DNS lookups, exceeding the RFC limit of 10. This causes SPF to fail with PermError.", domain, lookupCount),
			Asset:        domain,
			Evidence:     map[string]any{"spf_record": spf, "lookup_count": lookupCount},
			DiscoveredAt: time.Now(),
		})
	}

	return spf, findings
}

func checkDMARC(ctx context.Context, domain string) (string, []finding.Finding) {
	dmarcDomain := "_dmarc." + domain
	records, err := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return "", nil
	}

	var dmarc string
	for _, r := range records {
		if strings.HasPrefix(r, "v=DMARC1") {
			dmarc = r
			break
		}
	}

	if dmarc == "" {
		return "", []finding.Finding{{
			CheckID:      finding.CheckEmailDMARCMissing,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityHigh,
			Title:        "Missing DMARC record",
			Description:  fmt.Sprintf("No DMARC record found at _dmarc.%s. Without DMARC, there is no policy for how mail receivers should handle unauthenticated email from this domain.", domain),
			Asset:        domain,
			Evidence:     map[string]any{"dmarc_domain": dmarcDomain},
			DiscoveredAt: time.Now(),
		}}
	}

	var findings []finding.Finding
	tags := parseDMARCTags(dmarc)

	// Check policy strength.
	// p=none with rua=/ruf= is "monitoring mode" — a legitimate transitional
	// state where the org is collecting data before enforcing. Still a risk
	// (spoofed mail delivers) but less urgent than blind p=none with no visibility.
	policy := tags["p"]
	_, hasRUAEarly := tags["rua"]
	_, hasRUFEarly := tags["ruf"]
	hasReporting := hasRUAEarly || hasRUFEarly
	if policy == "none" {
		sev := finding.SeverityHigh
		desc := "DMARC is configured but p=none means email that fails authentication is still delivered. Change to p=quarantine or p=reject to protect against spoofing."
		if hasReporting {
			sev = finding.SeverityMedium
			desc = "DMARC p=none with rua=/ruf= reporting is monitoring mode — a legitimate transitional state. " +
				"Spoofed mail still delivers, but the org can observe failures. Move to p=quarantine then p=reject."
		}
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckEmailDMARCPolicyNone,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        "DMARC policy set to 'none' — not enforced",
			Description:  desc,
			Asset:        domain,
			Evidence:     map[string]any{"dmarc_record": dmarc, "policy": policy, "has_reporting": hasReporting},
			DiscoveredAt: time.Now(),
		})
	}

	// Check subdomain policy.
	// RFC 7489 §6.3: when sp= is absent, subdomains inherit the p= policy.
	// Only flag when sp=none is explicit, OR when sp is absent AND p=none
	// (meaning subdomains inherit the unenforced root policy).
	sp, hasSP := tags["sp"]
	if sp == "none" || (!hasSP && policy == "none") {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckEmailDMARCSubdomainNone,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityMedium,
			Title:        "DMARC subdomain policy not enforced",
			Description:  "The DMARC sp= tag is missing or set to 'none', meaning subdomains inherit no protection and can be spoofed.",
			Asset:        domain,
			Evidence:     map[string]any{"dmarc_record": dmarc, "sp": sp},
			DiscoveredAt: time.Now(),
		})
	}

	// Check for reporting addresses (hasRUAEarly/hasRUFEarly already computed above)
	if !hasReporting {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckEmailDMARCNoReporting,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityLow,
			Title:        "DMARC has no reporting configured",
			Description:  "No rua= or ruf= addresses in the DMARC record. Without reporting, you cannot detect spoofing attempts or authentication failures.",
			Asset:        domain,
			Evidence:     map[string]any{"dmarc_record": dmarc},
			DiscoveredAt: time.Now(),
		})
	}

	return dmarc, findings
}

func checkDKIM(ctx context.Context, domain string) []finding.Finding {
	found := false
	var findings []finding.Finding

	for _, selector := range dkimSelectors {
		dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		records, err := net.DefaultResolver.LookupTXT(ctx, dkimDomain)
		if err != nil {
			continue
		}
		for _, r := range records {
			if strings.Contains(r, "v=DKIM1") || strings.Contains(r, "k=rsa") || strings.Contains(r, "p=") {
				found = true
				// Check key length (weak if < 2048 bits based on key size in base64)
				if keyLen := estimateDKIMKeyLength(r); keyLen > 0 && keyLen < 2048 {
					findings = append(findings, finding.Finding{
						CheckID:      finding.CheckEmailDKIMWeakKey,
						Module:       "surface",
						Scanner:      scannerName,
						Severity:     finding.SeverityMedium,
						Title:        fmt.Sprintf("DKIM key for selector '%s' is weak (%d bits)", selector, keyLen),
						Description:  fmt.Sprintf("The DKIM key at %s is %d bits, which is below the recommended 2048-bit minimum. Weak DKIM keys can be factored by well-resourced attackers.", dkimDomain, keyLen),
						Asset:        domain,
						Evidence:     map[string]any{"selector": selector, "dkim_domain": dkimDomain, "key_bits": keyLen},
						DiscoveredAt: time.Now(),
					})
				}
				break // stop scanning TXT records for this selector
			}
		}
		// Do not break the outer selector loop when found=true — continue checking
		// all selectors so we detect weak legacy keys even when a strong key exists.
	}

	if !found {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckEmailDKIMMissing,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityMedium,
			Title:        "No DKIM record found for common selectors",
			Description:  fmt.Sprintf("No DKIM record was found for %s using common selectors (%s). DKIM signs outgoing mail, allowing receivers to verify it hasn't been tampered with.", domain, strings.Join(dkimSelectors, ", ")),
			Asset:        domain,
			Evidence:     map[string]any{"selectors_checked": dkimSelectors},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

func checkMTASTS(ctx context.Context, domain string) []finding.Finding {
	// Check for MTA-STS DNS record
	mtastsDNS := "_mta-sts." + domain
	records, _ := net.DefaultResolver.LookupTXT(ctx, mtastsDNS)
	hasDNS := false
	for _, r := range records {
		if strings.HasPrefix(r, "v=STSv1") {
			hasDNS = true
			break
		}
	}

	if !hasDNS {
		return []finding.Finding{{
			CheckID:      finding.CheckEmailMTASTSMissing,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityLow,
			Title:        "MTA-STS not configured",
			Description:  fmt.Sprintf("No MTA-STS record found for %s. MTA-STS prevents downgrade attacks on SMTP connections.", domain),
			Asset:        domain,
			Evidence:     map[string]any{"dns_record": mtastsDNS},
			DiscoveredAt: time.Now(),
		}}
	}

	// Fetch the policy file. RFC 8461 §3.2: the policy MUST be served at
	// https://mta-sts.<domain>/.well-known/mta-sts.txt. If the DNS record
	// exists but the policy is unreachable, MTA-STS is broken and sending
	// servers may fail or fall back to unauthenticated delivery.
	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	client := &http.Client{Timeout: 10 * time.Second}
	policyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(policyReq)
	if err != nil || resp.StatusCode != 200 {
		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
			resp.Body.Close()
		}
		return []finding.Finding{{
			CheckID:      finding.CheckEmailMTASTSPolicyFetchFail,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityMedium,
			Title:        "MTA-STS DNS record present but policy file unreachable",
			Description:  fmt.Sprintf("_mta-sts.%s has a valid DNS record, but the policy at %s could not be fetched (status %d). Sending servers that enforce MTA-STS will fail delivery and MTA-STS provides no protection. Fix the policy endpoint or remove the DNS record.", domain, policyURL, statusCode),
			Asset:        domain,
			Evidence:     map[string]any{"policy_url": policyURL, "status_code": statusCode},
			DiscoveredAt: time.Now(),
		}}
	}
	defer resp.Body.Close()

	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if strings.Contains(body, "mode: testing") {
		return []finding.Finding{{
			CheckID:      finding.CheckEmailMTASTSNotEnforced,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityMedium,
			Title:        "MTA-STS policy is in testing mode — not enforced",
			Description:  "MTA-STS is deployed but set to mode: testing. Receiving servers will report policy violations but still accept unauthenticated connections. Change to mode: enforce.",
			Asset:        domain,
			Evidence:     map[string]any{"policy_url": policyURL, "mode": "testing"},
			DiscoveredAt: time.Now(),
		}}
	}

	return nil
}

func checkTLSRPT(ctx context.Context, domain string) []finding.Finding {
	tlsrptDomain := "_smtp._tls." + domain
	records, err := net.DefaultResolver.LookupTXT(ctx, tlsrptDomain)
	if err != nil || len(records) == 0 {
		return []finding.Finding{{
			CheckID:      finding.CheckEmailTLSRPTMissing,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityLow,
			Title:        "TLS-RPT not configured",
			Description:  fmt.Sprintf("No TLS-RPT record at _smtp._tls.%s. TLS reporting allows you to receive alerts when mail servers fail to establish encrypted connections.", domain),
			Asset:        domain,
			Evidence:     map[string]any{"dns_record": tlsrptDomain},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

func checkBIMI(ctx context.Context, domain string) []finding.Finding {
	bimiDomain := "default._bimi." + domain
	records, err := net.DefaultResolver.LookupTXT(ctx, bimiDomain)
	hasBIMI := false
	if err == nil {
		for _, r := range records {
			if strings.HasPrefix(r, "v=BIMI1") {
				hasBIMI = true
				break
			}
		}
	}
	if !hasBIMI {
		return []finding.Finding{{
			CheckID:      finding.CheckEmailBIMIMissing,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityInfo,
			Title:        "BIMI not configured",
			Description:  "No BIMI record found. BIMI displays your brand logo in supported email clients, improving brand trust and deliverability.",
			Asset:        domain,
			Evidence:     map[string]any{"dns_record": bimiDomain},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

func checkDANE(ctx context.Context, domain string) []finding.Finding {
	// Look up MX records first, then check TLSA for each MX.
	mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxRecords) == 0 {
		return nil
	}

	mx := strings.TrimSuffix(mxRecords[0].Host, ".")
	tlsaDomain := fmt.Sprintf("_25._tcp.%s", mx)

	// Go's net package cannot query arbitrary DNS record types (TLSA = type 52).
	// Use dig if available; skip the check entirely when it isn't — a missing
	// tool should not produce a false-positive finding.
	digPath, lookupErr := exec.LookPath("dig")
	if lookupErr != nil {
		return nil // dig unavailable — skip rather than false-positive
	}

	cmd := exec.CommandContext(ctx, digPath, "+short", "TLSA", tlsaDomain)
	out, runErr := cmd.Output()
	if runErr != nil {
		return nil // dig failed (NXDOMAIN, SERVFAIL, timeout) — skip
	}

	if strings.TrimSpace(string(out)) != "" {
		return nil // TLSA record exists — DANE is configured
	}

	return []finding.Finding{{
		CheckID:      finding.CheckEmailDANEMissing,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityLow,
		Title:        "DANE/TLSA not configured for mail server",
		Description:  fmt.Sprintf("No TLSA record found at %s. DANE provides an additional layer of authentication for SMTP connections using DNSSEC.", tlsaDomain),
		Asset:        domain,
		Evidence:     map[string]any{"mx": mx, "tlsa_domain": tlsaDomain},
		DiscoveredAt: time.Now(),
	}}
}

// parseDMARCTags parses a DMARC TXT record into a tag=value map.
func parseDMARCTags(record string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return tags
}

// checkSPFIncludes recursively expands SPF include: and redirect= directives to reveal
// all third-party services authorized to send email on behalf of the domain.
// Emits a single INFO finding listing the expanded sender set (useful context for phishing risk).
func checkSPFIncludes(ctx context.Context, domain, spfRecord string) []finding.Finding {
	if spfRecord == "" {
		return nil
	}
	services := expandSPFIncludes(ctx, spfRecord, 0, map[string]bool{})
	if len(services) == 0 {
		return nil
	}
	return []finding.Finding{{
		CheckID:      finding.CheckEmailSPFIncludes,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityInfo,
		Title:        fmt.Sprintf("SPF record authorizes %d third-party mail sender(s)", len(services)),
		Description:  fmt.Sprintf("The SPF record for %s delegates sending authority to: %s. Review these services to ensure all are current and authorized.", domain, strings.Join(services, ", ")),
		Asset:        domain,
		Evidence:     map[string]any{"spf_record": spfRecord, "authorized_senders": services},
		DiscoveredAt: time.Now(),
	}}
}

// expandSPFIncludes recursively follows include: and redirect= directives in an SPF record,
// returning the deduplicated list of included domain names (not the full records).
// maxDepth prevents infinite loops on circular SPF chains (RFC 7208 §4.6.4 bans these, but
// misconfigured records exist in the wild).
func expandSPFIncludes(ctx context.Context, spf string, depth int, seen map[string]bool) []string {
	if depth > 5 {
		return nil
	}
	var services []string
	for _, part := range strings.Fields(spf) {
		part = strings.TrimLeft(part, "+-~?")
		var target string
		switch {
		case strings.HasPrefix(part, "include:"):
			target = strings.TrimPrefix(part, "include:")
		case strings.HasPrefix(part, "redirect="):
			target = strings.TrimPrefix(part, "redirect=")
		}
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		services = append(services, target)
		// Recurse into the included domain's SPF record.
		records, err := net.DefaultResolver.LookupTXT(ctx, target)
		if err != nil {
			continue
		}
		for _, r := range records {
			if strings.HasPrefix(r, "v=spf1") {
				services = append(services, expandSPFIncludes(ctx, r, depth+1, seen)...)
				break
			}
		}
	}
	return services
}

// countSPFLookups counts the number of DNS-lookup-inducing mechanisms in an SPF record.
// RFC 7208 §4.6.4: include, a, mx, ptr, exists, and redirect each count as one lookup.
// "a" and "mx" are standalone mechanisms: they may be followed by ':', '/', or end-of-token.
// HasPrefix("a") would falsely match "all", "aws", etc., so we check for exact or bounded match.
func countSPFLookups(spf string) int {
	count := 0
	for _, part := range strings.Fields(spf) {
		trimmed := strings.TrimLeft(part, "+-~?")
		switch {
		case strings.HasPrefix(trimmed, "include:"),
			strings.HasPrefix(trimmed, "exists:"),
			strings.HasPrefix(trimmed, "redirect="),
			strings.HasPrefix(trimmed, "ptr:"),
			trimmed == "ptr":
			count++
		case trimmed == "a", strings.HasPrefix(trimmed, "a:"), strings.HasPrefix(trimmed, "a/"):
			count++
		case trimmed == "mx", strings.HasPrefix(trimmed, "mx:"), strings.HasPrefix(trimmed, "mx/"):
			count++
		}
	}
	return count
}

// estimateDKIMKeyLength returns the RSA key size in bits from a DKIM TXT record.
// It parses the base64-encoded SubjectPublicKeyInfo (SPKI) DER value in the p=
// tag using the standard crypto/x509 library. Returns 0 if the key is absent,
// revoked (p= is empty), or not RSA.
func estimateDKIMKeyLength(record string) int {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "p=") {
			continue
		}
		b64 := strings.TrimPrefix(part, "p=")
		b64 = strings.ReplaceAll(b64, " ", "")
		if b64 == "" {
			return 0 // empty p= means the key has been revoked
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return 0
		}
		// Try SPKI (SubjectPublicKeyInfo) format first — the RFC 6376 standard.
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			// Many real-world DKIM records encode the raw RSA public key in
			// PKCS#1 format (no algorithm OID wrapper) instead of SPKI.
			// ParsePKIXPublicKey rejects these; try PKCS#1 as a fallback.
			rsaKey, pkcs1Err := x509.ParsePKCS1PublicKey(der)
			if pkcs1Err != nil {
				return 0
			}
			return rsaKey.N.BitLen()
		}
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return 0 // not RSA (e.g. Ed25519) — skip size check
		}
		return rsaKey.N.BitLen()
	}
	return 0
}

// checkSMTP connects to the domain's MX server, reads the banner, and issues
// EHLO to observe the server's response. No mail is sent — this is equivalent
// to what any mail client does when it first connects to a mail server.
func checkSMTP(ctx context.Context, domain string, now time.Time, scanType module.ScanType) []finding.Finding {
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return nil
	}

	mx := strings.TrimSuffix(mxs[0].Host, ".")
	addr := mx + ":25"

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	scanner := bufio.NewScanner(conn)

	// Read greeting banner
	if !scanner.Scan() {
		return nil
	}
	banner := scanner.Text()

	var findings []finding.Finding

	// Banner info leak: server software/version visible
	if leaksSoftware(banner) {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckEmailSMTPBannerLeak,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityLow,
			Title:        "SMTP banner reveals mail server software",
			Description:  fmt.Sprintf("The mail server for %s reveals its software and version in the SMTP greeting: %q. This helps attackers target known vulnerabilities in that specific version.", domain, banner),
			Asset:        domain,
			Evidence:     map[string]any{"mx": mx, "banner": banner},
			DiscoveredAt: now,
		})
	}

	// Send EHLO — standard handshake, every client does this
	if _, err := fmt.Fprintf(conn, "EHLO beacon-scanner.local\r\n"); err != nil {
		return findings
	}
	for scanner.Scan() {
		line := scanner.Text()
		// Consume EHLO response (multi-line 250-)
		if !strings.HasPrefix(line, "250-") && !strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Open relay test: deep mode only — sending MAIL FROM is an active probe
	// that appears in server logs and may trigger rate limiting on the target.
	if scanType != module.ScanDeep {
		fmt.Fprintf(conn, "QUIT\r\n") //nolint:errcheck — best-effort cleanup
		return findings
	}

	// We only send the MAIL FROM command and observe the response —
	// we never complete the DATA phase, so no mail is ever delivered.
	if _, err := fmt.Fprintf(conn, "MAIL FROM:<probe@beacon-scanner-check.invalid>\r\n"); err != nil {
		return findings
	}
	if !scanner.Scan() {
		return findings
	}
	mailFromResp := scanner.Text()

	// If MAIL FROM was accepted (250), try RCPT TO with an external address.
	// An open relay accepts both without authentication.
	if strings.HasPrefix(mailFromResp, "250") {
		if _, err := fmt.Fprintf(conn, "RCPT TO:<probe@openrelay-check.invalid>\r\n"); err != nil {
			return findings
		}
		if scanner.Scan() {
			rcptResp := scanner.Text()
			if strings.HasPrefix(rcptResp, "250") {
				findings = append(findings, finding.Finding{
					CheckID:      finding.CheckEmailSMTPOpenRelay,
					Module:       "surface",
					Scanner:      scannerName,
					Severity:     finding.SeverityCritical,
					Title:        "SMTP open relay — server accepts mail for external domains",
					Description:  fmt.Sprintf("The mail server %s accepted a relay attempt: it accepted MAIL FROM and RCPT TO for domains it does not own. This means anyone can send spam or phishing email through your mail infrastructure, leading to blacklisting and reputational damage.", mx),
					Asset:        domain,
					Evidence:     map[string]any{"mx": mx, "mail_from_response": mailFromResp, "rcpt_to_response": rcptResp},
					DiscoveredAt: now,
				})
			}
		}
	}

	// Always issue QUIT cleanly — best-effort, ignore write error
	fmt.Fprintf(conn, "QUIT\r\n") //nolint:errcheck
	return findings
}

// leaksSoftware returns true if the SMTP banner contains recognisable software names/versions.
func leaksSoftware(banner string) bool {
	lower := strings.ToLower(banner)
	for _, keyword := range []string{"postfix", "sendmail", "exim", "microsoft esmtp", "exchange", "zimbra", "qmail", "courier"} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}
