// Package tls performs native Go TLS/certificate security checks without
// requiring any external binary. It covers certificate properties, protocol
// negotiation, forward secrecy, HSTS policy, and OCSP revocation.
//
// Complements the nuclei surface templates (which check expiry, self-signed,
// hostname mismatch) and the testssl.sh wrapper (which probes deprecated
// protocol versions and cipher exploit vulnerabilities in deep mode).
//
// All checks run in surface mode (passive TLS handshake observation).
// OCSP revocation fetch is the only outbound call beyond the normal TLS
// handshake — it contacts the OCSP responder URL from the certificate's AIA
// extension, which is the standard browser behavior.
package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "tls"

// oidSCT is the OID for the Certificate Transparency signed certificate
// timestamp (SCT) extension: 1.3.6.1.4.1.11129.2.4.2
var oidSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// pfsKeyExchanges are TLS cipher suite names that provide forward secrecy via
// ephemeral Diffie-Hellman or ECDH key exchange.
var pfsKeyExchanges = []string{"ECDHE", "DHE", "TLS_AES", "TLS_CHACHA20", "TLS_ECDHE"}

// weakSigAlgs maps x509.SignatureAlgorithm values that are considered
// cryptographically weak to a human-readable name.
var weakSigAlgs = map[x509.SignatureAlgorithm]string{
	x509.MD5WithRSA:    "MD5WithRSA",
	x509.SHA1WithRSA:   "SHA1WithRSA",
	x509.ECDSAWithSHA1: "ECDSAWithSHA1",
	x509.DSAWithSHA1:   "DSAWithSHA1",
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	host, port := splitHostPort(asset)

	// ── Phase 1: TLS handshake — collect cert chain + negotiated parameters ──
	conn, state, chain, err := tlsHandshake(ctx, host, port, &tls.Config{
		InsecureSkipVerify: true, // we check everything ourselves
		ServerName:         host,
	})
	if err != nil {
		return nil, nil // host not reachable over TLS — skip silently
	}
	conn.Close()

	if len(chain) == 0 {
		return nil, nil
	}
	leaf := chain[0]

	var findings []finding.Finding
	now := time.Now()

	// ── Certificate checks ────────────────────────────────────────────────────

	// Weak public key
	if f := checkWeakKey(leaf, asset, now); f != nil {
		findings = append(findings, *f)
	}

	// Weak signature algorithm
	if name, weak := weakSigAlgs[leaf.SignatureAlgorithm]; weak {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSCertWeakSignature,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("Certificate signed with weak algorithm: %s", name),
			Description: fmt.Sprintf(
				"The TLS certificate for %s uses %s, which is cryptographically broken. "+
					"Browsers and modern TLS clients reject these signatures. "+
					"Replace the certificate with one using SHA-256 or SHA-384.",
				asset, name),
			Evidence:     map[string]any{"sig_algorithm": name, "subject": leaf.Subject.CommonName},
			ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -text | grep 'Signature Algorithm'", asset),
			DiscoveredAt: now,
		})
	}

	// SAN missing (CN-only cert)
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSCertSANMissing,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    asset,
			Title:    "Certificate has no Subject Alternative Names (SAN)",
			Description: fmt.Sprintf(
				"The certificate for %s identifies the host only via the deprecated CN field. "+
					"RFC 2818 requires SANs; all modern browsers ignore CN for hostname validation. "+
					"Reissue the certificate with explicit DNS SANs.",
				asset),
			Evidence:     map[string]any{"subject_cn": leaf.Subject.CommonName},
			ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -text | grep -A5 'Subject Alternative'", asset),
			DiscoveredAt: now,
		})
	}

	// Wildcard cert (informational)
	for _, san := range leaf.DNSNames {
		if strings.HasPrefix(san, "*.") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckTLSCertWildcard,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityInfo,
				Asset:    asset,
				Title:    fmt.Sprintf("Wildcard TLS certificate in use: %s", san),
				Description: fmt.Sprintf(
					"A wildcard certificate (%s) covers all immediate subdomains of the domain. "+
						"If the private key is compromised, all subdomains are affected simultaneously. "+
						"Consider per-service certificates for high-value services.",
					san),
				Evidence:     map[string]any{"wildcard_san": san, "subject": leaf.Subject.CommonName},
				ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName", asset),
				DiscoveredAt: now,
			})
			break
		}
	}

	// Certificate validity period > 398 days (CA/B Forum Ballot SC-31, 2020)
	validDays := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
	if validDays > 398 && leaf.NotBefore.After(time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSCertLongValidity,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    asset,
			Title:    fmt.Sprintf("Certificate validity period too long: %d days", validDays),
			Description: fmt.Sprintf(
				"The TLS certificate for %s is valid for %d days. "+
					"Since September 2020, the CA/Browser Forum limits public TLS certificates to 398 days. "+
					"Long-lived certificates delay revocation of compromised keys and are rejected by Apple Safari.",
				asset, validDays),
			Evidence:     map[string]any{"validity_days": validDays, "not_before": leaf.NotBefore.Format(time.RFC3339), "not_after": leaf.NotAfter.Format(time.RFC3339)},
			ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -dates", asset),
			DiscoveredAt: now,
		})
	}

	// No OCSP URL in AIA extension
	if len(leaf.OCSPServer) == 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSCertNoOCSP,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    asset,
			Title:    "Certificate has no OCSP responder URL",
			Description: fmt.Sprintf(
				"The TLS certificate for %s has no OCSP (Online Certificate Status Protocol) URL in its "+
					"Authority Information Access extension. Clients cannot check if this certificate has been revoked. "+
					"This is common with private PKI; for public-facing services, issue a certificate from a CA that provides OCSP.",
				asset),
			Evidence:     map[string]any{"subject": leaf.Subject.CommonName, "issuer": leaf.Issuer.CommonName},
			ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -text | grep -A2 'Authority Information'", asset),
			DiscoveredAt: now,
		})
	} else {
		// OCSP URL present — check revocation status
		if f := checkOCSPRevocation(ctx, leaf, chain, asset, now); f != nil {
			findings = append(findings, *f)
		}
	}

	// No CRL distribution point
	if len(leaf.CRLDistributionPoints) == 0 && len(leaf.OCSPServer) == 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSCRLNoURL,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    "Certificate has no revocation mechanism (no OCSP or CRL)",
			Description: fmt.Sprintf(
				"The TLS certificate for %s has neither an OCSP responder URL nor a CRL distribution point. "+
					"There is no standard mechanism for clients to check if this certificate has been revoked.",
				asset),
			Evidence:     map[string]any{"subject": leaf.Subject.CommonName},
			DiscoveredAt: now,
		})
	}

	// No Signed Certificate Timestamp (Certificate Transparency)
	if !hasSCT(leaf) {
		// Only flag for certs issued after CT became mandatory (April 2018)
		if leaf.NotBefore.After(time.Date(2018, 4, 30, 0, 0, 0, 0, time.UTC)) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckTLSCertNoSCT,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Asset:    asset,
				Title:    "Certificate lacks Signed Certificate Timestamps (CT log proof)",
				Description: fmt.Sprintf(
					"The TLS certificate for %s has no Signed Certificate Timestamps (SCTs) in its "+
						"extensions. Chrome has required CT since April 2018; certificates without SCTs are "+
						"untrusted in Chrome and Safari. The certificate may have been issued outside "+
						"normal CA channels or may be a mis-issued certificate.",
					asset),
				Evidence:     map[string]any{"subject": leaf.Subject.CommonName, "issuer": leaf.Issuer.CommonName, "not_before": leaf.NotBefore.Format(time.RFC3339)},
				ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -text | grep -A3 'CT Precertificate'", asset),
				DiscoveredAt: now,
			})
		}
	}

	// ── TLS handshake property checks ─────────────────────────────────────────

	// No Perfect Forward Secrecy
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	hasPFS := false
	for _, kex := range pfsKeyExchanges {
		if strings.Contains(cipherName, kex) {
			hasPFS = true
			break
		}
	}
	// TLS 1.3 always has PFS
	if state.Version == tls.VersionTLS13 {
		hasPFS = true
	}
	if !hasPFS {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSNoPFS,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("No Perfect Forward Secrecy: cipher %s", cipherName),
			Description: fmt.Sprintf(
				"%s negotiated cipher suite %s which does not provide Perfect Forward Secrecy (PFS). "+
					"Without PFS, a future compromise of the server's private key allows decryption of all "+
					"previously recorded TLS sessions. Configure the server to prefer ECDHE or DHE cipher suites. "+
					"For nginx: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:...'; ssl_prefer_server_ciphers on;",
				asset, cipherName),
			Evidence:     map[string]any{"cipher_suite": cipherName, "tls_version": tlsVersionName(state.Version)},
			ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | grep 'Cipher is'", asset),
			DiscoveredAt: now,
		})
	}

	// TLS 1.3 not supported — probe with MinVersion=TLS13
	if state.Version < tls.VersionTLS13 {
		if !supportsTLS13(ctx, host, port) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckTLSNoTLS13,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Asset:    asset,
				Title:    "TLS 1.3 not supported",
				Description: fmt.Sprintf(
					"%s does not support TLS 1.3 (the server negotiated %s). "+
						"TLS 1.3 removes legacy crypto, reduces handshake latency by one round-trip, "+
						"and is now supported by all major TLS libraries. "+
						"Update your TLS library and enable TLS 1.3 in your server configuration.",
					asset, tlsVersionName(state.Version)),
				Evidence:     map[string]any{"negotiated_version": tlsVersionName(state.Version)},
				ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 -tls1_3 2>&1 | head -5", asset),
				DiscoveredAt: now,
			})
		}
	}


	// ── Deprecated protocol version checks ───────────────────────────────────
	// Attempt connections with TLS 1.0 and TLS 1.1 as the maximum version.
	// If the server accepts these deprecated protocols, emit a finding.
	if f := checkDeprecatedProtocol(ctx, host, port, asset, tls.VersionTLS10, "TLS 1.0", finding.CheckTLSProtocolTLS10, finding.SeverityHigh, now); f != nil {
		findings = append(findings, *f)
	}
	if f := checkDeprecatedProtocol(ctx, host, port, asset, tls.VersionTLS11, "TLS 1.1", finding.CheckTLSProtocolTLS11, finding.SeverityMedium, now); f != nil {
		findings = append(findings, *f)
	}

	// ── HSTS header checks ────────────────────────────────────────────────────
	hstsFindings := checkHSTS(ctx, asset, now)
	findings = append(findings, hstsFindings...)

	return findings, nil
}

// ── Certificate property helpers ──────────────────────────────────────────────

func checkWeakKey(cert *x509.Certificate, asset string, now time.Time) *finding.Finding {
	var keyDesc string
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits >= 2048 {
			return nil
		}
		keyDesc = fmt.Sprintf("RSA-%d", bits)
	case *ecdsa.PublicKey:
		bits := k.Curve.Params().BitSize
		if bits >= 224 {
			return nil
		}
		keyDesc = fmt.Sprintf("EC-%d", bits)
	default:
		return nil
	}
	f := finding.Finding{
		CheckID:  finding.CheckTLSCertWeakKey,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("Certificate uses weak public key: %s", keyDesc),
		Description: fmt.Sprintf(
			"The TLS certificate for %s uses a %s key, which does not meet current minimum standards. "+
				"NIST SP 800-131A and CA/Browser Forum require RSA keys of at least 2048 bits (RSA-2048) "+
				"or EC keys of at least 224 bits. Reissue the certificate with a stronger key.",
			asset, keyDesc),
		Evidence:     map[string]any{"key_type": keyDesc, "subject": cert.Subject.CommonName},
		ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -text | grep 'Public-Key'", asset),
		DiscoveredAt: now,
	}
	return &f
}

func checkOCSPRevocation(ctx context.Context, leaf *x509.Certificate, chain []*x509.Certificate, asset string, now time.Time) *finding.Finding {
	if len(leaf.OCSPServer) == 0 || len(chain) < 2 {
		return nil
	}
	issuer := chain[1]

	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return nil
	}

	ocspCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	httpClient := &http.Client{Timeout: 8 * time.Second}
	httpReq, err := http.NewRequestWithContext(ocspCtx, http.MethodPost, leaf.OCSPServer[0],
		bytes.NewReader(req))
	if err != nil {
		return nil
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return nil
	}

	if ocspResp.Status != ocsp.Revoked {
		return nil
	}

	reason := "unspecified"
	if ocspResp.RevocationReason >= 0 {
		reason = ocspRevocationReason(ocspResp.RevocationReason)
	}

	f := finding.Finding{
		CheckID:  finding.CheckTLSCertRevoked,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    "TLS certificate has been revoked",
		Description: fmt.Sprintf(
			"The TLS certificate for %s (CN: %s, serial: %s) has been revoked by its issuer (%s). "+
				"Revocation reason: %s. Revoked at: %s. "+
				"Visitors using this certificate see security errors. Replace it immediately.",
			asset, leaf.Subject.CommonName,
			leaf.SerialNumber.String(), leaf.Issuer.CommonName,
			reason, ocspResp.RevokedAt.Format(time.RFC3339)),
		Evidence: map[string]any{
			"subject":           leaf.Subject.CommonName,
			"issuer":            leaf.Issuer.CommonName,
			"serial":            leaf.SerialNumber.String(),
			"revocation_reason": reason,
			"revoked_at":        ocspResp.RevokedAt.Format(time.RFC3339),
			"ocsp_url":          leaf.OCSPServer[0],
		},
		ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 2>/dev/null | openssl x509 -noout -serial -issuer && openssl ocsp -issuer <(openssl s_client -connect %s:443 2>/dev/null | openssl x509) -cert <(openssl s_client -connect %s:443 2>/dev/null | openssl x509) -url %s", asset, asset, asset, leaf.OCSPServer[0]),
		DiscoveredAt: now,
	}
	return &f
}

func hasSCT(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSCT) {
			return len(ext.Value) > 0
		}
	}
	return false
}

// ── HSTS header checks ────────────────────────────────────────────────────────

// checkHSTS fetches the HTTPS root path and delegates header parsing to
// parseHSTSFindings. Returns nil if the server is unreachable or has no HSTS.
func checkHSTS(ctx context.Context, asset string, now time.Time) []finding.Finding {
	httpClient := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		return nil // missing HSTS is already checked by nuclei; don't duplicate
	}

	return parseHSTSFindings(hsts, asset, now)
}

// parseHSTSFindings parses the Strict-Transport-Security header value and
// returns findings for any policy weaknesses. It is extracted from checkHSTS
// so that tests can call it directly without making HTTP requests.
func parseHSTSFindings(hsts, asset string, now time.Time) []finding.Finding {
	var findings []finding.Finding

	// Parse max-age
	maxAge := 0
	for _, part := range strings.Split(hsts, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "max-age=") {
			v := strings.TrimPrefix(part, "max-age=")
			if n, err := strconv.Atoi(v); err == nil {
				maxAge = n
			}
		}
	}

	// max-age < 1 year (31536000 seconds) — OWASP, Google, and the HSTS preload
	// list all require at least 1 year. Anything shorter risks SSL-strip attacks
	// when browser caches expire or users switch devices.
	if maxAge > 0 && maxAge < 31536000 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSHSTSShortMaxAge,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    asset,
			Title:    fmt.Sprintf("HSTS max-age too short: %d seconds (%d days)", maxAge, maxAge/86400),
			Description: fmt.Sprintf(
				"%s sets HSTS with max-age=%d (%d days). OWASP and the HSTS preload list require "+
					"at least 31536000 seconds (1 year). Short max-age allows SSL-strip attacks shortly "+
					"after a browser cache clears. Set max-age=31536000 (1 year) or higher.",
				asset, maxAge, maxAge/86400),
			Evidence:     map[string]any{"hsts_header": hsts, "max_age_seconds": maxAge},
			ProofCommand: fmt.Sprintf("curl -si https://%s/ | grep -i strict-transport", asset),
			DiscoveredAt: now,
		})
	}

	// Missing includeSubDomains
	if !strings.Contains(strings.ToLower(hsts), "includesubdomains") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSHSTSNoSubdomains,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    asset,
			Title:    "HSTS policy does not include subdomains",
			Description: fmt.Sprintf(
				"%s sets HSTS but without the includeSubDomains directive. "+
					"Subdomains are not covered by the HTTPS-only policy, allowing attackers to "+
					"use a subdomain (e.g. via cookie injection from a non-HTTPS subdomain) to "+
					"downgrade the main domain. Add includeSubDomains to the HSTS header.",
				asset),
			Evidence:     map[string]any{"hsts_header": hsts},
			ProofCommand: fmt.Sprintf("curl -si https://%s/ | grep -i strict-transport", asset),
			DiscoveredAt: now,
		})
	}

	// Missing preload
	if !strings.Contains(strings.ToLower(hsts), "preload") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckTLSHSTSNoPreload,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    "HSTS policy not configured for browser preload list",
			Description: fmt.Sprintf(
				"%s sets HSTS but without the preload directive. Without preload, a first-time "+
					"visitor can still reach the site over HTTP before the HSTS policy is cached. "+
					"Add preload to the header and submit the domain at hstspreload.org to protect "+
					"first-visit connections.",
				asset),
			Evidence:     map[string]any{"hsts_header": hsts},
			ProofCommand: fmt.Sprintf("curl -si https://%s/ | grep -i strict-transport", asset),
			DiscoveredAt: now,
		})
	}

	return findings
}

// ── TLS connection helpers ────────────────────────────────────────────────────

func tlsHandshake(ctx context.Context, host, port string, cfg *tls.Config) (*tls.Conn, tls.ConnectionState, []*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	netConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, tls.ConnectionState{}, nil, err
	}

	tlsConn := tls.Client(netConn, cfg)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		netConn.Close()
		return nil, tls.ConnectionState{}, nil, err
	}

	state := tlsConn.ConnectionState()
	return tlsConn, state, state.PeerCertificates, nil
}

// checkDeprecatedProtocol attempts a TLS handshake with the given version as
// both MinVersion and MaxVersion. If the server accepts the connection, it
// returns a finding indicating the deprecated protocol is still enabled.
func checkDeprecatedProtocol(ctx context.Context, host, port, asset string, version uint16, versionName string, checkID finding.CheckID, sev finding.Severity, now time.Time) *finding.Finding {
	conn, _, _, err := tlsHandshake(ctx, host, port, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err != nil {
		return nil // server rejected — not vulnerable
	}
	conn.Close()

	return &finding.Finding{
		CheckID:  checkID,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: sev,
		Asset:    asset,
		Title:    fmt.Sprintf("Server accepts deprecated %s connections", versionName),
		Description: fmt.Sprintf(
			"%s accepted a %s connection. %s is deprecated by RFC 8996 (March 2021) and "+
				"contains known vulnerabilities (BEAST, POODLE, Lucky13). All major browsers "+
				"have disabled %s support. Disable %s on the server and require TLS 1.2 or higher. "+
				"For nginx: ssl_protocols TLSv1.2 TLSv1.3; "+
				"For Apache: SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1;",
			asset, versionName, versionName, versionName, versionName),
		Evidence: map[string]any{
			"accepted_version": versionName,
		},
		ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:%s -%s 2>&1 | head -5",
			host, port, strings.ReplaceAll(strings.ToLower(versionName), " ", "")),
		DiscoveredAt: now,
	}
}

// supportsTLS13 returns true if host:port accepts a TLS 1.3-only connection.
func supportsTLS13(ctx context.Context, host, port string) bool {
	conn, _, _, err := tlsHandshake(ctx, host, port, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ── Utility functions ─────────────────────────────────────────────────────────

func splitHostPort(asset string) (string, string) {
	if strings.Contains(asset, ":") {
		h, p, err := net.SplitHostPort(asset)
		if err == nil {
			return h, p
		}
	}
	return asset, "443"
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func ocspRevocationReason(reason int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "key_compromise",
		2:  "ca_compromise",
		3:  "affiliation_changed",
		4:  "superseded",
		5:  "cessation_of_operation",
		6:  "certificate_hold",
		8:  "remove_from_crl",
		9:  "privilege_withdrawn",
		10: "aa_compromise",
	}
	if r, ok := reasons[reason]; ok {
		return r
	}
	return fmt.Sprintf("reason_%d", reason)
}
