package surface

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// AssetConfidence is a five-level scale used to describe how confident we are
// that a discovered IP or hostname belongs to the scan's root domain.
type AssetConfidence int

const (
	// AssetRuledOut means positive contrary evidence shows this asset belongs
	// to a different organisation.  We still surface-scan it (passive observation
	// is always legal), but the TUI marks it clearly and deep scan requires an
	// explicit double confirmation.
	AssetRuledOut AssetConfidence = iota

	// AssetUnlikely means signals lean against ownership — e.g. cert has only
	// unrelated SANs — but we lack enough evidence to rule it out completely.
	AssetUnlikely

	// AssetUnconfirmed means there is neither positive nor negative evidence.
	// No PTR, cert doesn't contain rootDomain, Host probe not tried yet.
	AssetUnconfirmed

	// AssetLikely means at least one weak signal points to ownership (e.g. same
	// ASN as rootDomain, or PTR suffix matches but not conclusively).
	AssetLikely

	// AssetConfirmed means at least one strong signal confirms ownership:
	// PTR is a subdomain of rootDomain, TLS cert SANs include rootDomain, or
	// the HTTP Host-bound probe returned 2xx.
	AssetConfirmed
)

func (c AssetConfidence) String() string {
	switch c {
	case AssetRuledOut:
		return "ruled_out"
	case AssetUnlikely:
		return "unlikely"
	case AssetUnconfirmed:
		return "unconfirmed"
	case AssetLikely:
		return "likely"
	case AssetConfirmed:
		return "confirmed"
	}
	return "unknown"
}

// OwnershipResult is the output of checkAssetOwnership.  It holds both the
// confidence level and structured signals that feed directly into fingerprinting,
// so that the confirmation check doubles as a lightweight pre-classify pass.
type OwnershipResult struct {
	Confidence AssetConfidence

	// Human-readable evidence strings shown in the Discovered Assets TUI panel.
	Evidence []string

	// Fingerprint signals — feed these into playbook.Evidence when the asset
	// is later classified so the classify scanner has a head start.
	PTRNames     []string // reverse-DNS names for the IP
	TLSSANs      []string // certificate Subject Alternative Names
	TLSIssuer    string   // certificate issuer organisation
	TLSCertHash  string   // SHA-256 fingerprint of the leaf cert (hex)
	ServerHeader string   // HTTP Server: header from Host-bound probe
	HTTPStatus   int      // status code from Host-bound probe (0 = no probe)
	CloudProvider string  // inferred from PTR (aws/gcp/azure/hetzner/etc.)
	// OtherDomains lists SANs from the cert that are NOT rootDomain subdomains.
	// Useful to detect shared-hosting situations.
	OtherDomains []string
}

// checkAssetOwnership runs passive, unsolicited ownership verification on ip.
// All checks are legally and ethically equivalent to what any internet user
// can observe: reverse-DNS queries, public TLS certificate inspection, and a
// single HTTP HEAD request.  No credentials, no exploit payloads.
//
// The returned OwnershipResult feeds both the TUI's Discovered Assets panel
// (via Evidence strings) and the asset's fingerprint (via signal fields).
func checkAssetOwnership(ctx context.Context, ip, rootDomain string) OwnershipResult {
	bare := strings.SplitN(ip, ":", 2)[0] // strip port if present
	res := OwnershipResult{Confidence: AssetUnconfirmed}

	// ── 1. Reverse-DNS (PTR) ──────────────────────────────────────────────
	// PTR records that end in rootDomain are strong confirmation.
	// PTR records for known cloud providers tell us the hosting platform even
	// when they don't confirm the domain.
	rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
	names, err := net.DefaultResolver.LookupAddr(rctx, bare)
	rcancel()

	if err == nil && len(names) > 0 {
		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			res.PTRNames = append(res.PTRNames, name)
			res.Evidence = append(res.Evidence, fmt.Sprintf("PTR: %s", name))

			nameLower := strings.ToLower(name)
			// Strong: PTR is the root domain or a subdomain.
			if name == rootDomain || strings.HasSuffix(nameLower, "."+strings.ToLower(rootDomain)) {
				res.Confidence = AssetConfirmed
			}
			// Cloud provider fingerprinting from PTR.
			switch {
			case strings.Contains(nameLower, ".compute.amazonaws.com") ||
				strings.Contains(nameLower, ".ec2.internal") ||
				strings.Contains(nameLower, ".awsglobalaccelerator.com"):
				res.CloudProvider = "aws"
			case strings.Contains(nameLower, ".googleusercontent.com") ||
				strings.Contains(nameLower, ".googleapis.com") ||
				strings.Contains(nameLower, ".1e100.net"):
				res.CloudProvider = "gcp"
			case strings.Contains(nameLower, ".azure.com") ||
				strings.Contains(nameLower, ".cloudapp.net") ||
				strings.Contains(nameLower, ".windows.net"):
				res.CloudProvider = "azure"
			case strings.Contains(nameLower, ".hetzner.de") ||
				strings.Contains(nameLower, ".hetzner.com"):
				res.CloudProvider = "hetzner"
			case strings.Contains(nameLower, ".digitalocean.com") ||
				strings.Contains(nameLower, ".vultr.com") ||
				strings.Contains(nameLower, ".linode.com"):
				res.CloudProvider = strings.Split(nameLower, ".")[len(strings.Split(nameLower, "."))-2]
			}
		}
	} else {
		res.Evidence = append(res.Evidence, "PTR: none (no reverse-DNS record)")
	}

	// ── 2. TLS certificate inspection ─────────────────────────────────────
	// The certificate SANs are the most reliable confirmation signal for
	// virtual-hosted IPs.  We skip chain verification because we are only
	// reading the SANs and fingerprint — not trusting the cert for auth.
	dialCtx, dialCancel := context.WithTimeout(ctx, 4*time.Second)
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // reading SANs only
			ServerName:         rootDomain,
		},
	}
	addr443 := net.JoinHostPort(bare, "443")
	conn, err := tlsDialer.DialContext(dialCtx, "tcp", addr443)
	dialCancel()

	if err == nil {
		tlsConn := conn.(*tls.Conn)
		certs := tlsConn.ConnectionState().PeerCertificates
		conn.Close()

		if len(certs) > 0 {
			leaf := certs[0]
			res.TLSIssuer = leaf.Issuer.Organization[0]
			if len(leaf.Issuer.Organization) == 0 {
				res.TLSIssuer = leaf.Issuer.CommonName
			}

			for _, san := range leaf.DNSNames {
				res.TLSSANs = append(res.TLSSANs, san)
				stripped := strings.TrimPrefix(strings.ToLower(san), "*.")
				rootLower := strings.ToLower(rootDomain)
				if stripped == rootLower || strings.HasSuffix(stripped, "."+rootLower) {
					res.Evidence = append(res.Evidence, fmt.Sprintf("TLS SAN: %s (matches target domain)", san))
					if res.Confidence < AssetConfirmed {
						res.Confidence = AssetConfirmed
					}
				} else {
					res.OtherDomains = append(res.OtherDomains, san)
				}
			}
			// IP SANs: explicit IP address in cert is strong confirmation.
			for _, ipSAN := range leaf.IPAddresses {
				if ipSAN.String() == bare {
					res.Evidence = append(res.Evidence, fmt.Sprintf("TLS IP SAN: %s (IP listed in cert)", bare))
					res.Confidence = AssetConfirmed
				}
			}
			// If we got SANs but none matched and some are clearly other orgs → Unlikely.
			if res.Confidence < AssetConfirmed && len(res.OtherDomains) > 0 {
				res.Evidence = append(res.Evidence, fmt.Sprintf("TLS cert: %d SANs, none match target (e.g. %s)", len(res.OtherDomains), res.OtherDomains[0]))
				if res.Confidence == AssetUnconfirmed {
					res.Confidence = AssetUnlikely
				}
			}
		}
	}

	// ── 3. HTTP Host-bound probe ───────────────────────────────────────────
	// A virtual-hosted origin server that recognises rootDomain will return
	// 2xx or 3xx when sent Host: rootDomain.  A 421 (Misdirected Request) or
	// consistent 4xx specifically means the server explicitly rejects it.
	// We use HEAD to minimise data transfer.
	if res.Confidence < AssetConfirmed {
		probeURL := "https://" + bare + "/"
		if port := strings.SplitN(ip, ":", 2); len(port) == 2 {
			probeURL = "https://" + ip + "/"
		}
		hc := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
		hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
		req, _ := http.NewRequestWithContext(hctx, http.MethodHead, probeURL, nil)
		if req != nil {
			req.Host = rootDomain // bind to target domain's vhost
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
			resp, herr := hc.Do(req)
			if herr == nil {
				res.HTTPStatus = resp.StatusCode
				res.ServerHeader = resp.Header.Get("Server")
				resp.Body.Close()
				switch {
				case resp.StatusCode >= 200 && resp.StatusCode < 400:
					res.Evidence = append(res.Evidence, fmt.Sprintf("HTTP Host probe: %d (server recognises domain)", resp.StatusCode))
					res.Confidence = AssetConfirmed
				case resp.StatusCode == 421:
					res.Evidence = append(res.Evidence, "HTTP Host probe: 421 Misdirected Request (server rejects domain)")
					if res.Confidence == AssetUnconfirmed || res.Confidence == AssetUnlikely {
						res.Confidence = AssetRuledOut
					}
				default:
					res.Evidence = append(res.Evidence, fmt.Sprintf("HTTP Host probe: %d", resp.StatusCode))
				}
				if res.ServerHeader != "" {
					res.Evidence = append(res.Evidence, fmt.Sprintf("Server: %s", res.ServerHeader))
				}
			}
		}
		hcancel()
	}

	// ── 4. Summary evidence line ───────────────────────────────────────────
	res.Evidence = append(res.Evidence, fmt.Sprintf("Confidence: %s", res.Confidence))

	return res
}

// ipBelongsToDomain returns true when hostname (e.g. a PTR name) is the root
// domain or a subdomain of it.
func ipBelongsToDomain(hostname, rootDomain string) bool {
	h := strings.TrimSuffix(strings.ToLower(hostname), ".")
	r := strings.ToLower(rootDomain)
	return h == r || strings.HasSuffix(h, "."+r)
}
