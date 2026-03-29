// Package takeover detects subdomain takeover vulnerabilities by:
//
//  1. Resolving CNAME chains and matching the final CNAME against known
//     platform suffixes that are claimable (GitHub Pages, S3, Heroku, etc.).
//  2. Making an HTTP request and matching the response body against
//     platform-specific "unclaimed resource" fingerprint strings.
//
// This catches dangling CNAMEs that Nuclei templates may miss because the
// template matcher works at the HTTP layer while some platforms return
// non-standard status codes or redirect before the fingerprint is shown.
//
// Active claim+verify+release (GitHub Pages, S3) is opt-in and requires
// credentials in the scanner config.
package takeover

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

const scannerName = "takeover"

// Scanner detects subdomain takeover vulnerabilities.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// platform describes a SaaS service that can be claimed via subdomain CNAME.
type platform struct {
	// name is the human-readable platform name.
	name string
	// cnameSuffixes are CNAME endings that point to this platform.
	// A dangling CNAME with one of these suffixes indicates possible takeover.
	cnameSuffixes []string
	// httpFingerprint is a string that appears in the HTTP response body
	// when the resource on this platform has not been claimed.
	// Empty means HTTP fingerprinting is not available for this platform.
	httpFingerprint string
}

// platforms is the fingerprint database for known claimable services.
// Keep suffixes lowercase. HTTP fingerprints are case-sensitive unless
// the response body is lowercased before matching (it is not — use exact case).
var platforms = []platform{
	{
		name:            "GitHub Pages",
		cnameSuffixes:   []string{".github.io", ".github.com"},
		httpFingerprint: "There isn't a GitHub Pages site here.",
	},
	{
		name:            "Amazon S3",
		cnameSuffixes:   []string{".s3.amazonaws.com", ".s3-website"},
		httpFingerprint: "NoSuchBucket",
	},
	{
		name:            "Amazon S3 (static website)",
		cnameSuffixes:   []string{".s3-website."},
		httpFingerprint: "The specified bucket does not exist",
	},
	{
		name:            "Heroku",
		cnameSuffixes:   []string{".herokudns.com", ".herokuapp.com"},
		httpFingerprint: "No such app",
	},
	{
		name:            "Netlify",
		cnameSuffixes:   []string{".netlify.app", ".netlify.com"},
		httpFingerprint: "Not Found - Request ID:",
	},
	{
		name:            "Azure (App Service / Traffic Manager)",
		cnameSuffixes:   []string{".azurewebsites.net", ".trafficmanager.net", ".cloudapp.net", ".blob.core.windows.net"},
		httpFingerprint: "404 Web Site not found",
	},
	{
		name:            "Fastly",
		cnameSuffixes:   []string{".fastly.net"},
		httpFingerprint: "Fastly error: unknown domain",
	},
	{
		name:            "Ghost",
		cnameSuffixes:   []string{".ghost.io"},
		httpFingerprint: "The thing you were looking for is no longer here",
	},
	{
		name:            "Tumblr",
		cnameSuffixes:   []string{".tumblr.com"},
		httpFingerprint: "Whatever you were looking for doesn't currently exist at this address",
	},
	{
		name:            "Shopify",
		cnameSuffixes:   []string{".myshopify.com"},
		httpFingerprint: "Sorry, this shop is currently unavailable",
	},
	{
		name:            "WP Engine",
		cnameSuffixes:   []string{".wpengine.com"},
		httpFingerprint: "The site you were looking for couldn",
	},
	{
		name:            "Zendesk",
		cnameSuffixes:   []string{".zendesk.com"},
		httpFingerprint: "Help Center Closed",
	},
	{
		name:            "Pantheon",
		cnameSuffixes:   []string{".pantheonsite.io"},
		httpFingerprint: "The gods are wise, but do not know of the site which you seek",
	},
	{
		name:            "Readme",
		cnameSuffixes:   []string{".readme.io"},
		httpFingerprint: "Project doesnt exist... yet!",
	},
	{
		name:            "Surge.sh",
		cnameSuffixes:   []string{".surge.sh"},
		httpFingerprint: "project not found",
	},
	{
		name:            "Squarespace",
		cnameSuffixes:   []string{".squarespace.com"},
		httpFingerprint: "No Such Account",
	},
	{
		name:            "Cargo",
		cnameSuffixes:   []string{".cargocollective.com"},
		httpFingerprint: "If you're moving your domain away from Cargo you must make this",
	},
	{
		name:            "Intercom",
		cnameSuffixes:   []string{".custom.intercom.help"},
		httpFingerprint: "This page is reserved for artistic dogs",
	},
	{
		name:            "HubSpot",
		cnameSuffixes:   []string{".hubspot.net", ".hs-sites.com"},
		httpFingerprint: "does not exist in our system",
	},
	{
		name:            "Strikingly",
		cnameSuffixes:   []string{".strikingly.com", ".s.strikinglydns.com"},
		httpFingerprint: "But if you're looking to build your own website",
	},
	{
		name:            "Fly.io",
		cnameSuffixes:   []string{".fly.dev", ".edgeapp.net"},
		httpFingerprint: "fly.io",
	},
	{
		name:            "Render",
		cnameSuffixes:   []string{".onrender.com"},
		httpFingerprint: "Site Not Found",
	},
	{
		name:            "Vercel",
		cnameSuffixes:   []string{".vercel.app", ".vercel-dns.com", ".now.sh"},
		httpFingerprint: "cname-not-found",
	},
	{
		name:            "Railway",
		cnameSuffixes:   []string{".railway.app", ".up.railway.app"},
		httpFingerprint: "Application not found",
	},
	{
		name:            "Bitbucket",
		cnameSuffixes:   []string{".bitbucket.io"},
		httpFingerprint: "Repository not found",
	},
	{
		name:            "Agility CMS",
		cnameSuffixes:   []string{".agilitycms.com"},
		httpFingerprint: "Sorry, this page is no longer available",
	},
	{
		name:            "Gitbook",
		cnameSuffixes:   []string{".gitbook.io"},
		httpFingerprint: "If you need specifics, here",
	},
	{
		name:            "Ngrok",
		cnameSuffixes:   []string{".ngrok.io", ".ngrok-free.app"},
		httpFingerprint: "Tunnel not found",
	},
	{
		name:            "Webflow",
		cnameSuffixes:   []string{".webflow.io", ".proxy-ssl.webflow.com"},
		httpFingerprint: "The page you are looking for doesn't exist or has been moved",
	},
	{
		name:            "Launchrock",
		cnameSuffixes:   []string{".launchrock.com"},
		httpFingerprint: "It looks like you may have taken a wrong turn somewhere",
	},
	{
		name:            "Tilda",
		cnameSuffixes:   []string{".tildacdn.com"},
		httpFingerprint: "Please renew your subscription",
	},
}

// Run checks each asset for subdomain takeover vulnerabilities by:
//  1. Resolving the CNAME chain for the asset.
//  2. Matching the final CNAME against known platform suffixes.
//  3. When a platform match is found, making an HTTP request to check
//     for the platform's "unclaimed resource" fingerprint.
//
// Runs in both surface and deep mode — CNAME lookups are passive DNS queries.
func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Resolve the CNAME chain. An NXDOMAIN or empty result means the
	// subdomain has no DNS record — no takeover vector via CNAME.
	cname, err := resolveCNAME(ctx, asset)
	if err != nil || cname == "" {
		return nil, nil
	}
	cnameLower := strings.ToLower(cname)

	// Match against platform fingerprints.
	var matched *platform
	for i := range platforms {
		for _, suffix := range platforms[i].cnameSuffixes {
			if strings.Contains(cnameLower, suffix) {
				matched = &platforms[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		return nil, nil
	}

	// CNAME points to a claimable platform. Now confirm by HTTP probe —
	// a live, claimed resource returns 200+content, not the unclaimed fingerprint.
	body, statusCode := httpProbe(ctx, asset)

	// If we couldn't reach the asset at all (network error / no HTTP service),
	// the CNAME alone is still a finding — the subdomain is dangling.
	dangling := true
	confirmed := false

	if body != "" && matched.httpFingerprint != "" {
		if strings.Contains(strings.ToLower(body), strings.ToLower(matched.httpFingerprint)) {
			confirmed = true // platform confirmed this resource is unclaimed
		} else if statusCode >= 200 && statusCode < 300 {
			dangling = false // asset is live and claimed — not a takeover
		}
	}

	if !dangling {
		return nil, nil
	}

	severity := finding.SeverityHigh
	description := fmt.Sprintf(
		"The subdomain %s has a CNAME record pointing to %s (%s), "+
			"but the resource at that address does not appear to be claimed. "+
			"An attacker may be able to register this resource on %s and serve "+
			"arbitrary content under the %s domain, enabling phishing, "+
			"cookie theft, and bypass of SameSite cookie protections.",
		asset, cname, matched.name, matched.name, asset,
	)
	if confirmed {
		severity = finding.SeverityCritical
		description += " The platform's unclaimed-resource fingerprint was confirmed in the HTTP response."
	}

	return []finding.Finding{{
		CheckID:  finding.CheckSubdomainTakeover,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: severity,
		Asset:    asset,
		Title:    fmt.Sprintf("Subdomain takeover: %s → %s (%s)", asset, cname, matched.name),
		Description: description,
		Evidence: map[string]any{
			"cname":              cname,
			"platform":           matched.name,
			"http_fingerprint":   matched.httpFingerprint,
			"http_status":        statusCode,
			"confirmed_by_http":  confirmed,
		},
		DiscoveredAt: time.Now(),
	}}, nil
}

// resolveCNAME follows the CNAME chain for hostname and returns the final
// canonical name (with trailing dot stripped). Returns "" when the host has
// an A/AAAA record but no CNAME, or on error.
func resolveCNAME(ctx context.Context, hostname string) (string, error) {
	resolver := net.DefaultResolver
	cname, err := resolver.LookupCNAME(ctx, hostname)
	if err != nil {
		return "", err
	}
	// LookupCNAME returns the hostname itself (with trailing dot) when there is
	// no CNAME chain — i.e., the host resolves directly via A/AAAA.
	canonical := strings.TrimSuffix(strings.ToLower(cname), ".")
	if canonical == strings.ToLower(strings.TrimSuffix(hostname, ".")) {
		return "", nil // no CNAME — direct A record
	}
	return canonical, nil
}

// httpProbe fetches the root of the asset over HTTPS then HTTP.
// Returns the response body (up to 4 KB) and status code, or "" / 0 on error.
func httpProbe(ctx context.Context, asset string) (string, int) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return string(body), resp.StatusCode
	}
	return "", 0
}
