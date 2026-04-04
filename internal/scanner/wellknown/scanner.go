// Package wellknown probes IANA-registered .well-known URIs to discover
// exposed service metadata, security policies, and app association files.
package wellknown

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWellKnownAppleAppSite, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownAssetLinks, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownChangePwd, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownHostMeta, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownMTA, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownMatrix, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownNodeInfo, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownOIDC, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownResourceMissing, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownSecurityTxt, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWellKnownWebfinger, finding.SeverityInfo, finding.ModeSurface),
	)
}

const scannerName = "wellknown"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

type probe struct {
	path    string
	checkID finding.CheckID
	title   string
	desc    string
	// bodyContains: if non-empty, response body must contain this string to confirm.
	bodyContains string
}

var probes = []probe{
	{
		path:    "/.well-known/security.txt",
		checkID: finding.CheckWellKnownSecurityTxt,
		title:   "security.txt found",
		desc:    "The site publishes a security.txt file (RFC 9116) with vulnerability disclosure contact info.",
		bodyContains: "Contact:",
	},
	{
		path:    "/.well-known/change-password",
		checkID: finding.CheckWellKnownChangePwd,
		title:   "change-password endpoint exists",
		desc:    "The site supports the well-known change-password URL, helping password managers direct users to the correct page.",
	},
	{
		path:    "/.well-known/apple-app-site-association",
		checkID: finding.CheckWellKnownAppleAppSite,
		title:   "Apple App Site Association exposed",
		desc:    "The apple-app-site-association file reveals iOS app bundle identifiers and associated URL patterns.",
		bodyContains: "applinks",
	},
	{
		path:    "/.well-known/assetlinks.json",
		checkID: finding.CheckWellKnownAssetLinks,
		title:   "Android Asset Links exposed",
		desc:    "The assetlinks.json file reveals Android app package names and signing certificate fingerprints.",
		bodyContains: "target",
	},
	{
		path:    "/.well-known/nodeinfo",
		checkID: finding.CheckWellKnownNodeInfo,
		title:   "NodeInfo endpoint (federated service)",
		desc:    "NodeInfo is exposed, indicating a federated service (Mastodon, Lemmy, etc.). Reveals software name and version.",
		bodyContains: "nodeinfo",
	},
	{
		path:    "/.well-known/webfinger",
		checkID: finding.CheckWellKnownWebfinger,
		title:   "WebFinger endpoint accessible",
		desc:    "The WebFinger endpoint is accessible, which can reveal user accounts and service metadata on federated platforms.",
	},
	{
		path:    "/.well-known/mta-sts.txt",
		checkID: finding.CheckWellKnownMTA,
		title:   "MTA-STS policy via well-known",
		desc:    "An MTA-STS policy is published, enforcing TLS for inbound email delivery.",
		bodyContains: "mode:",
	},
	{
		path:    "/.well-known/matrix/server",
		checkID: finding.CheckWellKnownMatrix,
		title:   "Matrix federation server",
		desc:    "A Matrix federation server configuration is exposed, revealing the homeserver address and port.",
		bodyContains: "m.server",
	},
	{
		path:    "/.well-known/host-meta",
		checkID: finding.CheckWellKnownHostMeta,
		title:   "host-meta (XRD/LRDD) exposed",
		desc:    "The host-meta resource descriptor is accessible. This can reveal service endpoints and federation metadata.",
	},
	{
		path:    "/.well-known/openid-configuration",
		checkID: finding.CheckWellKnownOIDC,
		title:   "OIDC discovery document exposed",
		desc:    "The OpenID Connect discovery document reveals authorization/token endpoints, supported scopes, and signing algorithms.",
		bodyContains: "issuer",
	},
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var findings []finding.Finding
	now := time.Now()

	for _, p := range probes {
		url := "https://" + asset + p.path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			// Try HTTP fallback.
			url = "http://" + asset + p.path
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
			resp, err = client.Do(req)
			if err != nil {
				continue
			}
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		// If the probe requires body content confirmation, check it.
		if p.bodyContains != "" && !strings.Contains(strings.ToLower(string(body)), strings.ToLower(p.bodyContains)) {
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:     p.checkID,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityInfo,
			Asset:       asset,
			Title:       fmt.Sprintf("%s on %s", p.title, asset),
			Description: p.desc,
			Evidence: map[string]any{
				"url":         url,
				"status_code": resp.StatusCode,
				"body_preview": truncate(string(body), 500),
			},
			ProofCommand: fmt.Sprintf("curl -s '%s'", url),
			DiscoveredAt: now,
		})
	}

	// Check for MISSING security.txt — best practice gap.
	hasSecurityTxt := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWellKnownSecurityTxt {
			hasSecurityTxt = true
			break
		}
	}
	if !hasSecurityTxt {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckWellKnownResourceMissing,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityInfo,
			Asset:       asset,
			Title:       fmt.Sprintf("No security.txt on %s", asset),
			Description: "No security.txt (RFC 9116) was found. Publishing a security.txt helps security researchers report vulnerabilities responsibly.",
			Evidence:    map[string]any{"checked_paths": []string{"/.well-known/security.txt", "/security.txt"}},
			ProofCommand: fmt.Sprintf("curl -s https://%s/.well-known/security.txt", asset),
			DiscoveredAt: now,
		})
	}

	return findings, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
