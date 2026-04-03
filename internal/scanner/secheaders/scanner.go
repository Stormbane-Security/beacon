// Package secheaders implements a surface-mode scanner that checks for missing
// or misconfigured HTTP security headers. Unlike the nuclei-based header check,
// this scanner produces granular per-header findings with proof commands and
// runs without external tool dependencies.
package secheaders

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckHeadersMissingCSP, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckHeadersMissingPermissionsPolicy, finding.SeverityLow, finding.ModeSurface),
		scan.Check(finding.CheckHeadersMissingReferrerPolicy, finding.SeverityLow, finding.ModeSurface),
		scan.Check(finding.CheckHeadersMissingXContentType, finding.SeverityLow, finding.ModeSurface),
		scan.Check(finding.CheckHeadersMissingXFrameOptions, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckHeadersServerInfoLeak, finding.SeverityLow, finding.ModeSurface),
	)
}
const scannerName = "secheaders"

// Scanner checks for missing or misconfigured HTTP security response headers.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the security headers scan.
// Runs in all modes (surface, deep, authorized) — it only performs a single
// GET request and inspects the response headers.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	scheme, headers, err := fetchHeaders(ctx, client, asset)
	if err != nil || headers == nil {
		return nil, nil // unreachable — nothing to report
	}

	url := scheme + "://" + asset + "/"
	var findings []finding.Finding

	// Content-Security-Policy
	if headers.Get("Content-Security-Policy") == "" {
		findings = append(findings, headerFinding(
			finding.CheckHeadersMissingCSP,
			finding.SeverityMedium,
			asset, url,
			"Content-Security-Policy",
			"No Content-Security-Policy header. Without CSP, the browser has no restrictions on "+
				"inline scripts, eval(), or resource origins — making XSS exploitation trivial once "+
				"a vector is found.",
		))
	}

	// Strict-Transport-Security
	if headers.Get("Strict-Transport-Security") == "" {
		findings = append(findings, headerFinding(
			finding.CheckHeadersMissingHSTS,
			finding.SeverityMedium,
			asset, url,
			"Strict-Transport-Security",
			"No Strict-Transport-Security header. Browsers will not enforce HTTPS, leaving users "+
				"vulnerable to SSL-stripping attacks on first visit or after HSTS expiry.",
		))
	}

	// X-Frame-Options
	if headers.Get("X-Frame-Options") == "" {
		// CSP frame-ancestors is the modern replacement — if present, downgrade severity.
		csp := headers.Get("Content-Security-Policy")
		sev := finding.SeverityMedium
		desc := "No X-Frame-Options header and no CSP frame-ancestors directive. " +
			"The page can be embedded in iframes on any origin, enabling clickjacking attacks."
		if strings.Contains(csp, "frame-ancestors") {
			sev = finding.SeverityInfo
			desc = "No X-Frame-Options header, but CSP frame-ancestors is set. " +
				"Modern browsers use frame-ancestors; X-Frame-Options is only needed for legacy browser support."
		}
		findings = append(findings, headerFinding(
			finding.CheckHeadersMissingXFrameOptions,
			sev,
			asset, url,
			"X-Frame-Options",
			desc,
		))
	}

	// X-Content-Type-Options
	if headers.Get("X-Content-Type-Options") == "" {
		findings = append(findings, headerFinding(
			finding.CheckHeadersMissingXContentType,
			finding.SeverityLow,
			asset, url,
			"X-Content-Type-Options",
			"No X-Content-Type-Options: nosniff header. Browsers may MIME-sniff responses, "+
				"potentially interpreting uploads or API responses as executable content.",
		))
	}

	// Referrer-Policy
	if headers.Get("Referrer-Policy") == "" {
		findings = append(findings, headerFinding(
			finding.CheckHeadersMissingReferrerPolicy,
			finding.SeverityLow,
			asset, url,
			"Referrer-Policy",
			"No Referrer-Policy header. The browser's default policy may leak full URLs "+
				"(including query parameters with tokens or session IDs) to third-party origins.",
		))
	}

	// Permissions-Policy (formerly Feature-Policy)
	if headers.Get("Permissions-Policy") == "" && headers.Get("Feature-Policy") == "" {
		findings = append(findings, headerFinding(
			finding.CheckHeadersMissingPermissionsPolicy,
			finding.SeverityLow,
			asset, url,
			"Permissions-Policy",
			"No Permissions-Policy header. Browser features like camera, microphone, geolocation, "+
				"and payment APIs are not restricted — embedded iframes inherit full access by default.",
		))
	}

	// Server info leak
	server := headers.Get("Server")
	if server != "" && looksVersioned(server) {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckHeadersServerInfoLeak,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityLow,
			Title:       fmt.Sprintf("Server header discloses version: %s", server),
			Description: "The Server response header includes version information. This helps attackers fingerprint the exact software version and target known CVEs for that release.",
			Asset:       asset,
			Evidence: map[string]any{
				"header": "Server",
				"value":  server,
				"url":    url,
			},
			ProofCommand: fmt.Sprintf("curl -sI '%s' | grep -i '^server:'", url),
			DiscoveredAt: time.Now(),
		})
	}

	// X-Powered-By info leak (uses the same check ID as server info leak)
	powered := headers.Get("X-Powered-By")
	if powered != "" {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckHeadersServerInfoLeak,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityLow,
			Title:       fmt.Sprintf("X-Powered-By header discloses technology: %s", powered),
			Description: "The X-Powered-By header reveals the application framework or runtime. This assists attackers in selecting targeted exploits for the specific technology stack.",
			Asset:       asset,
			Evidence: map[string]any{
				"header": "X-Powered-By",
				"value":  powered,
				"url":    url,
			},
			ProofCommand: fmt.Sprintf("curl -sI '%s' | grep -i '^x-powered-by:'", url),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// fetchHeaders tries HTTPS then HTTP and returns the response headers.
func fetchHeaders(ctx context.Context, client *http.Client, asset string) (scheme string, headers http.Header, err error) {
	for _, s := range []string{"https", "http"} {
		url := s + "://" + asset + "/"
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if reqErr != nil {
			continue
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			err = doErr
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		return s, resp.Header, nil
	}
	return "", nil, err
}

// headerFinding builds a finding for a missing security header.
func headerFinding(checkID finding.CheckID, sev finding.Severity, asset, url, header, desc string) finding.Finding {
	return finding.Finding{
		CheckID:      checkID,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     sev,
		Title:        fmt.Sprintf("Missing %s header", header),
		Description:  desc,
		Asset:        asset,
		Evidence: map[string]any{
			"missing_header": header,
			"url":            url,
		},
		ProofCommand: fmt.Sprintf("curl -sI '%s' | grep -i '%s'", url, strings.ToLower(header)),
		DiscoveredAt: time.Now(),
	}
}

// looksVersioned returns true if a Server header value contains version-like
// information (digits following a slash or space).
func looksVersioned(server string) bool {
	// "nginx/1.24.0", "Apache/2.4.57", "Microsoft-IIS/10.0"
	for i, c := range server {
		if c == '/' && i+1 < len(server) && server[i+1] >= '0' && server[i+1] <= '9' {
			return true
		}
	}
	return false
}
