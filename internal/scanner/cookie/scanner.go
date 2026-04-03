// Package cookie audits cookie security attributes across all Set-Cookie
// headers returned by a target. Checks for missing Secure, HttpOnly, SameSite,
// __Host-/__Secure- prefix, and excessive domain scope.
package cookie

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}

const scannerName = "cookie"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// sensitiveNames are cookie name patterns that likely hold session/auth data.
var sensitiveNames = []string{
	"session", "sess", "sid", "jsessionid", "phpsessid",
	"asp.net_sessionid", "connect.sid", "laravel_session",
	"ci_session", "rack.session", "auth", "token", "jwt",
	"access_token", "id_token", "remember_me", "logged_in",
	"csrf", "xsrf",
}

func isSensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range sensitiveNames {
		if lower == s || strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var allCookies []*http.Cookie

	// Probe both HTTPS and HTTP root paths.
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		allCookies = append(allCookies, resp.Cookies()...)
	}

	if len(allCookies) == 0 {
		return nil, nil
	}

	seen := map[string]bool{}
	var findings []finding.Finding
	now := time.Now()

	for _, c := range allCookies {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true

		sensitive := isSensitiveName(c.Name)

		// Check missing Secure flag on sensitive cookies.
		if !c.Secure && sensitive {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCookieMissingSecure,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Asset:       asset,
				Title:       fmt.Sprintf("Cookie %q missing Secure flag", c.Name),
				Description: fmt.Sprintf("The cookie %q appears to hold session/auth data but does not set the Secure attribute. It will be sent over unencrypted HTTP connections, exposing it to interception.", c.Name),
				Evidence:    map[string]any{"cookie_name": c.Name, "domain": c.Domain, "path": c.Path},
				ProofCommand: fmt.Sprintf("curl -sI https://%s/ | grep -i set-cookie", asset),
				DiscoveredAt: now,
			})
		}

		// Check missing HttpOnly flag on sensitive cookies.
		if !c.HttpOnly && sensitive {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCookieMissingHTTPOnly,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Asset:       asset,
				Title:       fmt.Sprintf("Cookie %q missing HttpOnly flag", c.Name),
				Description: fmt.Sprintf("The cookie %q appears to hold session/auth data but does not set HttpOnly. JavaScript (including XSS payloads) can read this cookie via document.cookie.", c.Name),
				Evidence:    map[string]any{"cookie_name": c.Name},
				ProofCommand: fmt.Sprintf("curl -sI https://%s/ | grep -i set-cookie", asset),
				DiscoveredAt: now,
			})
		}

		// Check missing SameSite attribute.
		// Go's net/http leaves SameSite as 0 (zero value) when the attribute is
		// absent, while SameSiteDefaultMode == 1. Check both.
		if (c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode) && sensitive {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCookieMissingSameSite,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityLow,
				Asset:       asset,
				Title:       fmt.Sprintf("Cookie %q missing SameSite attribute", c.Name),
				Description: fmt.Sprintf("The cookie %q does not set SameSite. Browsers default to Lax, but explicit SameSite=Strict or SameSite=Lax is recommended for session cookies.", c.Name),
				Evidence:    map[string]any{"cookie_name": c.Name},
				ProofCommand: fmt.Sprintf("curl -sI https://%s/ | grep -i set-cookie", asset),
				DiscoveredAt: now,
			})
		}

		// Check missing __Host- or __Secure- prefix on session cookies.
		if sensitive && c.Secure && !strings.HasPrefix(c.Name, "__Host-") && !strings.HasPrefix(c.Name, "__Secure-") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCookieNoPrefix,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityLow,
				Asset:       asset,
				Title:       fmt.Sprintf("Cookie %q missing __Host-/__Secure- prefix", c.Name),
				Description: fmt.Sprintf("The cookie %q is marked Secure but does not use the __Host- or __Secure- prefix. These prefixes instruct browsers to enforce additional security constraints (no Domain attribute, Path=/ required).", c.Name),
				Evidence:    map[string]any{"cookie_name": c.Name},
				ProofCommand: fmt.Sprintf("curl -sI https://%s/ | grep -i set-cookie", asset),
				DiscoveredAt: now,
			})
		}

		// Check excessive Domain scope.
		if c.Domain != "" {
			// A cookie set on ".example.com" is accessible from any subdomain.
			parts := strings.Split(strings.TrimPrefix(c.Domain, "."), ".")
			if len(parts) == 2 && sensitive {
				// Cookie scoped to the apex domain (e.g., .example.com).
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCookieExcessiveScope,
					Module:      "surface",
					Scanner:     scannerName,
					Severity:    finding.SeverityMedium,
					Asset:       asset,
					Title:       fmt.Sprintf("Cookie %q scoped to apex domain %q", c.Name, c.Domain),
					Description: fmt.Sprintf("The cookie %q has Domain=%s, making it accessible from every subdomain. A compromised or attacker-controlled subdomain can read and exfiltrate this cookie.", c.Name, c.Domain),
					Evidence:    map[string]any{"cookie_name": c.Name, "domain": c.Domain},
					ProofCommand: fmt.Sprintf("curl -sI https://%s/ | grep -i set-cookie", asset),
					DiscoveredAt: now,
				})
			}
		}
	}

	return findings, nil
}
