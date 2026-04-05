// Package hostheader implements a deep-mode scanner for host header injection
// vulnerabilities. It probes the target with crafted Host and X-Forwarded-Host
// style headers and checks whether the injected value is reflected in redirect
// locations, Set-Cookie domain attributes, or the response body.
package hostheader

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckHostHeaderInjection, finding.SeverityHigh, finding.ModeDeep),
	)
}
const (
	scannerName  = "hostheader"
	probeValue   = "evil-beacon-probe.example.com"
	baselinePath = "/"
)

// Scanner checks for host header injection vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the host header injection scan. Only runs in deep mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	ac := authctx.HTTPClient(ctx)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: ac.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if client.Transport == nil {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	// Test BOTH HTTP and HTTPS independently. A common host header injection
	// vector is HTTP→HTTPS redirects where the server reflects the Host header
	// in the Location header. If we only test the first scheme that works
	// (usually HTTPS), we miss this entirely because HTTPS serves a 200 OK
	// with no redirect.
	var findings []finding.Finding
	for _, scheme := range []string{"https", "http"} {
		schemeFindings := s.probeScheme(ctx, client, asset, scheme)
		findings = append(findings, schemeFindings...)
	}

	return findings, nil
}

// probeScheme tests host header injection against a single scheme (http or https).
func (s *Scanner) probeScheme(ctx context.Context, client *http.Client, asset, scheme string) []finding.Finding {
	url := scheme + "://" + asset + baselinePath

	// Baseline request to get normal response values.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	baseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	baseLocation := resp.Header.Get("Location")
	baseCookie := resp.Header.Get("Set-Cookie")

	// Header injection combos: name → how to apply it to the request.
	type probe struct {
		header string // empty string means replace Host
		name   string // human-readable label
	}
	probes := []probe{
		{header: "", name: "Host"},
		{header: "X-Forwarded-Host", name: "X-Forwarded-Host"},
		{header: "X-Host", name: "X-Host"},
		{header: "X-Original-Host", name: "X-Original-Host"},
	}

	var findings []finding.Finding

	for _, p := range probes {
		probeReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		if p.header == "" {
			// Replace the Host field directly.
			probeReq.Host = probeValue
		} else {
			probeReq.Header.Set(p.header, probeValue)
		}

		probeResp, err := client.Do(probeReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(probeResp.Body, 4096))
		_ = probeResp.Body.Close()

		location := probeResp.Header.Get("Location")
		setCookie := probeResp.Header.Get("Set-Cookie")

		reflected, where := checkReflection(
			probeValue,
			baseLocation, baseCookie, string(baseBody),
			location, setCookie, string(body),
			probeResp.StatusCode,
		)
		if !reflected {
			continue
		}

		// Check whether the poisoned response was served from cache — if so
		// this is confirmed cache poisoning (Critical), not just a theoretical risk.
		cached := strings.EqualFold(probeResp.Header.Get("X-Cache"), "HIT") ||
			strings.EqualFold(probeResp.Header.Get("CF-Cache-Status"), "HIT")

		sev := finding.SeverityHigh
		title := fmt.Sprintf("Host header injection: %s reflected in %s (%s)", p.name, where, scheme)
		desc := "The application reflects the injected host header value in its response. " +
			"This can be exploited for cache poisoning attacks (serving malicious content to other users " +
			"via a shared cache) and password-reset poisoning (sending password-reset emails containing " +
			"links pointing to an attacker-controlled domain). An attacker who can manipulate the " +
			"Host header can redirect sensitive tokens and links to infrastructure they control."
		if cached {
			sev = finding.SeverityCritical
			title = fmt.Sprintf("Host header cache poisoning: %s reflected in %s (cached, %s)", p.name, where, scheme)
			desc = "The poisoned response was served from cache (X-Cache: HIT). Real users are being " +
				"redirected to the injected domain. This is confirmed cache poisoning — the attacker does " +
				"not need to be on-path. Anyone requesting this URL receives the poisoned response until " +
				"the cache entry expires."
		}

		evidence := map[string]any{
			"injected_header": p.name,
			"injected_value":  probeValue,
			"reflected_in":    where,
			"url":             url,
			"scheme":          scheme,
		}
		if cached {
			evidence["cached"] = "true"
		}

		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckHostHeaderInjection,
			Module:       "deep",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        title,
			Description:  desc,
			Asset:        asset,
			DeepOnly:     true,
			Evidence:     evidence,
			ProofCommand: fmt.Sprintf("curl -si -H '%s: %s' '%s' | grep -iE 'location|x-cache|cf-cache-status'", p.name, probeValue, url),
			DiscoveredAt: time.Now(),
		})
	}

	// ── Absolute URL with mismatched Host header ──────────────────────────
	absReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		absReq.Host = probeValue
		absResp, absErr := client.Do(absReq)
		if absErr == nil {
			absBody, _ := io.ReadAll(io.LimitReader(absResp.Body, 4096))
			_ = absResp.Body.Close()

			absLocation := absResp.Header.Get("Location")
			absSetCookie := absResp.Header.Get("Set-Cookie")

			reflected, where := checkReflection(
				probeValue,
				baseLocation, baseCookie, string(baseBody),
				absLocation, absSetCookie, string(absBody),
				absResp.StatusCode,
			)
			if reflected {
				findings = append(findings, finding.Finding{
					CheckID:      finding.CheckHostHeaderInjection,
					Module:       "deep",
					Scanner:      scannerName,
					Severity:     finding.SeverityHigh,
					Title:        fmt.Sprintf("Host header injection via absolute URL: Host reflected in %s (%s)", where, scheme),
					Description: "The application reflects the Host header value even when the request uses an " +
						"absolute URL pointing to the real host. This technique bypasses WAFs and reverse proxies " +
						"that validate the Host header against the request target, because the routing layer uses " +
						"the absolute URI while the application uses the Host header for link generation.",
					Asset:        asset,
					DeepOnly:     true,
					Evidence: map[string]any{
						"injected_header": "Host (absolute URL)",
						"injected_value":  probeValue,
						"reflected_in":    where,
						"url":             url,
						"scheme":          scheme,
					},
					ProofCommand: fmt.Sprintf(
						"curl -si --request-target '%s' -H 'Host: %s' '%s' | grep -iE 'location|set-cookie'",
						url, probeValue, url),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}


// checkReflection returns whether the probe value appears in the injected
// response at a location that was not already present in the baseline.
func checkReflection(
	probe string,
	baseLocation, baseCookie, baseBody string,
	location, setCookie, body string,
	statusCode int,
) (reflected bool, where string) {
	// Location header
	if strings.Contains(location, probe) && !strings.Contains(baseLocation, probe) {
		if statusCode >= 300 && statusCode < 400 {
			return true, "Location header"
		}
	}

	// Set-Cookie domain= attribute
	if strings.Contains(strings.ToLower(setCookie), "domain=") &&
		strings.Contains(setCookie, probe) &&
		!strings.Contains(baseCookie, probe) {
		return true, "Set-Cookie header"
	}

	// Response body
	if strings.Contains(body, probe) && !strings.Contains(baseBody, probe) {
		return true, "response body"
	}

	return false, ""
}
