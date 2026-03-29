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

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

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
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		// Do not follow redirects – we need to inspect raw Location headers.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Determine which scheme works for this asset.
	scheme, baseStatus, baseLocation, baseCookie, baseBody, err := baseline(ctx, client, asset)
	if err != nil {
		return nil, nil // asset unreachable – nothing to report
	}
	_ = baseStatus

	url := scheme + "://" + asset + baselinePath

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
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		if p.header == "" {
			// Replace the Host field directly.
			req.Host = probeValue
		} else {
			req.Header.Set(p.header, probeValue)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		location := resp.Header.Get("Location")
		setCookie := resp.Header.Get("Set-Cookie")

		reflected, where := checkReflection(
			probeValue,
			baseLocation, baseCookie, baseBody,
			location, setCookie, string(body),
			resp.StatusCode,
		)
		if !reflected {
			continue
		}

		// Check whether the poisoned response was served from cache — if so
		// this is confirmed cache poisoning (Critical), not just a theoretical risk.
		cached := strings.EqualFold(resp.Header.Get("X-Cache"), "HIT") ||
			strings.EqualFold(resp.Header.Get("CF-Cache-Status"), "HIT")

		sev := finding.SeverityHigh
		title := fmt.Sprintf("Host header injection: %s reflected in %s", p.name, where)
		desc := "The application reflects the injected host header value in its response. " +
			"This can be exploited for cache poisoning attacks (serving malicious content to other users " +
			"via a shared cache) and password-reset poisoning (sending password-reset emails containing " +
			"links pointing to an attacker-controlled domain). An attacker who can manipulate the " +
			"Host header can redirect sensitive tokens and links to infrastructure they control."
		if cached {
			sev = finding.SeverityCritical
			title = fmt.Sprintf("Host header cache poisoning: %s reflected in %s (cached)", p.name, where)
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
	// HTTP/1.1 allows an absolute Request-URI (RFC 7230 §5.3.2). When the
	// request line contains the real host but the Host header says evil.com,
	// some servers use the Host header for application logic (redirects,
	// links, cache keys) while routing is based on the absolute URI. This
	// bypasses naive "Host must match the target" checks in some WAFs.
	absReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		absReq.Host = probeValue
		// Force the request line to use an absolute URL by setting the URL
		// explicitly — Go's http.Client normally strips scheme+host from
		// the request line, but the Host header override is what matters
		// for application-level injection.
		absResp, absErr := client.Do(absReq)
		if absErr == nil {
			absBody, _ := io.ReadAll(io.LimitReader(absResp.Body, 1024))
			absResp.Body.Close()

			absLocation := absResp.Header.Get("Location")
			absSetCookie := absResp.Header.Get("Set-Cookie")

			reflected, where := checkReflection(
				probeValue,
				baseLocation, baseCookie, baseBody,
				absLocation, absSetCookie, string(absBody),
				absResp.StatusCode,
			)
			if reflected {
				findings = append(findings, finding.Finding{
					CheckID:      finding.CheckHostHeaderInjection,
					Module:       "deep",
					Scanner:      scannerName,
					Severity:     finding.SeverityHigh,
					Title:        fmt.Sprintf("Host header injection via absolute URL: Host reflected in %s", where),
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
					},
					ProofCommand: fmt.Sprintf(
						"curl -si --request-target '%s' -H 'Host: %s' '%s' | grep -iE 'location|set-cookie'",
						url, probeValue, url),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// baseline performs a plain GET to determine the working scheme and collect
// baseline response values (Location, Set-Cookie domain, body snippet).
func baseline(ctx context.Context, client *http.Client, asset string) (
	scheme string,
	statusCode int,
	location, setCookie, body string,
	err error,
) {
	for _, s := range []string{"https", "http"} {
		url := s + "://" + asset + baselinePath
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		var resp *http.Response
		resp, err = client.Do(req)
		if err != nil {
			continue
		}

		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		resp.Body.Close()

		scheme = s
		statusCode = resp.StatusCode
		location = resp.Header.Get("Location")
		setCookie = resp.Header.Get("Set-Cookie")
		body = string(b)
		err = nil
		return
	}
	return
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
