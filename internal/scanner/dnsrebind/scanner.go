// Package dnsrebind implements a deep-mode scanner that detects whether a web
// application is vulnerable to DNS rebinding attacks. DNS rebinding exploits
// the browser's same-origin policy by making a DNS name resolve first to the
// attacker's server (to serve malicious JS) and then re-resolve to an internal
// IP (127.0.0.1, 169.254.169.254, 10.x.x.x) so the JS can reach internal
// services.
//
// This scanner checks:
//  1. Host header validation — does the server accept requests with an
//     arbitrary Host header and return the same content?
//  2. Localhost-routable Host headers — does the server respond identically
//     when Host is set to 127.0.0.1, [::1], or 0.0.0.0?
//  3. Internal service exposure — does a reverse proxy route requests to
//     internal services based on unvalidated Host headers?
//  4. CORS amplification — permissive CORS (Access-Control-Allow-Origin: *)
//     combined with missing Host validation makes DNS rebinding trivially
//     exploitable because the attacker's JS can read responses.
package dnsrebind

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckDNSRebindHostUnvalidated, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckDNSRebindInternalRoutable, finding.SeverityCritical, finding.ModeDeep),
	)
}

const (
	scannerName = "dnsrebind"
	maxBodyRead = 8192
)

// internalHosts are Host header values that point to internal/link-local services.
// If a reverse proxy routes to different backends based on Host without validation,
// these will return different content than the baseline.
var internalHosts = []string{
	"localhost",
	"127.0.0.1",
	"[::1]",
	"0.0.0.0",
	"internal.service",
	"metadata.google.internal",
	"169.254.169.254",
}

// localhostHosts are Host values that test whether the server accepts
// connections from any origin (no DNS pinning).
var localhostHosts = []string{
	"127.0.0.1",
	"[::1]",
	"0.0.0.0",
}

// Scanner detects DNS rebinding vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the DNS rebinding scan. Only runs in deep or authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := buildClient(ctx)

	var findings []finding.Finding
	for _, scheme := range []string{"https", "http"} {
		f := s.probe(ctx, client, asset, scheme)
		findings = append(findings, f...)
	}
	return findings, nil
}

// buildClient creates an HTTP client that follows no redirects and trusts
// self-signed certs, optionally carrying auth context.
func buildClient(ctx context.Context) *http.Client {
	ac := authctx.HTTPClient(ctx)
	client := &http.Client{
		Timeout: 10 * time.Second,
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
	return client
}

// probe tests a single scheme (http or https) for DNS rebinding issues.
func (s *Scanner) probe(ctx context.Context, client *http.Client, asset, scheme string) []finding.Finding {
	url := scheme + "://" + asset + "/"

	// --- baseline request ---
	baseStatus, baseBody, baseCORS, err := doRequest(ctx, client, url, "")
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	// --- Check 1: Host header validation ---
	// Send request with Host: attacker.com. If the server responds with the
	// same status and similar body, it does not validate Host headers.
	attackerHost := "attacker-rebind-probe.example.com"
	probeStatus, probeBody, _, err := doRequest(ctx, client, url, attackerHost)
	if err == nil && probeStatus == baseStatus && bodySimilar(baseBody, probeBody) {
		corsNote := ""
		if baseCORS == "*" {
			corsNote = " Combined with Access-Control-Allow-Origin: *, an attacker's JS can also read responses cross-origin."
		}
		f := finding.Finding{
			CheckID:  finding.CheckDNSRebindHostUnvalidated,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("DNS rebinding: Host header not validated (%s)", scheme),
			Description: "The server returns the same content when the Host header is set to an " +
				"arbitrary attacker-controlled domain. This means a DNS rebinding attack can make " +
				"the victim's browser believe it is communicating with the attacker's domain while " +
				"actually hitting this server's IP, bypassing same-origin policy protections." + corsNote,
			Asset:    asset,
			DeepOnly: true,
			Evidence: map[string]any{
				"url":              url,
				"injected_host":    attackerHost,
				"baseline_status":  baseStatus,
				"probe_status":     probeStatus,
				"cors_permissive":  baseCORS == "*",
			},
			ProofCommand: fmt.Sprintf("curl -si -H 'Host: %s' '%s' | head -20", attackerHost, url),
			DiscoveredAt: time.Now(),
		}
		findings = append(findings, f)
	}

	// --- Check 2: DNS pinning / localhost-routable ---
	// If the server responds identically with Host: 127.0.0.1, [::1], or
	// 0.0.0.0, the server doesn't distinguish origins and a rebinding attack
	// could route the browser to these loopback addresses.
	for _, lh := range localhostHosts {
		lhStatus, lhBody, _, lhErr := doRequest(ctx, client, url, lh)
		if lhErr != nil {
			continue
		}
		if lhStatus == baseStatus && bodySimilar(baseBody, lhBody) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckDNSRebindHostUnvalidated,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("DNS rebinding: server accepts Host: %s (%s)", lh, scheme),
				Description: fmt.Sprintf(
					"The server returns the same content when Host is set to %s. "+
						"This confirms the application does not pin to a specific hostname, "+
						"making DNS rebinding attacks feasible — an attacker's DNS can resolve "+
						"to %s and the browser will deliver the response to malicious JS.", lh, lh),
				Asset:    asset,
				DeepOnly: true,
				Evidence: map[string]any{
					"url":             url,
					"injected_host":   lh,
					"baseline_status": baseStatus,
					"probe_status":    lhStatus,
				},
				ProofCommand: fmt.Sprintf("curl -si -H 'Host: %s' '%s' | head -20", lh, url),
				DiscoveredAt: time.Now(),
			})
			break // one finding is enough to prove the point
		}
	}

	// --- Check 3: Internal service exposure via Host header ---
	// Try Host headers pointing to internal services. If we get DIFFERENT
	// content (not an error page and not the baseline), the reverse proxy
	// routes based on Host without validation → attacker can reach internal
	// backends through DNS rebinding.
	for _, ih := range internalHosts {
		ihStatus, ihBody, _, ihErr := doRequest(ctx, client, url, ih)
		if ihErr != nil {
			continue
		}
		// We want: server responded successfully AND the body is different
		// from baseline (meaning the proxy routed us to a different backend).
		if ihStatus >= 200 && ihStatus < 400 && !bodySimilar(baseBody, ihBody) && len(ihBody) > 0 {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckDNSRebindInternalRoutable,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("DNS rebinding: internal service reachable via Host: %s (%s)", ih, scheme),
				Description: fmt.Sprintf(
					"Setting Host: %s returns different content from the baseline, indicating "+
						"the reverse proxy routes requests to internal backends based on the Host "+
						"header. An attacker can use DNS rebinding to make the victim's browser "+
						"access this internal service, potentially exposing cloud metadata endpoints, "+
						"admin panels, or other sensitive resources.", ih),
				Asset:    asset,
				DeepOnly: true,
				Evidence: map[string]any{
					"url":              url,
					"injected_host":    ih,
					"baseline_status":  baseStatus,
					"internal_status":  ihStatus,
					"body_length":      len(ihBody),
					"body_snippet":     truncate(ihBody, 256),
				},
				ProofCommand: fmt.Sprintf("curl -si -H 'Host: %s' '%s' | head -40", ih, url),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// doRequest sends a GET to url, optionally overriding the Host header.
// Returns status code, body (truncated), CORS header value, and error.
func doRequest(ctx context.Context, client *http.Client, url, host string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", "", err
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	_ = resp.Body.Close()

	cors := resp.Header.Get("Access-Control-Allow-Origin")
	return resp.StatusCode, string(body), cors, nil
}

// bodySimilar returns true if two response bodies are close enough to be
// considered the "same page". We use a simple heuristic: same length within 10%
// and sharing a common prefix.
func bodySimilar(a, b string) bool {
	if a == b {
		return true
	}
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	// Length within 10%.
	ratio := float64(len(a)) / float64(len(b))
	if ratio < 0.9 || ratio > 1.1 {
		return false
	}
	// Check common prefix (at least 50% overlap).
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	common := 0
	for i := 0; i < minLen; i++ {
		if a[i] == b[i] {
			common++
		} else {
			break
		}
	}
	return float64(common) >= float64(minLen)*0.5
}

// truncate returns the first n bytes of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// BodySimilar is exported for testing.
var BodySimilar = bodySimilar

// DoRequest is exported for testing.
var DoRequest = doRequest

// InternalHosts is exported for testing.
var InternalHosts = internalHosts

// LocalhostHosts is exported for testing.
var LocalhostHosts = localhostHosts

// Probe is exported for testing.
func (s *Scanner) Probe(ctx context.Context, client *http.Client, asset, scheme string) []finding.Finding {
	return s.probe(ctx, client, asset, scheme)
}

// BuildClient is exported for testing.
var BuildClient = buildClient

// SetInternalHosts replaces the internalHosts slice (for testing).
func SetInternalHosts(hosts []string) func() {
	old := internalHosts
	internalHosts = hosts
	return func() { internalHosts = old }
}

// SetLocalhostHosts replaces the localhostHosts slice (for testing).
func SetLocalhostHosts(hosts []string) func() {
	old := localhostHosts
	localhostHosts = hosts
	return func() { localhostHosts = old }
}
