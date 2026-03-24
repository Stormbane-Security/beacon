// Package hpp probes for HTTP Parameter Pollution (HPP) vulnerabilities by
// sending requests with duplicate query parameters and checking whether the
// server uses the second value in a way that bypasses access controls or
// changes application behaviour.
//
// Deep mode only (active probing with potentially sensitive parameter values).
package hpp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName = "hpp"
	maxBodySize = 64 * 1024 // 64 KB
)

// probePaths are common API and web endpoints that accept query parameters.
var probePaths = []string{
	"/api",
	"/api/v1",
	"/search",
	"/users",
	"/products",
}

// roleProbe tests whether a second "role" value overrides the first.
// If "admin" appears in the response but not when using role=user alone,
// this signals that the server honours the second (attacker-controlled) value.
type roleProbe struct {
	// dual is the duplicate-parameter URL query string.
	dual string
	// single is the baseline query string with only the safe value.
	single string
	// signal is the string whose presence indicates the second value was used.
	signal string
}

var roleProbes = []roleProbe{
	{dual: "role=user&role=admin", single: "role=user", signal: "admin"},
}

// Scanner probes for HTTP Parameter Pollution vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the HPP scan. Only runs in deep mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	for _, path := range probePaths {
		// Skip paths that return 404 to reduce noise.
		if isNotFound(ctx, client, base+path) {
			continue
		}

		// Probe 1: role=user&role=admin — second value override.
		for _, rp := range roleProbes {
			dualURL := base + path + "?" + rp.dual
			dualBody := fetchBody(ctx, client, dualURL)
			if dualBody == "" {
				continue
			}

			// Only flag if the signal appears in the dual-param response.
			if !strings.Contains(dualBody, rp.signal) {
				continue
			}

			// Baseline: fetch with single safe param. If signal already
			// appears without pollution, this is a false positive.
			singleURL := base + path + "?" + rp.single
			singleBody := fetchBody(ctx, client, singleURL)
			if strings.Contains(singleBody, rp.signal) {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebHPP,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("HTTP Parameter Pollution (role override) on %s%s", asset, path),
				Description: fmt.Sprintf(
					"The endpoint %s accepted duplicate 'role' parameters (%s) and "+
						"the response contained %q, suggesting the server uses the "+
						"second parameter value. An attacker may be able to escalate "+
						"privileges by injecting additional parameter values.",
					dualURL, rp.dual, rp.signal),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -s "%s" | grep -i "admin"`, dualURL),
				Evidence: map[string]any{
					"url":         dualURL,
					"path":        path,
					"probe":       rp.dual,
					"signal":      rp.signal,
					"baseline":    singleURL,
				},
				DiscoveredAt: time.Now(),
			})
			break
		}

		// Probe 2: id=1&id=2 — check if response differs from id=1 alone.
		idDualURL := base + path + "?id=1&id=2"
		idSingleURL := base + path + "?id=1"
		dualBody := fetchBody(ctx, client, idDualURL)
		singleBody := fetchBody(ctx, client, idSingleURL)
		if dualBody != "" && singleBody != "" && dualBody != singleBody {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebHPP,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("HTTP Parameter Pollution (id parameter) on %s%s", asset, path),
				Description: fmt.Sprintf(
					"The endpoint %s returned different responses for ?id=1 vs ?id=1&id=2, "+
						"indicating the server processes duplicate 'id' parameters differently. "+
						"This may allow an attacker to manipulate resource lookups.",
					base+path),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`diff <(curl -s "%s") <(curl -s "%s")`, idSingleURL, idDualURL),
				Evidence: map[string]any{
					"url_single": idSingleURL,
					"url_dual":   idDualURL,
					"path":       path,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Probe 3: filter=safe&filter=unsafe%0d%0a — CRLF variant.
		crlfDualURL := base + path + "?filter=safe&filter=unsafe%0d%0a"
		crlfBody := fetchBody(ctx, client, crlfDualURL)
		crlfSingleURL := base + path + "?filter=safe"
		crlfSingleBody := fetchBody(ctx, client, crlfSingleURL)
		if crlfBody != "" && crlfSingleBody != "" && crlfBody != crlfSingleBody {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebHPP,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("HTTP Parameter Pollution (CRLF filter bypass) on %s%s", asset, path),
				Description: fmt.Sprintf(
					"The endpoint %s returned a different response when a duplicate 'filter' "+
						"parameter with a CRLF-encoded value was appended. This may indicate "+
						"susceptibility to parameter pollution combined with log injection or "+
						"header injection.",
					base+path),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -v "%s"`, crlfDualURL),
				Evidence: map[string]any{
					"url_single": crlfSingleURL,
					"url_dual":   crlfDualURL,
					"path":       path,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// fetchBody makes a GET request and returns the response body as a string.
// Returns an empty string on error or empty response.
func fetchBody(ctx context.Context, client *http.Client, rawURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()
	return string(body)
}

// isNotFound returns true when the path returns HTTP 404.
func isNotFound(ctx context.Context, client *http.Client, rawURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusNotFound
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "http"
	}
	resp.Body.Close()
	return "https"
}
