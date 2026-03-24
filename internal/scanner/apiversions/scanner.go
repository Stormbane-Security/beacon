// Package apiversions discovers undocumented or unprotected API versions.
// Older API versions are frequently less protected than the current version —
// missing auth middleware, weaker rate limiting, or unpatched endpoints.
//
// The scanner probes common version prefixes and compares responses to detect
// active API versions the operator may not know are still accessible.
package apiversions

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "apiversions"

// versionPaths are candidate API version prefixes to probe.
var versionPaths = []struct {
	path    string
	version string
}{
	{"/api/v1/", "v1"},
	{"/api/v2/", "v2"},
	{"/api/v3/", "v3"},
	{"/api/v4/", "v4"},
	{"/api/v5/", "v5"},
	{"/v1/", "v1"},
	{"/v2/", "v2"},
	{"/v3/", "v3"},
	{"/v4/", "v4"},
	{"/api/1/", "1"},
	{"/api/2/", "2"},
	{"/api/2.0/", "2.0"},
	{"/api/beta/", "beta"},
	{"/api/alpha/", "alpha"},
	{"/api/internal/", "internal"},
	{"/api/dev/", "dev"},
	{"/api/staging/", "staging"},
	{"/rest/v1/", "v1"},
	{"/rest/v2/", "v2"},
	{"/services/v1/", "v1"},
	{"/services/v2/", "v2"},
}

// Scanner probes for active API version endpoints.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Surface mode: probe only — no deep fuzzing of discovered endpoints.
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	// Gate: if the server returns 200 for a path that cannot exist, every probe
	// path will look "active". Skip the entire scan on catch-all servers.
	if isCatchAll(ctx, client, base) {
		return nil, nil
	}

	// Collect active versions — probe all paths concurrently (max 10 in flight).
	type activeVersion struct {
		path    string
		version string
		status  int
		ct      string
		bodyLen int
	}

	type result struct {
		path    string
		version string
		status  int
		ct      string
		bodyLen int
	}

	resultCh := make(chan result, len(versionPaths))
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, v := range versionPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(v struct{ path, version string }) {
			defer wg.Done()
			defer func() { <-sem }()

			u := base + v.path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()

			// Skip 404 and method-not-allowed.
			if resp.StatusCode == 404 || resp.StatusCode == 405 {
				return
			}
			// Skip redirects — a 3xx means the path doesn't serve API content here;
			// it's almost always a catch-all that forwards unknown paths to the root
			// or login page, not an actual staging/dev environment.
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				return
			}
			// Skip HTML responses — almost certainly a catch-all redirect/landing page.
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "text/html") {
				return
			}

			resultCh <- result{
				path:    v.path,
				version: v.version,
				status:  resp.StatusCode,
				ct:      ct,
				bodyLen: len(body),
			}
		}(v)
	}

	go func() { wg.Wait(); close(resultCh) }()

	var active []activeVersion
	for r := range resultCh {
		active = append(active, activeVersion{
			path:    r.path,
			version: r.version,
			status:  r.status,
			ct:      r.ct,
			bodyLen: r.bodyLen,
		})
	}

	if len(active) == 0 {
		return nil, nil
	}

	// Separate dev/internal/staging versions from numbered versions —
	// these are higher severity because they're more likely unintentionally exposed.
	var findings []finding.Finding
	devKeywords := map[string]bool{"beta": true, "alpha": true, "internal": true, "dev": true, "staging": true}

	for _, av := range active {
		sev := finding.SeverityLow
		if devKeywords[av.version] {
			sev = finding.SeverityHigh
		}

		title := fmt.Sprintf("API version %s is accessible", av.version)
		if devKeywords[av.version] {
			title = fmt.Sprintf("Non-production API endpoint accessible (%s)", av.version)
		}

		desc := fmt.Sprintf(
			"The API endpoint %s%s returned HTTP %d. Legacy API versions often lack the "+
				"security controls (authentication, rate limiting, input validation) applied to current versions. "+
				"Verify this version is intentionally public and has the same security posture as the primary API.",
			base, av.path, av.status)
		if devKeywords[av.version] {
			desc = fmt.Sprintf(
				"A non-production API endpoint (%s) is publicly accessible and returned HTTP %d. "+
					"Development and staging endpoints typically have weaker authentication, broader CORS policies, "+
					"debug features enabled, or access to non-production data. This should not be reachable from the internet.",
				av.version, av.status)
		}

		findings = append(findings, finding.Finding{
			CheckID:      "exposure.api_version",
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        title,
			Description:  desc,
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -si -H 'Accept: application/json' %s%s", base, av.path),
			Evidence: map[string]any{
				"url":          base + av.path,
				"path":         av.path,
				"version":      av.version,
				"status_code":  av.status,
				"content_type": av.ct,
			},
		})
	}

	return findings, nil
}

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}

// isCatchAll returns true when two distinct nonsense paths return HTTP 200
// with identical response bodies — a reliable signal that the server is a
// wildcard/catch-all (SPA, reverse proxy, etc.) where every probe is noise.
// A single-probe check has a high false-positive rate: some servers legitimately
// return 200 for unknown paths but still have distinct, real API endpoints.
func isCatchAll(ctx context.Context, client *http.Client, base string) bool {
	probeA := base + "/beacon-probe-a1b2c3d4e5f6-doesnotexist"
	probeB := base + "/beacon-probe-f6e5d4c3b2a1-alsonotreal"

	hashOf := func(rawURL string) ([]byte, int) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, 0
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, resp.StatusCode
		}
		h := sha256.Sum256(body)
		return h[:], resp.StatusCode
	}

	hashA, statusA := hashOf(probeA)
	hashB, statusB := hashOf(probeB)

	// Both must be 200 and have identical bodies to be considered a catch-all.
	if statusA != http.StatusOK || statusB != http.StatusOK {
		return false
	}
	if hashA == nil || hashB == nil {
		return false
	}
	return string(hashA) == string(hashB)
}
