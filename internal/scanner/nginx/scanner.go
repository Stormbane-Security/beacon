// Package nginx detects Nginx alias traversal and IIS short-name enumeration
// vulnerabilities via passive path probes (no payloads, no credentials).
//
// Surface mode safe — only GETs known paths and inspects responses.
package nginx

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
	scannerName = "nginx"
	maxBodySize = 32 * 1024 // 32 KB
)

// commonPaths are URL path prefixes to combine with traversal suffixes.
// These are typical alias-mapped directories in Nginx configurations.
var commonPaths = []string{
	"/api/v1",
	"/static",
	"/assets",
	"/uploads",
	"/files",
}

// traversalSuffixes are appended to each common path to attempt traversal.
var traversalSuffixes = []string{
	"../etc/passwd",
	"./etc/passwd",
}

// passwdSignals indicate a successful /etc/passwd read.
var passwdSignals = []string{
	"root:x:0:0",
	"bin:x:1:1",
}

// iisSignals are substrings in the Server header that identify IIS servers.
var iisSignals = []string{
	"IIS",
	"Microsoft",
}

// Scanner detects Nginx alias traversal and IIS short-name enumeration.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the nginx/IIS scan. Runs in both surface and deep modes.
func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	// Nginx alias traversal: probe each common path with traversal suffixes.
	for _, path := range commonPaths {
		for _, suffix := range traversalSuffixes {
			probePath := path + "/" + suffix
			u := base + probePath
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				if resp != nil {
					resp.Body.Close()
				}
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			resp.Body.Close()

			bodyStr := string(body)
			signal := passwdSignalFound(bodyStr)
			if signal == "" {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebNginxAliasTraversal,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("Nginx alias traversal exposes /etc/passwd on %s", asset),
				Description: fmt.Sprintf(
					"The path %s on %s returned /etc/passwd content (%q). "+
						"This indicates a misconfigured Nginx alias directive that allows "+
						"directory traversal outside the intended document root. "+
						"An attacker can read arbitrary files from the server filesystem.",
					probePath, asset, signal),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					`curl -s "%s%s" | grep "root:"`, base, probePath),
				Evidence: map[string]any{
					"url":    u,
					"path":   probePath,
					"signal": signal,
				},
				DiscoveredAt: time.Now(),
			})

			// One finding per path prefix is sufficient.
			break
		}
	}

	// IIS short-name enumeration: probe /~1/ and check for 400 response.
	iisURL := base + "/~1/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, iisURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			serverHeader := resp.Header.Get("Server")
			if resp.StatusCode == http.StatusBadRequest && isIISServer(serverHeader) {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebIISShortname,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Title:    fmt.Sprintf("IIS short-name enumeration possible on %s", asset),
					Description: fmt.Sprintf(
						"The IIS server at %s returned HTTP 400 for the path /~1/, "+
							"indicating that 8.3 short-name enumeration may be possible. "+
							"An attacker can use this to enumerate file and directory names "+
							"that are otherwise hidden, potentially revealing sensitive paths.",
						asset),
					Asset: asset,
					ProofCommand: fmt.Sprintf(
						`curl -v "%s/~1/" 2>&1 | grep "< HTTP"`, base),
					Evidence: map[string]any{
						"url":           iisURL,
						"status":        resp.StatusCode,
						"server_header": serverHeader,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// passwdSignalFound returns the first /etc/passwd signal found in body,
// or an empty string if none are present.
func passwdSignalFound(body string) string {
	for _, sig := range passwdSignals {
		if strings.Contains(body, sig) {
			return sig
		}
	}
	return ""
}

// isIISServer returns true when the Server header value identifies IIS.
func isIISServer(serverHeader string) bool {
	for _, sig := range iisSignals {
		if strings.Contains(serverHeader, sig) {
			return true
		}
	}
	return false
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
