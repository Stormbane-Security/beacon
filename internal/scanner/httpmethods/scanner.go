// Package httpmethods checks for dangerous HTTP methods enabled on a web server.
//
// Surface mode (safe for unsolicited scans):
//   - Sends one OPTIONS request and inspects the Allow header.
//   - Reports dangerous methods that are advertised but does NOT send any
//     PUT/DELETE/TRACE requests. Findings are marked "advertised" (lower
//     confidence) because many servers list methods in Allow headers without
//     actually accepting them.
//
// Deep mode (requires permission):
//   - After the OPTIONS check, confirms each advertised dangerous method by
//     sending the actual request to a benign probe path.
//   - Confirmed findings are reported at higher severity and with proof commands.
//
// Dangerous methods checked:
//   - PUT    — allows arbitrary file upload / content modification
//   - DELETE — allows resource deletion
//   - TRACE  — echoes request back; enables XST (Cross-Site Tracing)
package httpmethods

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "httpmethods"

// Scanner checks for dangerous HTTP methods.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// dangerousMethods are methods that should never be enabled on public-facing servers.
var dangerousMethods = []struct {
	method string
	risk   string
}{
	{"PUT", "Allows arbitrary file upload or overwrite — attackers can plant webshells or replace content."},
	{"DELETE", "Allows deletion of server-side resources — data destruction or service disruption."},
	{"TRACE", "Echoes request headers back to the client. Enables Cross-Site Tracing (XST), which can expose HttpOnly cookies and Authorization headers to JavaScript even when SameSite protections are in place."},
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := discoverBase(ctx, client, asset)
	if baseURL == "" {
		return nil, nil
	}

	// Step 1: OPTIONS probe — always runs in both modes. Safe and read-only.
	allowed := optionsAllowed(ctx, client, baseURL)

	var findings []finding.Finding
	now := time.Now()

	for _, dm := range dangerousMethods {
		// Surface mode: only flag methods explicitly listed in the Allow header.
		// Deep mode: also probe methods not in Allow, since many servers don't
		// return the header but still accept dangerous methods.
		inAllow := strings.Contains(strings.ToUpper(allowed), dm.method)
		if !inAllow && scanType != module.ScanDeep {
			continue
		}

		if scanType != module.ScanDeep && inAllow {
			// Surface mode: report the advertisement without confirming.
			// Severity is Low because Allow headers are unreliable indicators.
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebDangerousMethodEnabled,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Asset:    asset,
				Title: fmt.Sprintf("Dangerous HTTP method advertised: %s on %s",
					dm.method, baseURL),
				Description: fmt.Sprintf(
					"The Allow response header on %s lists %s as a supported method. "+
						"%s This finding is unconfirmed — run a deep scan to verify "+
						"whether the method is actually accepted.",
					baseURL, dm.method, dm.risk,
				),
				Evidence: map[string]any{
					"method":       dm.method,
					"url":          baseURL,
					"allow_header": allowed,
					"confirmed":    false,
				},
				DiscoveredAt: now,
			})
			continue
		}

		// Deep mode: confirm with an actual request before reporting.
		confirmed, statusCode := confirmMethod(ctx, client, baseURL, dm.method)
		if !confirmed {
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWebDangerousMethodEnabled,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    asset,
			Title: fmt.Sprintf("Dangerous HTTP method enabled: %s on %s",
				dm.method, baseURL),
			Description: fmt.Sprintf(
				"The server at %s accepts HTTP %s requests (confirmed with status %d). "+
					"%s Disable this method in the web server configuration unless explicitly required.",
				baseURL, dm.method, statusCode, dm.risk,
			),
			Evidence: map[string]any{
				"method":       dm.method,
				"url":          baseURL,
				"status_code":  statusCode,
				"allow_header": allowed,
				"confirmed":    true,
			},
			DiscoveredAt: now,
		})
	}

	return findings, nil
}

// discoverBase returns the first responsive base URL (https or http) for asset.
func discoverBase(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + asset + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return url
		}
	}
	return ""
}

// optionsAllowed sends OPTIONS to url and returns the value of the Allow header.
func optionsAllowed(ctx context.Context, client *http.Client, url string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, url, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return resp.Header.Get("Allow")
}

// confirmMethod sends a single method request to a probe path and returns true
// when the server responds with anything other than 405 (Method Not Allowed)
// or 501 (Not Implemented), indicating the method is actually processed.
//
// For PUT/DELETE we use a safe non-existent path to avoid modifying real content.
// If a PUT succeeds (2xx), a best-effort DELETE is sent to remove any artifact.
func confirmMethod(ctx context.Context, client *http.Client, baseURL, method string) (bool, int) {
	probeURL := strings.TrimSuffix(baseURL, "/") + "/.beacon-method-probe-xq7z"

	req, err := http.NewRequestWithContext(ctx, method, probeURL, nil)
	if err != nil {
		return false, 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	resp.Body.Close()

	code := resp.StatusCode
	if code == http.StatusMethodNotAllowed || code == http.StatusNotImplemented {
		return false, code
	}

	// If a PUT succeeded (2xx), best-effort DELETE to remove any artifact created.
	if method == http.MethodPut && code >= 200 && code < 300 {
		delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, probeURL, nil)
		if err == nil {
			delReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
			delResp, err := client.Do(delReq)
			if err == nil {
				delResp.Body.Close()
			}
		}
	}

	return true, code
}
