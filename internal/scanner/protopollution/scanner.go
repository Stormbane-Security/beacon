// Package protopollution detects Node.js prototype pollution in JSON API endpoints.
// It posts prototype-polluting payloads and then checks whether the injected
// property is reflected in a subsequent GET response.
//
// Active exploitation probes require ScanAuthorized mode (--authorized flag).
// ScanAuthorized only (active payloads).
package protopollution

import (
	"bytes"
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
	scannerName  = "protopollution"
	maxBodySize  = 32 * 1024 // 32 KB
	probeMarker  = "beacon_pp_test"
)

// apiPaths are JSON API endpoints commonly found in Node.js applications.
var apiPaths = []string{
	"/api",
	"/api/v1",
	"/api/v2",
	"/api/v1/users",
	"/api/v1/data",
	"/api/data",
	"/api/config",
	"/api/settings",
	"/api/info",
}

// pollutionPayloads are the JSON bodies used to attempt prototype pollution.
var pollutionPayloads = []struct {
	body  string
	label string
}{
	{
		body:  `{"__proto__":{"` + probeMarker + `":true}}`,
		label: "__proto__",
	},
	{
		body:  `{"constructor":{"prototype":{"` + probeMarker + `":true}}}`,
		label: "constructor.prototype",
	},
}

// Scanner detects prototype pollution in JSON API endpoints.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the prototype pollution scan. Only runs in deep mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Exploitation probes require --authorized (beyond --deep).
	if scanType != module.ScanAuthorized {
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

	for _, path := range apiPaths {
		for _, payload := range pollutionPayloads {
			// POST the pollution payload.
			postURL := base + path
			postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL,
				bytes.NewBufferString(payload.body))
			if err != nil {
				continue
			}
			postReq.Header.Set("Content-Type", "application/json")
			postReq.Header.Set("Accept", "application/json")

			postResp, err := client.Do(postReq)
			if err != nil {
				if postResp != nil {
					postResp.Body.Close()
				}
				continue
			}
			io.Copy(io.Discard, io.LimitReader(postResp.Body, maxBodySize)) //nolint:errcheck
			postResp.Body.Close()

			// Only proceed if the endpoint accepted the POST (2xx or 3xx).
			if postResp.StatusCode < 200 || postResp.StatusCode >= 400 {
				continue
			}

			// GET the same endpoint and check for the marker in the response.
			getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, postURL, nil)
			if err != nil {
				continue
			}
			getReq.Header.Set("Accept", "application/json")

			getResp, err := client.Do(getReq)
			if err != nil {
				if getResp != nil {
					getResp.Body.Close()
				}
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(getResp.Body, maxBodySize))
			getResp.Body.Close()

			if !strings.Contains(string(body), probeMarker) {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebPrototypePollution,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title: fmt.Sprintf(
					"Prototype Pollution (%s) detected on %s%s",
					payload.label, asset, path),
				Description: fmt.Sprintf(
					"The endpoint %s accepted a JSON POST body containing a %q prototype "+
						"pollution payload and the injected property %q was subsequently "+
						"visible in a GET response. This indicates the application merges "+
						"untrusted JSON into a shared prototype, enabling an attacker to "+
						"inject arbitrary properties onto Object.prototype and potentially "+
						"bypass security controls or achieve remote code execution in "+
						"Node.js applications that use vulnerable prototype-aware sinks.",
					postURL, payload.label, probeMarker),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -s -X POST -H 'Content-Type: application/json' -d '{"__proto__":{"beacon_pp_test":true}}' https://%s%s && curl -s https://%s%s | grep beacon_pp_test`,
					asset, path, asset, path),
				Evidence: map[string]any{
					"url":     postURL,
					"path":    path,
					"payload": payload.body,
					"label":   payload.label,
					"marker":  probeMarker,
				},
				DiscoveredAt: time.Now(),
			})

			// One finding per path is enough.
			break
		}
	}

	return findings, nil
}

// detectScheme tries HTTPS first, falling back to HTTP.
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
