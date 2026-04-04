// Package h2c detects HTTP/2 Cleartext (h2c) upgrade support on reverse proxies.
// When a proxy accepts the Upgrade: h2c header and returns 101 Switching Protocols,
// it establishes an unmanaged TCP tunnel that bypasses proxy-level access controls,
// WAF rules, and authentication checks.
//
// Deep mode only — sends an Upgrade request.
package h2c

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebH2CSmuggling, finding.SeverityHigh, finding.ModeDeep),
	)
}
const scannerName = "h2c"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)

	// Send an HTTP/1.1 request with Upgrade: h2c headers.
	// If the proxy responds with 101 Switching Protocols, it accepts h2c upgrade.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
	req.Header.Set("HTTP2-Settings", "AAMAAABkAAQCAAAAAAIAAAAA") // base64 encoded SETTINGS frame
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	// Check for 101 Switching Protocols — confirms h2c upgrade accepted.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		upgrade := resp.Header.Get("Upgrade")
		return []finding.Finding{{
			CheckID:  finding.CheckWebH2CSmuggling,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    "HTTP/2 Cleartext (h2c) upgrade accepted — proxy bypass possible",
			Description: fmt.Sprintf(
				"The server at %s accepts HTTP/2 Cleartext upgrade requests (Upgrade: h2c) "+
					"and responds with 101 Switching Protocols. When a reverse proxy forwards "+
					"this upgrade, it establishes an unmanaged TCP tunnel to the backend, "+
					"bypassing all proxy-level security controls (WAF rules, authentication, "+
					"access controls, rate limiting). An attacker can smuggle requests through "+
					"this tunnel directly to the backend.",
				asset),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -si -H 'Upgrade: h2c' -H 'Connection: Upgrade, HTTP2-Settings' -H 'HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA' '%s/'",
				base),
			Evidence: map[string]any{
				"status":         resp.StatusCode,
				"upgrade_header": upgrade,
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	// Also check: some proxies accept the upgrade but return 200 instead of 101,
	// with the Upgrade header reflected.
	if resp.StatusCode == http.StatusOK {
		upgrade := strings.ToLower(resp.Header.Get("Upgrade"))
		if strings.Contains(upgrade, "h2c") {
			return []finding.Finding{{
				CheckID:  finding.CheckWebH2CSmuggling,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    "Server reflects h2c Upgrade header — potential proxy bypass",
				Description: fmt.Sprintf(
					"The server at %s reflects the Upgrade: h2c header in its response, "+
						"indicating it may support HTTP/2 Cleartext upgrade. This can allow "+
						"proxy bypass via h2c smuggling.",
					asset),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -si -H 'Upgrade: h2c' '%s/'", base),
				Evidence: map[string]any{
					"status":         resp.StatusCode,
					"upgrade_header": resp.Header.Get("Upgrade"),
					"body_snippet":   string(body[:min(len(body), 200)]),
				},
				DiscoveredAt: time.Now(),
			}}, nil
		}
	}

	return nil, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
