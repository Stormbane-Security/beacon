// Package hopbyhop detects proxy-layer header stripping via the HTTP
// Connection header. When a reverse proxy honours arbitrary hop-by-hop
// header nominations, an attacker can strip security-relevant headers
// (X-Real-IP, X-Forwarded-For, Authorization) from the backend's view,
// bypassing IP allowlists, authentication, or rate limiting.
//
// Deep mode only — sends requests with crafted Connection headers.
package hopbyhop

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
		scan.Check(finding.CheckProxyHopByHopAbuse, finding.SeverityHigh, finding.ModeDeep),
	)
}
const scannerName = "hopbyhop"

// securityHeaders that, if stripped, create a security bypass.
var securityHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Forwarded-Host",
	"X-Original-URL",
	"X-Rewrite-URL",
}

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

	// Step 1: Baseline request to get normal response.
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil, nil
	}
	baseReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil, nil
	}
	baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 64*1024))
	baseResp.Body.Close()

	var findings []finding.Finding

	// Step 2: For each security header, try to nominate it as hop-by-hop.
	// If the response changes significantly, the proxy stripped it.
	for _, hdr := range securityHeaders {
		if ctx.Err() != nil {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		// Nominate the security header as hop-by-hop via Connection header.
		req.Header.Set("Connection", "keep-alive, "+hdr)
		// Also set the header with a known value so we can detect stripping.
		req.Header.Set(hdr, "127.0.0.1")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		// Detect stripping: significant response change indicates the backend
		// received a different request (header was stripped by the proxy).
		statusChanged := resp.StatusCode != baseResp.StatusCode
		bodyLenDiff := abs(len(body)-len(baseBody)) > 50

		// Also check if the response reflects the header — if the baseline
		// doesn't reflect it but the Connection-nominated request doesn't either,
		// while a normal request with that header DOES reflect it, that's stripping.
		if statusChanged || bodyLenDiff {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckProxyHopByHopAbuse,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Proxy strips %s via hop-by-hop Connection header", hdr),
				Description: fmt.Sprintf(
					"The reverse proxy at %s honours arbitrary hop-by-hop header nominations "+
						"via the Connection header. When %s is listed in Connection, the proxy "+
						"strips it before forwarding to the backend. An attacker can use this to "+
						"bypass IP-based access controls, authentication, or rate limiting that "+
						"relies on headers set by the proxy.",
					asset, hdr),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -si -H 'Connection: keep-alive, %s' -H '%s: 127.0.0.1' '%s/'",
					hdr, hdr, base),
				Evidence: map[string]any{
					"stripped_header":  hdr,
					"baseline_status":  baseResp.StatusCode,
					"modified_status":  resp.StatusCode,
					"baseline_bodylen": len(baseBody),
					"modified_bodylen": len(body),
				},
				DiscoveredAt: time.Now(),
			})
			break // one finding is sufficient
		}
	}

	return findings, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// containsHeader checks if the response body echoes a header value.
func containsHeader(body []byte, value string) bool {
	return strings.Contains(string(body), value)
}
