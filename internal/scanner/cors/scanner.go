// Package cors implements a deep-mode scanner for CORS misconfiguration.
// It probes the target with crafted Origin headers and checks whether the
// reflected Access-Control-Allow-Origin response header exposes credentials
// or allows arbitrary origins.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "cors"

// Scanner probes for CORS misconfigurations.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// probeOrigins are Origin values we inject to test for reflection.
// evil.com tests arbitrary-origin reflection; null tests null-origin bypass.
var probeOrigins = []string{
	"https://evil.com",
	"null",
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// CORS probing is deep-mode only — surface mode is too noisy.
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Detect the working scheme once — avoids a wasted TLS handshake attempt on
	// every origin iteration for HTTP-only targets.
	scheme := "https"
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err == nil {
		if r, e := client.Do(probe); e != nil {
			if r != nil {
				r.Body.Close()
			}
			scheme = "http"
		} else {
			r.Body.Close()
		}
	}
	target := scheme + "://" + asset
	var findings []finding.Finding

	for _, origin := range probeOrigins {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)

		resp, err := client.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

		if acao == "" {
			continue
		}

		// Case 1: arbitrary origin reflected back with credentials
		if strings.EqualFold(acao, origin) && acac == "true" {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckCORSMisconfiguration,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("CORS: arbitrary origin reflected with credentials on %s", asset),
				Description: fmt.Sprintf(
					"%s reflects the injected Origin %q in Access-Control-Allow-Origin with "+
						"Access-Control-Allow-Credentials: true. An attacker-controlled page can make "+
						"credentialed cross-origin requests and read authenticated responses.",
					asset, origin,
				),
				Asset: asset,
				Evidence: map[string]any{
					"url":                               target,
					"injected_origin":                   origin,
					"access_control_allow_origin":       acao,
					"access_control_allow_credentials":  acac,
				},
				ProofCommand: fmt.Sprintf("curl -sI -H 'Origin: %s' '%s' | grep -i 'access-control'", origin, target),
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Case 2: wildcard with credentials (invalid but some servers do it)
		if acao == "*" && acac == "true" {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckCORSMisconfiguration,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("CORS: wildcard origin with credentials on %s", asset),
				Description: fmt.Sprintf(
					"%s returns Access-Control-Allow-Origin: * combined with "+
						"Access-Control-Allow-Credentials: true. While browsers reject this combination, "+
						"it indicates a misconfigured CORS policy that may behave unexpectedly.",
					asset,
				),
				Asset: asset,
				Evidence: map[string]any{
					"url":                              target,
					"access_control_allow_origin":      acao,
					"access_control_allow_credentials": acac,
				},
				ProofCommand: fmt.Sprintf("curl -sI -H 'Origin: https://evil.com' '%s' | grep -i 'access-control'", target),
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Case 3: null origin reflected (sandbox bypass)
		if origin == "null" && strings.EqualFold(acao, "null") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckCORSMisconfiguration,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("CORS: null origin reflected on %s", asset),
				Description: fmt.Sprintf(
					"%s reflects Origin: null in Access-Control-Allow-Origin. "+
						"Sandboxed iframes and local HTML files send a null origin, allowing "+
						"attacker-controlled sandboxed pages to make cross-origin requests.",
					asset,
				),
				Asset: asset,
				Evidence: map[string]any{
					"url":                         target,
					"injected_origin":             origin,
					"access_control_allow_origin": acao,
				},
				ProofCommand: fmt.Sprintf("curl -sI -H 'Origin: null' '%s' | grep -i 'access-control'", target),
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Preflight check: send an OPTIONS preflight with a dangerous Origin and
	// Access-Control-Request-Method to detect misconfigured preflight responses
	// that the simple GET probes above may have missed.
	preflightOrigin := "https://evil.example.com"

	// Only run the preflight check if the simple GET probes didn't already
	// emit a finding for this origin/wildcard combination.
	alreadyCaught := false
	for _, f := range findings {
		if ev, ok := f.Evidence["injected_origin"]; ok && ev == preflightOrigin {
			alreadyCaught = true
			break
		}
		if ev, ok := f.Evidence["access_control_allow_origin"]; ok && ev == "*" {
			alreadyCaught = true
			break
		}
	}

	if !alreadyCaught {
		preReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
		if err == nil {
			preReq.Header.Set("Origin", preflightOrigin)
			preReq.Header.Set("Access-Control-Request-Method", "POST")
			preReq.Header.Set("Access-Control-Request-Headers", "Authorization")

			if preResp, err := client.Do(preReq); err == nil {
				preResp.Body.Close()

				preACAO := preResp.Header.Get("Access-Control-Allow-Origin")
				preACAC := strings.ToLower(preResp.Header.Get("Access-Control-Allow-Credentials"))

				allowsOrigin := strings.EqualFold(preACAO, preflightOrigin) || preACAO == "*"
				if allowsOrigin && preACAC == "true" {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckCORSMisconfiguration,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityCritical,
						Title:    fmt.Sprintf("CORS: preflight misconfiguration allows credentialed cross-origin requests on %s", asset),
						Description: fmt.Sprintf(
							"%s responded to an OPTIONS preflight with Access-Control-Allow-Origin: %q and "+
								"Access-Control-Allow-Credentials: true. This was found via a preflight probe "+
								"(Origin: %s, Access-Control-Request-Method: POST, Access-Control-Request-Headers: Authorization). "+
								"An attacker-controlled page can make credentialed POST requests and read the responses.",
							asset, preACAO, preflightOrigin,
						),
						Asset: asset,
						Evidence: map[string]any{
							"url":                              target,
							"injected_origin":                  preflightOrigin,
							"access_control_allow_origin":      preACAO,
							"access_control_allow_credentials": preACAC,
							"via":                              "preflight",
						},
						ProofCommand: fmt.Sprintf(
							"curl -sI -X OPTIONS -H 'Origin: %s' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: Authorization' '%s' | grep -i 'access-control'",
							preflightOrigin, target),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}
