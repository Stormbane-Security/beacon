// Package cors implements a deep-mode scanner for CORS misconfiguration.
// It probes the target with crafted Origin headers and checks whether the
// reflected Access-Control-Allow-Origin response header exposes credentials
// or allows arbitrary origins.
package cors

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// altPorts are common non-standard ports to probe when the asset is a bare
// hostname. CORS misconfigurations frequently appear on development/staging
// servers that run on these ports rather than standard 80/443.
var altPorts = []struct {
	scheme string
	port   string
}{
	{"https", "443"},
	{"http", "80"},
	{"https", "8443"},
	{"http", "8080"},
	{"http", "3000"},
	{"http", "4000"},
	{"http", "5000"},
}

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

	// Build the list of targets to probe.
	// If the asset already includes a port (hostname:port), use it directly with
	// both https and http schemes. If it's a bare hostname, probe the standard
	// ports plus common non-standard ones where CORS misconfigs frequently appear.
	var targets []string
	if strings.Contains(asset, ":") {
		// Explicit port — try both schemes against the provided host:port.
		targets = []string{"https://" + asset, "http://" + asset}
	} else {
		for _, ap := range altPorts {
			var u string
			if ap.port == "443" || ap.port == "80" {
				// Standard ports: omit port number from URL for cleaner output.
				u = ap.scheme + "://" + asset
			} else {
				u = ap.scheme + "://" + asset + ":" + ap.port
			}
			// Quick reachability check — skip unreachable targets to keep scan fast.
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			targets = append(targets, u)
		}
	}

	var findings []finding.Finding

	for _, target := range targets {
		for _, origin := range probeOrigins {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Origin", origin)

			resp, err := client.Do(req)
			if err != nil {
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
						"url":                              target,
						"injected_origin":                  origin,
						"access_control_allow_origin":      acao,
						"access_control_allow_credentials": acac,
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

		// Preflight check per target: OPTIONS probe with a dangerous Origin to
		// catch misconfigs the simple GET probes above may have missed.
		preflightOrigin := "https://evil.example.com"

		// Skip the preflight probe if GET probes already found a Critical or High
		// CORS finding for this target — the preflight would be redundant.
		alreadyCaught := false
		for _, f := range findings {
			if f.Evidence["url"] == target &&
				(f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh) {
				alreadyCaught = true
				break
			}
		}

		// Catch-all guard for the preflight probe: if a random path returns 200
		// with credentialed CORS, this server echoes headers for every path and the
		// preflight would be a false positive. GET probes above already fired on
		// the real path, so we only gate the OPTIONS probe here.
		preflightIsCatchAll := false
		canaryURL := fmt.Sprintf("%s/beacon-canary-%016x", target, rand.Int63())
		canaryReq, _ := http.NewRequestWithContext(ctx, http.MethodOptions, canaryURL, nil)
		if canaryReq != nil {
			canaryReq.Header.Set("Origin", preflightOrigin)
			canaryReq.Header.Set("Access-Control-Request-Method", "POST")
			if cResp, err := client.Do(canaryReq); err == nil {
				cResp.Body.Close()
				cacao := cResp.Header.Get("Access-Control-Allow-Origin")
				cacac := strings.ToLower(cResp.Header.Get("Access-Control-Allow-Credentials"))
				// A catch-all returns 200 + reflects origin + credentials on random paths.
				if cResp.StatusCode == 200 && strings.EqualFold(cacao, preflightOrigin) && cacac == "true" {
					preflightIsCatchAll = true
				}
			}
		}

		if !alreadyCaught && !preflightIsCatchAll {
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
	}

	return findings, nil
}
