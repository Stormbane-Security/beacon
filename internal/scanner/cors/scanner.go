// Package cors implements a deep-mode scanner for CORS misconfiguration.
// It probes the target with crafted Origin headers and checks whether the
// reflected Access-Control-Allow-Origin response header exposes credentials
// or allows arbitrary origins.
package cors

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanlog"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckCORSCredentialedReflection, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckCORSMisconfiguration, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckCORSNullOrigin, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckCORSPreflightMisconfig, finding.SeverityCritical, finding.ModeDeep),
	)
}
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
	log := scanlog.FromContext(ctx)

	// CORS probing is deep-mode only — surface mode is too noisy.
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	ac := authctx.HTTPClient(ctx)
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     ac.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
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
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
			_ = resp.Body.Close()
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

			probeStart := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				log.ProbeTimed(scannerName, asset, fmt.Sprintf("cors-origin(%s)", origin), time.Since(probeStart), 0, err)
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
			_ = resp.Body.Close()
			log.ProbeTimed(scannerName, asset, fmt.Sprintf("cors-origin(%s)", origin), time.Since(probeStart), resp.StatusCode, nil)

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
				// Fall through to Case 4 so the compound check can also fire.
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

			// Case 3: null origin reflected (sandbox bypass) — dedicated check ID
			if origin == "null" && strings.EqualFold(acao, "null") {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckCORSNullOrigin,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("CORS: null origin reflected on %s", asset),
					Description: fmt.Sprintf(
						"%s reflects Origin: null in Access-Control-Allow-Origin. "+
							"Sandboxed iframes and local HTML files send a null origin, allowing "+
							"attacker-controlled sandboxed pages to make cross-origin requests. "+
							"Many CORS implementations have a whitelist that incorrectly includes 'null'. "+
							"An attacker can exploit this from a sandboxed iframe: "+
							"<iframe sandbox='allow-scripts' src='data:text/html,...'>.",
						asset,
					),
					Asset: asset,
					Evidence: map[string]any{
						"url":                              target,
						"injected_origin":                  origin,
						"access_control_allow_origin":      acao,
						"access_control_allow_credentials": acac,
					},
					ProofCommand: fmt.Sprintf("curl -sI -H 'Origin: null' '%s' | grep -i 'access-control'", target),
					DiscoveredAt: time.Now(),
				})
			}

			// Case 4: compound check — origin reflected AND credentials enabled.
			// This is the most dangerous CORS misconfiguration pattern and gets its
			// own dedicated finding for triaging separately from Cases 1-3.
			if strings.EqualFold(acao, origin) && acac == "true" && origin != "null" {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckCORSCredentialedReflection,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("CORS: origin reflected with credentials enabled on %s (compound)", asset),
					Description: fmt.Sprintf(
						"%s reflects the attacker-supplied Origin %q in Access-Control-Allow-Origin and "+
							"simultaneously sets Access-Control-Allow-Credentials: true. This compound "+
							"misconfiguration allows an attacker-controlled page to make fully credentialed "+
							"cross-origin requests (with cookies, Authorization headers, and TLS client "+
							"certificates) and read the authenticated responses. This is the most dangerous "+
							"CORS misconfiguration — it enables account takeover, data exfiltration, and "+
							"CSRF bypass from any attacker-controlled domain.",
						asset, origin,
					),
					Asset: asset,
					Evidence: map[string]any{
						"url":                              target,
						"injected_origin":                  origin,
						"access_control_allow_origin":      acao,
						"access_control_allow_credentials": acac,
						"compound":                         true,
					},
					ProofCommand: fmt.Sprintf("curl -sI -H 'Origin: %s' '%s' | grep -i 'access-control'", origin, target),
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

		// Catch-all guard for the preflight probe: a framework that blindly echoes
		// CORS headers on every path (including 404s) will reflect credentials on
		// random paths. Probe 3 distinct random paths; only declare catch-all if
		// ALL 3 return credentialed CORS — a single random path matching is
		// insufficient because some error handlers legitimately set CORS headers.
		preflightIsCatchAll := false
		catchAllHits := 0
		for range 3 {
			canaryURL := fmt.Sprintf("%s/beacon-canary-%016x", target, rand.Int63())
			canaryReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, canaryURL, nil)
			if err != nil {
				break
			}
			canaryReq.Header.Set("Origin", preflightOrigin)
			canaryReq.Header.Set("Access-Control-Request-Method", "POST")
			cResp, err := client.Do(canaryReq)
			if err != nil {
				break
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(cResp.Body, 4096)) //nolint:errcheck
			_ = cResp.Body.Close()
			cacao := cResp.Header.Get("Access-Control-Allow-Origin")
			cacac := strings.ToLower(cResp.Header.Get("Access-Control-Allow-Credentials"))
			if strings.EqualFold(cacao, preflightOrigin) && cacac == "true" {
				catchAllHits++
			}
		}
		if catchAllHits == 3 {
			preflightIsCatchAll = true
		}

		if !alreadyCaught && !preflightIsCatchAll {
			// Preflight probe 1: POST + Authorization (existing check)
			preReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
			if err == nil {
				preReq.Header.Set("Origin", preflightOrigin)
				preReq.Header.Set("Access-Control-Request-Method", "POST")
				preReq.Header.Set("Access-Control-Request-Headers", "Authorization")

				pfStart1 := time.Now()
				if preResp, err := client.Do(preReq); err == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(preResp.Body, 4096)) //nolint:errcheck
					_ = preResp.Body.Close()
					log.ProbeTimed(scannerName, asset, "preflight-post-auth", time.Since(pfStart1), preResp.StatusCode, nil)

					preACAO := preResp.Header.Get("Access-Control-Allow-Origin")
					preACAC := strings.ToLower(preResp.Header.Get("Access-Control-Allow-Credentials"))

					allowsOrigin := strings.EqualFold(preACAO, preflightOrigin) || preACAO == "*"
					if allowsOrigin && preACAC == "true" {
						findings = append(findings, finding.Finding{
							CheckID:  finding.CheckCORSPreflightMisconfig,
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
								"request_method":                   "POST",
								"request_headers":                  "Authorization",
							},
							ProofCommand: fmt.Sprintf(
								"curl -sI -X OPTIONS -H 'Origin: %s' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: Authorization' '%s' | grep -i 'access-control'",
								preflightOrigin, target),
							DiscoveredAt: time.Now(),
						})
					}
				}
			}

			// Preflight probe 2: PUT + X-Custom — catches servers that allow
			// dangerous methods and custom headers via permissive preflight
			// responses. Some implementations only restrict POST but allow PUT
			// or accept any custom header prefix.
			preReq2, err := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
			if err == nil {
				preReq2.Header.Set("Origin", preflightOrigin)
				preReq2.Header.Set("Access-Control-Request-Method", "PUT")
				preReq2.Header.Set("Access-Control-Request-Headers", "X-Custom")

				pfStart2 := time.Now()
				if preResp2, err := client.Do(preReq2); err == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(preResp2.Body, 4096)) //nolint:errcheck
					_ = preResp2.Body.Close()
					log.ProbeTimed(scannerName, asset, "preflight-put-custom", time.Since(pfStart2), preResp2.StatusCode, nil)

					preACAO2 := preResp2.Header.Get("Access-Control-Allow-Origin")
					preACAC2 := strings.ToLower(preResp2.Header.Get("Access-Control-Allow-Credentials"))
					preACAM2 := preResp2.Header.Get("Access-Control-Allow-Methods")
					preACAH2 := preResp2.Header.Get("Access-Control-Allow-Headers")

					allowsOrigin2 := strings.EqualFold(preACAO2, preflightOrigin) || preACAO2 == "*"
					allowsPUT := strings.Contains(strings.ToUpper(preACAM2), "PUT") || preACAM2 == "*"
					if allowsOrigin2 && allowsPUT {
						sev := finding.SeverityHigh
						if preACAC2 == "true" {
							sev = finding.SeverityCritical
						}
						findings = append(findings, finding.Finding{
							CheckID:  finding.CheckCORSPreflightMisconfig,
							Module:   "deep",
							Scanner:  scannerName,
							Severity: sev,
							Title:    fmt.Sprintf("CORS: preflight allows PUT with custom headers on %s", asset),
							Description: fmt.Sprintf(
								"%s responded to an OPTIONS preflight requesting PUT method and X-Custom header "+
									"with Access-Control-Allow-Origin: %q and Access-Control-Allow-Methods including PUT. "+
									"This indicates the server allows dangerous cross-origin write operations. "+
									"Attackers can use PUT requests from malicious pages to modify server-side resources.",
								asset, preACAO2,
							),
							Asset: asset,
							Evidence: map[string]any{
								"url":                              target,
								"injected_origin":                  preflightOrigin,
								"access_control_allow_origin":      preACAO2,
								"access_control_allow_methods":     preACAM2,
								"access_control_allow_headers":     preACAH2,
								"access_control_allow_credentials": preACAC2,
								"via":                              "preflight",
								"request_method":                   "PUT",
								"request_headers":                  "X-Custom",
							},
							ProofCommand: fmt.Sprintf(
								"curl -sI -X OPTIONS -H 'Origin: %s' -H 'Access-Control-Request-Method: PUT' -H 'Access-Control-Request-Headers: X-Custom' '%s' | grep -i 'access-control'",
								preflightOrigin, target),
							DiscoveredAt: time.Now(),
						})
					}
				}
			}
		}

		// Preflight probe 3: header reflection — send a unique custom header
		// name and check if Access-Control-Allow-Headers reflects it back.
		// Servers that blindly echo the requested headers allow attackers to
		// send arbitrary headers cross-origin (including Authorization).
		if !alreadyCaught && !preflightIsCatchAll {
			canaryHeader := "X-Beacon-Cors-Canary"
			preReq3, err := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
			if err == nil {
				preReq3.Header.Set("Origin", preflightOrigin)
				preReq3.Header.Set("Access-Control-Request-Method", "GET")
				preReq3.Header.Set("Access-Control-Request-Headers", canaryHeader)

				pfStart3 := time.Now()
				if preResp3, err := client.Do(preReq3); err == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(preResp3.Body, 4096)) //nolint:errcheck
					_ = preResp3.Body.Close()
					log.ProbeTimed(scannerName, asset, "preflight-header-reflect", time.Since(pfStart3), preResp3.StatusCode, nil)

					preACAO3 := preResp3.Header.Get("Access-Control-Allow-Origin")
					preACAH3 := preResp3.Header.Get("Access-Control-Allow-Headers")

					allowsOrigin3 := strings.EqualFold(preACAO3, preflightOrigin) || preACAO3 == "*"
					reflectsHeader := strings.Contains(strings.ToLower(preACAH3), strings.ToLower(canaryHeader))

					if allowsOrigin3 && reflectsHeader {
						findings = append(findings, finding.Finding{
							CheckID:  finding.CheckCORSPreflightMisconfig,
							Module:   "deep",
							Scanner:  scannerName,
							Severity: finding.SeverityHigh,
							Title:    fmt.Sprintf("CORS: Access-Control-Allow-Headers reflects arbitrary headers on %s", asset),
							Description: fmt.Sprintf(
								"%s reflects the arbitrary header %q back in Access-Control-Allow-Headers. "+
									"The server blindly echoes any requested header, which means an attacker-controlled "+
									"page can send cross-origin requests with arbitrary headers including Authorization, "+
									"X-CSRF-Token, or other security-sensitive headers.",
								asset, canaryHeader,
							),
							Asset: asset,
							Evidence: map[string]any{
								"url":                            target,
								"injected_origin":                preflightOrigin,
								"access_control_allow_origin":    preACAO3,
								"access_control_allow_headers":   preACAH3,
								"canary_header":                  canaryHeader,
								"via":                            "preflight",
							},
							ProofCommand: fmt.Sprintf(
								"curl -sI -X OPTIONS -H 'Origin: %s' -H 'Access-Control-Request-Method: GET' -H 'Access-Control-Request-Headers: %s' '%s' | grep -i 'access-control'",
								preflightOrigin, canaryHeader, target),
							DiscoveredAt: time.Now(),
						})
					}
				}
			}
		}
	}

	return findings, nil
}
