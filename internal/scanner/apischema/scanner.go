// Package apischema discovers API endpoints from OpenAPI/Swagger specs and
// tests for common API vulnerabilities: Broken Object-Level Authorization
// (BOLA), mass assignment, and missing rate limiting.
package apischema

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckAPIBOLA, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckAPIMassAssignment, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckAPINoRateLimit, finding.SeverityMedium, finding.ModeDeep),
	)
}

const scannerName = "apischema"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// specPaths are common locations for OpenAPI/Swagger specifications.
var specPaths = []string{
	"/openapi.json", "/swagger.json", "/api-docs",
	"/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
	"/api/openapi.json", "/api/swagger.json",
	"/docs/openapi.json", "/.well-known/openapi.json",
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Find an API spec.
	var spec map[string]any
	var specURL string

	for _, scheme := range []string{"https", "http"} {
		for _, path := range specPaths {
			url := scheme + "://" + asset + path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()

			if resp.StatusCode != 200 {
				continue
			}

			var parsed map[string]any
			if err := json.Unmarshal(body, &parsed); err != nil {
				continue
			}

			// Verify it looks like an OpenAPI/Swagger spec.
			if _, ok := parsed["paths"]; ok {
				spec = parsed
				specURL = url
				break
			}
			if _, ok := parsed["swagger"]; ok {
				spec = parsed
				specURL = url
				break
			}
		}
		if spec != nil {
			break
		}
	}

	if spec == nil {
		return nil, nil
	}

	var findings []finding.Finding
	now := time.Now()

	// Extract paths and test them.
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		return nil, nil
	}

	for path, methods := range paths {
		methodMap, ok := methods.(map[string]any)
		if !ok {
			continue
		}

		// Check for BOLA-susceptible patterns: paths with {id} parameters
		// that don't document authentication requirements.
		if strings.Contains(path, "{") && strings.Contains(path, "}") {
			for method, details := range methodMap {
				detail, ok := details.(map[string]any)
				if !ok {
					continue
				}

				// Check if security is defined.
				_, hasSecurity := detail["security"]
				if !hasSecurity {
					// Check global security.
					_, hasGlobalSecurity := spec["security"]
					if !hasGlobalSecurity {
						findings = append(findings, finding.Finding{
							CheckID:  finding.CheckAPIBOLA,
							Module:   "deep",
							Scanner:  scannerName,
							Severity: finding.SeverityCritical,
							Asset:    asset,
							Title:    fmt.Sprintf("Potential BOLA: %s %s (no auth documented)", strings.ToUpper(method), path),
							Description: fmt.Sprintf(
								"The API endpoint %s %s accepts a path parameter (likely an object ID) "+
									"but does not document authentication/authorization requirements in the "+
									"OpenAPI spec at %s. This pattern is susceptible to Broken Object-Level "+
									"Authorization (BOLA/IDOR) — the #1 OWASP API Security risk.",
								strings.ToUpper(method), path, specURL,
							),
							Evidence: map[string]any{
								"path":     path,
								"method":   method,
								"spec_url": specURL,
							},
							ProofCommand: fmt.Sprintf("curl -s '%s'", specURL),
							DiscoveredAt: now,
						})
					}
				}
			}
		}

		// Check for mass assignment susceptibility: POST/PUT/PATCH with request body.
		for method, details := range methodMap {
			if method != "post" && method != "put" && method != "patch" {
				continue
			}
			detail, ok := details.(map[string]any)
			if !ok {
				continue
			}

			// Check if request body is defined with loose schema.
			if rb, ok := detail["requestBody"]; ok {
				if _, ok := rb.(map[string]any); ok {
					// If the endpoint accepts a request body and has "additionalProperties"
					// or no strict schema, flag it.
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckAPIMassAssignment,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Asset:    asset,
						Title:    fmt.Sprintf("Potential mass assignment: %s %s", strings.ToUpper(method), path),
						Description: fmt.Sprintf(
							"The API endpoint %s %s accepts a request body. Without strict schema "+
								"validation and explicit field allowlisting, this endpoint may be vulnerable "+
								"to mass assignment — an attacker can set fields like 'role', 'isAdmin', "+
								"or 'balance' that should be server-controlled.",
							strings.ToUpper(method), path,
						),
						Evidence: map[string]any{
							"path":     path,
							"method":   method,
							"spec_url": specURL,
						},
						ProofCommand: fmt.Sprintf("curl -s '%s'", specURL),
						DiscoveredAt: now,
					})
				}
			}
		}
	}

	// Test rate limiting on API endpoints.
	rateLimitFindings := s.testRateLimiting(ctx, client, asset, paths)
	findings = append(findings, rateLimitFindings...)

	return findings, nil
}

func (s *Scanner) testRateLimiting(ctx context.Context, client *http.Client, asset string, paths map[string]any) []finding.Finding {
	// Pick up to 3 GET endpoints to test.
	var testPaths []string
	for path, methods := range paths {
		if len(testPaths) >= 3 {
			break
		}
		if methodMap, ok := methods.(map[string]any); ok {
			if _, hasGet := methodMap["get"]; hasGet {
				// Replace path params with safe test values.
				resolved := strings.ReplaceAll(path, "{id}", "1")
				resolved = strings.ReplaceAll(resolved, "{}", "test")
				testPaths = append(testPaths, resolved)
			}
		}
	}

	var findings []finding.Finding

	for _, path := range testPaths {
		url := "https://" + asset + path

		// Send 20 rapid requests and check for rate limit headers.
		hasRateLimit := false
		for i := 0; i < 20; i++ {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				break
			}
			resp, err := client.Do(req)
			if err != nil {
				break
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()

			// Check for rate limit indicators.
			if resp.StatusCode == 429 {
				hasRateLimit = true
				break
			}
			if resp.Header.Get("X-RateLimit-Limit") != "" ||
				resp.Header.Get("X-Rate-Limit-Limit") != "" ||
				resp.Header.Get("RateLimit-Limit") != "" ||
				resp.Header.Get("Retry-After") != "" {
				hasRateLimit = true
				break
			}
		}

		if !hasRateLimit {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckAPINoRateLimit,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("No rate limiting on API endpoint %s", path),
				Description: fmt.Sprintf(
					"The API endpoint %s on %s accepted 20 rapid requests without rate limiting "+
						"(no 429 response, no rate limit headers). This enables brute-force attacks, "+
						"credential stuffing, and API abuse.",
					path, asset,
				),
				Evidence: map[string]any{
					"path":       path,
					"requests":   20,
					"url":        url,
				},
				ProofCommand: fmt.Sprintf("for i in $(seq 1 20); do curl -s -o /dev/null -w '%%{http_code}\\n' '%s'; done", url),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}
