// Package secondorder detects second-order injection vulnerabilities.
//
// Second-order injection: inject a payload in endpoint A, observe it executing
// in endpoint B. Example: register with username `<script>alert(1)</script>`.
// The admin panel that lists users renders the username without escaping,
// creating stored XSS.
//
// Algorithm:
//  1. Discover input endpoints from crawl results (forms, API POST endpoints).
//  2. Discover output endpoints (pages that display user-generated content:
//     profile pages, admin panels, search results, logs).
//  3. For each input endpoint, inject a unique canary string.
//  4. For each output endpoint, check if the canary appears in the response.
//  5. If the canary appears, upgrade to actual payloads (XSS, SQLi).
//  6. If a payload reflects/executes → second-order injection confirmed.
//
// ScanAuthorized only — this scanner injects payloads into real application state.
package secondorder

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckSecondOrderXSS, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckSecondOrderSQLi, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckSecondOrderReflection, finding.SeverityHigh, finding.ModeDeep),
	)
}

const (
	scannerName = "secondorder"
	maxBodyRead = 128 * 1024 // 128 KB
)

// inputPaths are common endpoints that accept user input via POST.
var inputPaths = []string{
	"/register",
	"/profile/edit",
	"/feedback",
	"/contact",
	"/comment",
	"/api/users",
	"/api/v1/users",
	"/api/comments",
	"/api/v1/comments",
	"/api/feedback",
}

// outputPaths are common endpoints that display user-generated content.
var outputPaths = []string{
	"/admin/users",
	"/admin/logs",
	"/profile/1",
	"/search",
	"/dashboard",
	"/feed",
	"/api/users",
	"/api/v1/users",
	"/api/comments",
	"/api/v1/comments",
}

// inputFields are common form field names used to inject the canary.
var inputFields = []string{
	"username", "name", "email", "comment", "message",
	"feedback", "title", "description", "bio", "content",
}

// xssPayloads are XSS payloads to test after canary reflection.
var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`<img src=x onerror=alert(1)>`,
	`"><script>alert(1)</script>`,
}

// sqliPayloads are SQLi payloads to test after canary reflection.
var sqliPayloads = []string{
	`' OR '1'='1`,
	`'; DROP TABLE users;--`,
	`" OR "1"="1`,
}

// Scanner detects second-order injection vulnerabilities.
type Scanner struct {
	client *http.Client
}

// New returns a new Scanner with default settings.
func New() *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 -- security scanner must accept any cert
				},
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// NewWithClient creates a Scanner using the provided HTTP client.
// Intended for testing so a custom client can be injected.
func NewWithClient(client *http.Client) *Scanner {
	return &Scanner{client: client}
}

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the second-order injection scan. Only runs in authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	base := schemedetect.Base(ctx, s.client, asset)

	var findings []finding.Finding

	// Phase 1: For each input endpoint, inject a unique canary and check
	// all output endpoints for reflection.
	for _, inputPath := range inputPaths {
		if ctx.Err() != nil {
			break
		}

		canary := generateCanary()

		// Try injecting the canary via POST with form fields.
		injected := s.injectCanary(ctx, base, inputPath, canary)
		if !injected {
			continue
		}

		// Phase 2: Check each output endpoint for canary reflection.
		for _, outputPath := range outputPaths {
			if ctx.Err() != nil {
				break
			}

			body := s.fetchBody(ctx, base, outputPath)
			if body == "" {
				continue
			}

			if !strings.Contains(body, canary) {
				continue
			}

			// Canary reflected — this is at minimum a second-order reflection.
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckSecondOrderReflection,
				Module:   "authorized",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Second-order reflection: %s → %s", inputPath, outputPath),
				Description: fmt.Sprintf(
					"A unique canary injected via POST to %s was found reflected in the "+
						"response of %s. This confirms user input from one endpoint is rendered "+
						"in another without sanitization, creating a second-order injection vector.",
					inputPath, outputPath),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -sk -X POST '%s%s' -d 'username=BEACON_TEST_CANARY' && curl -sk '%s%s' | grep BEACON_TEST_CANARY`,
					base, inputPath, base, outputPath),
				Evidence: map[string]any{
					"input_endpoint":  inputPath,
					"output_endpoint": outputPath,
					"canary":          canary,
				},
				Confidence:   finding.ConfidenceVerified,
				DiscoveredAt: time.Now(),
			})

			// Phase 3: Upgrade to real payloads.
			xssFound := s.testPayloads(ctx, base, inputPath, outputPath, xssPayloads)
			if xssFound != "" {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckSecondOrderXSS,
					Module:   "authorized",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("Second-order XSS: %s → %s", inputPath, outputPath),
					Description: fmt.Sprintf(
						"A stored XSS payload injected via POST to %s was found rendered "+
							"unescaped in the response of %s. An attacker can inject JavaScript "+
							"that executes in the browser of any user viewing %s.",
						inputPath, outputPath, outputPath),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -sk -X POST '%s%s' -d 'username=<script>alert(1)</script>' && curl -sk '%s%s'`,
						base, inputPath, base, outputPath),
					Evidence: map[string]any{
						"input_endpoint":  inputPath,
						"output_endpoint": outputPath,
						"payload":         xssFound,
					},
					Confidence:   finding.ConfidenceVerified,
					DiscoveredAt: time.Now(),
				})
			}

			sqliFound := s.testPayloads(ctx, base, inputPath, outputPath, sqliPayloads)
			if sqliFound != "" {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckSecondOrderSQLi,
					Module:   "authorized",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("Second-order SQLi: %s → %s", inputPath, outputPath),
					Description: fmt.Sprintf(
						"A SQL injection payload injected via POST to %s was found reflected "+
							"in the response of %s. This may indicate the stored input is used "+
							"in SQL queries without parameterization when building %s.",
						inputPath, outputPath, outputPath),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -sk -X POST '%s%s' -d "username=' OR '1'='1" && curl -sk '%s%s'`,
						base, inputPath, base, outputPath),
					Evidence: map[string]any{
						"input_endpoint":  inputPath,
						"output_endpoint": outputPath,
						"payload":         sqliFound,
					},
					Confidence:   finding.ConfidenceVerified,
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// injectCanary POSTs the canary value to the input endpoint using common
// form field names. Returns true if any POST returned a non-error status.
func (s *Scanner) injectCanary(ctx context.Context, base, inputPath, canary string) bool {
	for _, field := range inputFields {
		if ctx.Err() != nil {
			return false
		}

		data := url.Values{}
		data.Set(field, canary)

		status := s.postForm(ctx, base+inputPath, data)
		// Accept any non-error response as a successful injection attempt.
		// 200, 201, 302 (redirect after submit) all indicate the form processed.
		if status >= 200 && status < 400 {
			return true
		}
	}
	return false
}

// testPayloads injects each payload via the input endpoint and checks the
// output endpoint for reflection. Returns the first reflected payload, or "".
func (s *Scanner) testPayloads(ctx context.Context, base, inputPath, outputPath string, payloads []string) string {
	for _, payload := range payloads {
		if ctx.Err() != nil {
			return ""
		}

		for _, field := range inputFields {
			data := url.Values{}
			data.Set(field, payload)

			status := s.postForm(ctx, base+inputPath, data)
			if status < 200 || status >= 400 {
				continue
			}

			body := s.fetchBody(ctx, base, outputPath)
			if strings.Contains(body, payload) {
				return payload
			}
		}
	}
	return ""
}

// postForm sends a POST request with form-encoded data and returns the status code.
func (s *Scanner) postForm(ctx context.Context, rawURL string, data url.Values) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// fetchBody GETs the given path and returns the response body as a string.
func (s *Scanner) fetchBody(ctx context.Context, base, path string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}
	return string(body)
}

// generateCanary creates a unique canary string for injection tracking.
func generateCanary() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("BEACON_2ND_ORDER_%x", b)
}
