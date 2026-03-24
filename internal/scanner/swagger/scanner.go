// Package swagger parses OpenAPI / Swagger specs exposed at common paths and
// fuzzes each discovered endpoint for validation gaps. It runs in deep mode
// only because it sends active payloads to every listed endpoint.
//
// What it checks:
//   - Whether a Swagger 2.0 or OpenAPI 3.x spec is publicly accessible
//   - For each operation in the spec, whether sending a missing required
//     parameter causes a 500 (unhandled validation error) vs. a proper 400/422
//   - Whether type-confusion inputs (string where integer expected) cause 500s
//   - Whether a simple SQL injection canary in string fields causes a 500
//     (indicating the value reaches a query without sanitisation)
//
// Surface mode only emits an informational finding for spec exposure.
// Deep mode also runs the per-endpoint fuzzing.
package swagger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "swagger"

// specPaths are common locations where Swagger/OpenAPI specs are served.
var specPaths = []string{
	"/swagger.json",
	"/swagger/v1/swagger.json",
	"/api-docs",
	"/api-docs/swagger.json",
	"/openapi.json",
	"/openapi.yaml",
	"/v1/openapi.json",
	"/v2/openapi.json",
	"/v3/openapi.json",
	"/api/swagger.json",
	"/api/openapi.json",
	"/docs/swagger.json",
	"/swagger-ui/swagger.json",
}

// openAPISpec is the minimal structure we decode from a spec to enumerate
// endpoints. We support Swagger 2.0 (paths + definitions) and OpenAPI 3.x
// (paths + components) via a unified decoder.
type openAPISpec struct {
	// Common to both versions
	Paths map[string]map[string]openAPIOperation `json:"paths"`

	// Swagger 2.0
	BasePath    string            `json:"basePath"`
	Host        string            `json:"host"`
	Definitions map[string]any    `json:"definitions"`
	Schemes     []string          `json:"schemes"`

	// OpenAPI 3.x
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
}

type openAPIOperation struct {
	Parameters []openAPIParameter `json:"parameters"`
	RequestBody *openAPIRequestBody `json:"requestBody"`
}

type openAPIParameter struct {
	Name     string `json:"name"`
	In       string `json:"in"` // query, header, path, cookie
	Required bool   `json:"required"`
	Schema   *openAPISchema `json:"schema"`
	Type     string `json:"type"` // Swagger 2.0 inline type
}

type openAPIRequestBody struct {
	Required bool `json:"required"`
	Content  map[string]struct {
		Schema *openAPISchema `json:"schema"`
	} `json:"content"`
}

type openAPISchema struct {
	Type       string            `json:"type"`
	Properties map[string]*openAPISchema `json:"properties"`
	Required   []string          `json:"required"`
}

// Scanner probes for exposed OpenAPI specs and fuzzes discovered endpoints.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	// Find a reachable spec.
	specURL, specBody := findSpec(ctx, client, base)
	if specURL == "" {
		return nil, nil
	}

	var findings []finding.Finding

	// Always emit an exposure finding regardless of scan depth.
	findings = append(findings, finding.Finding{
		CheckID:      finding.CheckSwaggerExposed,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityMedium,
		Title:        fmt.Sprintf("OpenAPI/Swagger spec publicly accessible at %s", specURL),
		Description:  "The API specification is publicly accessible. It documents all endpoints, parameters, authentication requirements, and data models — providing a complete attack map to anyone who can access it.",
		Asset:        asset,
		ProofCommand: fmt.Sprintf("curl -s %s | python3 -m json.tool | head -60", specURL),
		Evidence: map[string]any{
			"url":       specURL,
			"spec_size": len(specBody),
		},
		DiscoveredAt: time.Now(),
	})

	// Deep mode: parse spec and fuzz each endpoint.
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return findings, nil
	}

	var spec openAPISpec
	if err := json.Unmarshal(specBody, &spec); err != nil {
		// Non-JSON spec (YAML) or parse error — exposure finding is still valid.
		return findings, nil
	}

	fs := fuzzEndpoints(ctx, client, asset, base, &spec)
	findings = append(findings, fs...)
	return findings, nil
}

// findSpec probes the candidate spec paths and returns the first one that
// serves a JSON body containing "paths" (a minimal OpenAPI signal).
func findSpec(ctx context.Context, client *http.Client, base string) (string, []byte) {
	for _, path := range specPaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512 KB cap
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "text/html") {
			continue
		}
		// Must contain "paths" to be an OpenAPI spec.
		if bytes.Contains(body, []byte(`"paths"`)) {
			return u, body
		}
	}
	return "", nil
}

// fuzzEndpoints iterates over paths in the spec and sends probe requests
// designed to surface missing input validation.
func fuzzEndpoints(ctx context.Context, client *http.Client, asset, base string, spec *openAPISpec) []finding.Finding {
	var findings []finding.Finding

	// Cap total probes to avoid flooding the target.
	const maxProbes = 50
	probeCount := 0

	for path, methods := range spec.Paths {
		if probeCount >= maxProbes {
			break
		}
		for method, op := range methods {
			if probeCount >= maxProbes {
				break
			}
			method = strings.ToUpper(method)
			if method == "HEAD" || method == "OPTIONS" {
				continue
			}

			// Build the endpoint URL. Strip path params — we use literal
			// placeholder values that keep the URL valid.
			cleanPath := replacePathParams(path)
			endpointURL := base + cleanPath

			// Probe 1: missing required parameters → expect 400/422, flag 500.
			if f := probeMissingParams(ctx, client, asset, endpointURL, method, &op); f != nil {
				findings = append(findings, *f)
			}
			probeCount++

			if probeCount >= maxProbes {
				break
			}

			// Probe 2: type confusion and SQL canary in JSON body for POST/PUT/PATCH.
			if method == "POST" || method == "PUT" || method == "PATCH" {
				if f := probeTypeFuzz(ctx, client, asset, endpointURL, method, &op); f != nil {
					findings = append(findings, *f)
				}
				probeCount++
			}
		}
	}
	return findings
}

// probeMissingParams sends a request with all required parameters omitted.
// If the server returns 500, it means unhandled input validation.
func probeMissingParams(ctx context.Context, client *http.Client, asset, url, method string, op *openAPIOperation) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBufferString("{}"))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebAPIFuzz,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("API endpoint %s %s returns 500 on empty input", method, url),
		Description: fmt.Sprintf(
			"Sending an empty request body to %s %s caused a 500 Internal Server Error. "+
				"This indicates the server lacks input validation for required parameters — "+
				"uncaught exceptions may expose stack traces, framework internals, or "+
				"provide primitive for further exploitation.",
			method, url),
		Asset: asset,
		Evidence: map[string]any{
			"url":             url,
			"method":          method,
			"status_code":     resp.StatusCode,
			"response_prefix": string(body[:min(len(body), 300)]),
		},
		ProofCommand: fmt.Sprintf("curl -s -X %s %s -H 'Content-Type: application/json' -d '{}' | head -20", method, url),
		DiscoveredAt: time.Now(),
	}
}

// probeTypeFuzz sends type-confused values and a SQL injection canary.
// If the server returns 500 it suggests the input reaches a sensitive code path.
func probeTypeFuzz(ctx context.Context, client *http.Client, asset, url, method string, op *openAPIOperation) *finding.Finding {
	// Build a body that mixes type confusion (int field as string) and a SQL canary.
	payload := `{"id":"beacon'--","limit":"notanumber","q":"' OR '1'='1"}`
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBufferString(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		return nil
	}

	// Check if the response body contains SQL error indicators.
	bodyLower := strings.ToLower(string(body))
	sqlError := strings.Contains(bodyLower, "syntax error") ||
		strings.Contains(bodyLower, "sql") ||
		strings.Contains(bodyLower, "ora-") ||
		strings.Contains(bodyLower, "mysql") ||
		strings.Contains(bodyLower, "pg_query") ||
		strings.Contains(bodyLower, "sqlite")

	desc := fmt.Sprintf(
		"Sending type-confused values to %s %s caused a 500 Internal Server Error. "+
			"The server does not validate input types before processing them.",
		method, url)
	if sqlError {
		desc = fmt.Sprintf(
			"Sending a SQL injection canary to %s %s caused a 500 with SQL error indicators in the response. "+
				"The input may be reaching a database query without sanitisation.",
			method, url)
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebAPIFuzz,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("API endpoint %s %s returns 500 on type-fuzz input", method, url),
		Description: desc,
		Asset:    asset,
		Evidence: map[string]any{
			"url":             url,
			"method":          method,
			"payload":         payload,
			"status_code":     resp.StatusCode,
			"sql_error_hint":  sqlError,
			"response_prefix": string(body[:min(len(body), 300)]),
		},
		ProofCommand: fmt.Sprintf("curl -s -X %s %s -H 'Content-Type: application/json' -d '%s'", method, url, payload),
		DiscoveredAt: time.Now(),
	}
}

// replacePathParams replaces {param} placeholders with safe literal values
// so the URL is syntactically valid for HTTP requests.
func replacePathParams(path string) string {
	var out strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '{' {
			end := strings.Index(path[i:], "}")
			if end == -1 {
				out.WriteByte(path[i])
				continue
			}
			out.WriteString("1")
			i += end
			continue
		}
		out.WriteByte(path[i])
	}
	return out.String()
}

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
