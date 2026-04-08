// Package osv queries the OSV.dev vulnerability database.
//
// OSV (Open Source Vulnerabilities) is Google's free, open vulnerability
// database covering npm, PyPI, Go, RubyGems, crates.io, Maven, NuGet,
// Packagist, and more. No API key required.
//
// This client uses the batch query endpoint to check multiple packages
// in a single HTTP request, keeping scan-time overhead minimal.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	batchURL     = "https://api.osv.dev/v1/querybatch"
	maxBatchSize = 1000 // OSV API limit
)

// Client queries the OSV vulnerability database.
type Client struct {
	httpClient *http.Client
	baseURL    string // overridable for testing
}

// New creates an OSV client with sensible defaults.
func New() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    batchURL,
	}
}

// NewWithHTTPClient creates an OSV client with a custom HTTP client (for testing).
func NewWithHTTPClient(client *http.Client, baseURL string) *Client {
	return &Client{
		httpClient: client,
		baseURL:    baseURL,
	}
}

// PackageQuery identifies a package to check for vulnerabilities.
type PackageQuery struct {
	Name      string // package name (e.g., "express", "lodash")
	Version   string // installed version (e.g., "4.17.1")
	Ecosystem string // OSV ecosystem: "npm", "PyPI", "Go", "RubyGems", "Packagist"
}

// Vulnerability is a single vulnerability affecting a package.
type Vulnerability struct {
	ID       string   `json:"id"`       // OSV ID (e.g., "GHSA-xxxx-xxxx-xxxx")
	Aliases  []string `json:"aliases"`  // alternate IDs (e.g., ["CVE-2024-29041"])
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"` // normalized: "critical", "high", "medium", "low"

	// FixedVersion is the earliest version that fixes this vulnerability.
	// Empty if no fix is available.
	FixedVersion string `json:"fixed_version,omitempty"`
}

// PackageResult is the vulnerability result for a single package query.
type PackageResult struct {
	Query           PackageQuery    // the original query
	Vulnerabilities []Vulnerability // vulnerabilities affecting this version
	Error           string          // non-empty if the query failed
}

// QueryBatch checks multiple packages for known vulnerabilities in a single request.
// Returns one PackageResult per input query, in the same order.
func (c *Client) QueryBatch(ctx context.Context, queries []PackageQuery) ([]PackageResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	results := make([]PackageResult, len(queries))
	for i := range results {
		results[i].Query = queries[i]
	}

	// Process in chunks of maxBatchSize.
	for start := 0; start < len(queries); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(queries) {
			end = len(queries)
		}

		chunk := queries[start:end]
		chunkResults, err := c.queryChunk(ctx, chunk)
		if err != nil {
			// Mark all queries in this chunk as errored.
			for i := start; i < end; i++ {
				results[i].Error = err.Error()
			}
			continue
		}

		for i, cr := range chunkResults {
			results[start+i].Vulnerabilities = cr
		}
	}

	return results, nil
}

// EcosystemName maps internal ecosystem names to OSV's expected values.
func EcosystemName(ecosystem string) string {
	return osvEcosystem(ecosystem)
}

// osvEcosystem maps our ecosystem names to OSV's expected values.
func osvEcosystem(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "go":
		return "Go"
	case "ruby":
		return "RubyGems"
	case "composer":
		return "Packagist"
	default:
		return ecosystem
	}
}

// ── OSV API types ────────────────────────────────────────────────────────

type batchRequest struct {
	Queries []queryEntry `json:"queries"`
}

type queryEntry struct {
	Package packageSpec `json:"package"`
	Version string      `json:"version"`
}

type packageSpec struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []batchResultEntry `json:"results"`
}

type batchResultEntry struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string       `json:"id"`
	Aliases  []string     `json:"aliases"`
	Summary  string       `json:"summary"`
	Details  string       `json:"details"`
	Severity []osvCVSS    `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvCVSS struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package packageSpec `json:"package"`
	Ranges  []osvRange  `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// ── Internal ─────────────────────────────────────────────────────────────

func (c *Client) queryChunk(ctx context.Context, queries []PackageQuery) ([][]Vulnerability, error) {
	req := batchRequest{
		Queries: make([]queryEntry, len(queries)),
	}
	for i, q := range queries {
		req.Queries[i] = queryEntry{
			Package: packageSpec{
				Name:      q.Name,
				Ecosystem: osvEcosystem(q.Ecosystem),
			},
			Version: q.Version,
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("osv: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("osv: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("osv: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
	if err != nil {
		return nil, fmt.Errorf("osv: read response: %w", err)
	}

	var batchResp batchResponse
	if err := json.Unmarshal(respBody, &batchResp); err != nil {
		return nil, fmt.Errorf("osv: unmarshal response: %w", err)
	}

	results := make([][]Vulnerability, len(queries))
	for i, entry := range batchResp.Results {
		if i >= len(queries) {
			break
		}
		for _, v := range entry.Vulns {
			results[i] = append(results[i], convertVuln(v))
		}
	}

	return results, nil
}

// convertVuln converts an OSV vulnerability to our Vulnerability type.
func convertVuln(v osvVuln) Vulnerability {
	vuln := Vulnerability{
		ID:      v.ID,
		Aliases: v.Aliases,
		Summary: v.Summary,
	}
	if vuln.Summary == "" {
		vuln.Summary = v.Details
	}
	// Truncate long summaries.
	if len(vuln.Summary) > 500 {
		vuln.Summary = vuln.Summary[:497] + "..."
	}

	// Extract severity from CVSS vectors.
	vuln.Severity = extractSeverity(v.Severity)

	// Extract the earliest fixed version.
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					if vuln.FixedVersion == "" {
						vuln.FixedVersion = ev.Fixed
					}
				}
			}
		}
	}

	return vuln
}

// extractSeverity normalizes CVSS severity to critical/high/medium/low.
func extractSeverity(scores []osvCVSS) string {
	for _, s := range scores {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V4" {
			score := extractScoreFromVector(s.Score)
			if score >= 0 {
				return severityFromScore(score)
			}
		}
	}
	return ""
}

func extractScoreFromVector(vector string) float64 {
	for _, part := range strings.Split(vector, "/") {
		if score, err := strconv.ParseFloat(part, 64); err == nil && score >= 0 && score <= 10.0 {
			return score
		}
	}
	return -1
}

func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "info"
	}
}

// Query checks a single package for known vulnerabilities. Convenience wrapper
// around QueryBatch for the common case of one package at a time.
func (c *Client) Query(ctx context.Context, q PackageQuery) (*PackageResult, error) {
	results, err := c.QueryBatch(ctx, []PackageQuery{q})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return &PackageResult{Query: q}, nil
	}
	return &results[0], nil
}

// ServiceToOSVQueries maps a beacon service name + version string to zero or
// more OSV PackageQuery values. Server software like nginx or Apache is queried
// against the NVD ecosystem (no ecosystem filter — OSV matches by CPE). For
// language libraries detected in dependency manifests the ecosystem is set
// directly (npm, PyPI, etc.).
//
// Returns nil if the service name is not mapped.
func ServiceToOSVQueries(serviceName, version string) []PackageQuery {
	if version == "" {
		return nil
	}

	type mapping struct {
		osvName   string
		ecosystem string // empty = no ecosystem filter (uses commit/version matching)
	}

	// Map from beacon service tag / header value prefix to OSV query parameters.
	// For C/C++ server software we omit ecosystem so OSV matches via NVD/CVE entries.
	table := map[string]mapping{
		// Web servers
		"apache":        {osvName: "apache", ecosystem: ""},
		"nginx":         {osvName: "nginx", ecosystem: ""},
		"microsoft-iis": {osvName: "microsoft-iis", ecosystem: ""},
		"tomcat":        {osvName: "apache-tomcat", ecosystem: ""},
		"lighttpd":      {osvName: "lighttpd", ecosystem: ""},
		"openresty":     {osvName: "openresty", ecosystem: ""},

		// Language runtimes
		"php": {osvName: "php", ecosystem: ""},

		// CMS / platforms
		"wordpress": {osvName: "wordpress", ecosystem: ""},
		"drupal":    {osvName: "drupal", ecosystem: ""},
		"joomla":    {osvName: "joomla", ecosystem: ""},

		// Services detected by classify
		"jenkins":    {osvName: "jenkins", ecosystem: ""},
		"grafana":    {osvName: "grafana", ecosystem: ""},
		"gitlab":     {osvName: "gitlab", ecosystem: ""},
		"nextcloud":  {osvName: "nextcloud", ecosystem: ""},
		"confluence": {osvName: "confluence", ecosystem: ""},
		"jira":       {osvName: "jira", ecosystem: ""},
		"gitea":      {osvName: "gitea", ecosystem: ""},
		"kibana":     {osvName: "kibana", ecosystem: ""},
		"sonarqube":  {osvName: "sonarqube", ecosystem: ""},
		"harbor":     {osvName: "harbor", ecosystem: ""},
		"rabbitmq":   {osvName: "rabbitmq", ecosystem: ""},

		// npm packages
		"express":  {osvName: "express", ecosystem: "npm"},
		"lodash":   {osvName: "lodash", ecosystem: "npm"},
		"next":     {osvName: "next", ecosystem: "npm"},
		"nuxt":     {osvName: "nuxt", ecosystem: "npm"},
		"react":    {osvName: "react", ecosystem: "npm"},
		"angular":  {osvName: "@angular/core", ecosystem: "npm"},
		"vue":      {osvName: "vue", ecosystem: "npm"},
		"jquery":   {osvName: "jquery", ecosystem: "npm"},
		"backbone": {osvName: "backbone", ecosystem: "npm"},

		// Python frameworks
		"django": {osvName: "django", ecosystem: "PyPI"},
		"flask":  {osvName: "flask", ecosystem: "PyPI"},

		// Ruby frameworks
		"rails": {osvName: "rails", ecosystem: "RubyGems"},

		// SSH servers
		"openssh": {osvName: "openssh", ecosystem: ""},
	}

	m, ok := table[strings.ToLower(serviceName)]
	if !ok {
		return nil
	}

	return []PackageQuery{{
		Name:      m.osvName,
		Version:   version,
		Ecosystem: m.ecosystem,
	}}
}

// CVEIDs returns the CVE identifiers from a vulnerability's aliases.
func (v *Vulnerability) CVEIDs() []string {
	var cves []string
	for _, a := range v.Aliases {
		if len(a) > 4 && a[:4] == "CVE-" {
			cves = append(cves, a)
		}
	}
	return cves
}
