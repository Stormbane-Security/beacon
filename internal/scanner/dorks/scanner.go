// Package dorks queries the Bing Search API for exposed sensitive files
// related to the target domain using Google-style dork queries.
// Only runs when an API key is configured; returns nil otherwise.
package dorks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "dorks"

// Scanner queries Bing Search API for dork-based exposure findings.
type Scanner struct {
	apiKey string
}

// New creates a new dorks Scanner. If apiKey is empty the scanner is a no-op.
func New(apiKey string) *Scanner { return &Scanner{apiKey: apiKey} }

func (s *Scanner) Name() string { return scannerName }

// dorkQuery describes a single Bing dork query and how to classify its results.
type dorkQuery struct {
	// template has one %s placeholder for the domain
	template  string
	queryType string
	severity  finding.Severity
}

var dorkQueries = []dorkQuery{
	{"site:%s filetype:env", "env", finding.SeverityCritical},
	{"site:%s filetype:sql", "sql", finding.SeverityCritical},
	{"site:%s filetype:log", "log", finding.SeverityHigh},
	{"site:%s inurl:phpinfo", "phpinfo", finding.SeverityHigh},
	{`site:%s inurl:".git" -github`, "git", finding.SeverityHigh},
	{"site:%s inurl:backup", "backup", finding.SeverityHigh},
	{`site:%s "index of /" inurl:uploads`, "upload", finding.SeverityHigh},
	{"site:%s filetype:pem OR filetype:key OR filetype:p12", "key", finding.SeverityCritical},
}

// bingResponse is the minimal structure we decode from the Bing Search API.
type bingResponse struct {
	WebPages struct {
		Value []struct {
			URL     string `json:"url"`
			Name    string `json:"name"`
			Snippet string `json:"snippet"`
		} `json:"value"`
	} `json:"webPages"`
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	if s.apiKey == "" {
		return nil, nil
	}

	// Dork queries use site:rootdomain — running on every subdomain would fire
	// identical Bing API calls and exhaust quota fast. Only run on the root domain.
	// "example.co.uk" has 2 dots and is a valid ccTLD+SLD root domain.
	// Anything with more than 2 dots is guaranteed to be a subdomain.
	if strings.Count(asset, ".") > 2 {
		return nil, nil
	}

	domain := rootDomain(asset)

	client := &http.Client{Timeout: 10 * time.Second}
	seen := make(map[string]struct{})
	var findings []finding.Finding

	for i, dq := range dorkQueries {
		if i > 0 {
			select {
			case <-ctx.Done():
				return findings, nil
			case <-time.After(2 * time.Second):
			}
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		query := fmt.Sprintf(dq.template, domain)
		results, err := bingSearch(ctx, client, s.apiKey, query)
		if err != nil {
			// Non-fatal: skip this query and continue
			continue
		}

		for _, r := range results {
			// Only include results that actually relate to the target domain
			if !strings.Contains(strings.ToLower(r.URL), strings.ToLower(domain)) {
				continue
			}
			if _, ok := seen[r.URL]; ok {
				continue
			}
			seen[r.URL] = struct{}{}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckBingDorkExposure,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: dq.severity,
				Title:    fmt.Sprintf("Bing dork: %s exposed at %s", dq.queryType, r.URL),
				Description: fmt.Sprintf(
					"A Bing search dork revealed a potentially sensitive %s resource indexed at %s. "+
						"Publicly indexed sensitive files can be accessed and exploited by attackers "+
						"without requiring any authentication.",
					dq.queryType, r.URL,
				),
				Asset: asset,
				Evidence: map[string]any{
					"query":        query,
					"result_url":   r.URL,
					"result_title": r.Name,
					"snippet":      r.Snippet,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// bingResult is a single result from the Bing Web Search API.
type bingResult struct {
	URL     string
	Name    string
	Snippet string
}

// bingSearch executes a single Bing Web Search API call and returns the results.
func bingSearch(ctx context.Context, client *http.Client, apiKey, query string) ([]bingResult, error) {
	endpoint := "https://api.bing.microsoft.com/v7.0/search"
	params := url.Values{}
	params.Set("q", query)
	params.Set("count", "5")

	reqURL := endpoint + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var br bingResponse
	if err := json.Unmarshal(body, &br); err != nil {
		return nil, err
	}

	out := make([]bingResult, 0, len(br.WebPages.Value))
	for _, v := range br.WebPages.Value {
		out = append(out, bingResult{URL: v.URL, Name: v.Name, Snippet: v.Snippet})
	}
	return out, nil
}

// rootDomain strips subdomains, returning the registration-level domain.
// For simple TLDs ("example.com" → "example.com"), for ccTLD+SLD domains
// ("example.co.uk" → "example.co.uk") it returns the full asset as-is because
// the filter above already ensures assets have at most 2 dots.
func rootDomain(asset string) string {
	parts := strings.Split(asset, ".")
	if len(parts) <= 2 {
		return asset
	}
	// 3-label case: the dot-count filter (> 2) already rejects 4+ dot assets.
	// For exactly 3 labels, return the full asset — if it is a ccTLD root domain
	// (e.g. "example.co.uk") we want the full string. If a simple subdomain
	// somehow reaches here (e.g. "api.example.com"), returning the full string
	// is safe because Bing will simply scope results to that exact label.
	return asset
}
