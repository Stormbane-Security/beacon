// Package graphql checks whether GraphQL introspection is enabled on common
// endpoint paths. Introspection leaks the full API schema to any caller,
// exposing all types, queries, mutations, and field names.
package graphql

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "graphql"

// dialTimeout is used when checking basic TCP reachability.
const dialTimeout = 3 * time.Second

// httpTimeout covers the full introspection POST request.
const httpTimeout = 10 * time.Second

// introspectionQuery is the minimal GraphQL introspection query that reveals
// whether introspection is enabled without requesting the entire schema.
const introspectionQuery = `{"query":"{__schema{types{name}}}"}`

// commonPaths lists endpoint paths that are frequently used for GraphQL APIs.
var commonPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/query",
	"/gql",
}

// Scanner checks for enabled GraphQL introspection endpoints.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run probes each common GraphQL path over HTTP (and HTTPS) and emits a
// finding for every endpoint where introspection is enabled.
//
// The scanner skips gracefully if the host is unreachable.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Quick TCP reachability check on port 80 and 443. If neither is open we
	// skip to avoid noise on non-HTTP assets.
	if !isHTTPReachable(ctx, asset) {
		return nil, nil
	}

	client := &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: dialTimeout}).DialContext,
		},
		// Do not follow redirects — a redirect means the path is protected.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var findings []finding.Finding

	// confirmedPaths tracks paths where introspection was already confirmed so
	// we don't emit a duplicate finding when both https and http are open.
	confirmedPaths := make(map[string]bool)

	// confirmedEndpoints collects paths with a live GraphQL endpoint (whether or
	// not introspection is enabled) so deep-mode probes target the right URLs.
	var confirmedEndpoints []string

	for _, scheme := range []string{"https", "http"} {
		for _, path := range commonPaths {
			if confirmedPaths[path] {
				continue
			}
			url := fmt.Sprintf("%s://%s%s", scheme, asset, path)
			exposed, bodySnippet := checkIntrospection(ctx, client, url)
			if !exposed {
				// Even without introspection the endpoint may be live — check for
				// any GraphQL-shaped JSON response to know where to send deep probes.
				if isGraphQLEndpoint(ctx, client, url) && !confirmedPaths[path] {
					confirmedPaths[path] = true
					confirmedEndpoints = append(confirmedEndpoints, url)
				}
				continue
			}
			confirmedPaths[path] = true
			confirmedEndpoints = append(confirmedEndpoints, url)
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckGraphQLIntrospection,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("GraphQL introspection enabled at %s", url),
				Description: "GraphQL introspection is enabled, allowing any caller to query the full " +
					"API schema including all types, fields, queries, and mutations. " +
					"This exposes internal data models and API structure that should not be public, " +
					"and significantly aids attackers in crafting targeted queries.",
				Asset: asset,
				Evidence: map[string]any{
					"url":          url,
					"path":         path,
					"body_snippet": bodySnippet,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Deep-mode probes — batch queries, persisted query bypass, and CSRF via GET.
	// Only run against confirmed GraphQL endpoints found above.
	if scanType == module.ScanDeep {
		for _, endpointURL := range confirmedEndpoints {
			if f := checkBatchQuery(ctx, client, asset, endpointURL); f != nil {
				findings = append(findings, *f)
			}
			if f := checkPersistedQueryBypass(ctx, client, asset, endpointURL); f != nil {
				findings = append(findings, *f)
			}
			if f := checkGraphQLGET(ctx, client, asset, endpointURL); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

// isHTTPReachable returns true if port 443 or port 80 on the host accepts a
// TCP connection within the dial timeout.
func isHTTPReachable(ctx context.Context, host string) bool {
	dialer := &net.Dialer{Timeout: dialTimeout}
	// If the asset already includes a port (e.g. "example.com:8080" from a
	// per-port sub-scan), probe that specific port rather than 80/443.
	if _, _, err := net.SplitHostPort(host); err == nil {
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err == nil {
			_ = conn.Close()
			return true
		}
		return false
	}
	for _, port := range []string{"443", "80"} {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

// checkIntrospection POSTs an introspection query to url and returns true if
// the response body contains "__schema", indicating introspection is enabled.
// It also returns a short snippet of the response body for evidence.
func checkIntrospection(ctx context.Context, client *http.Client, url string) (bool, string) {
	body := bytes.NewBufferString(introspectionQuery)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, ""
	}

	// Cap the body read to avoid consuming huge responses.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return false, ""
	}

	responseBody := string(raw)
	if !strings.Contains(responseBody, `"__schema"`) {
		return false, ""
	}

	// Produce a compact snippet for evidence (first 512 chars of the JSON value).
	snippet := compactSnippet(raw, 512)
	return true, snippet
}

// isGraphQLEndpoint returns true if the URL looks like a live GraphQL endpoint
// even when introspection is disabled. We send a minimal __typename query —
// any valid GraphQL server responds with a JSON object containing "data".
func isGraphQLEndpoint(ctx context.Context, client *http.Client, url string) bool {
	body := bytes.NewBufferString(`{"query":"{__typename}"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false
	}
	// Require both "data" and "__typename" — any valid GraphQL server executing
	// {__typename} returns {"data":{"__typename":"..."}}. Checking both fields
	// avoids false-positives on REST APIs that happen to return a "data" key.
	responseBody := string(raw)
	return strings.Contains(responseBody, `"data"`) && strings.Contains(responseBody, `"__typename"`)
}

// checkBatchQuery tests whether the GraphQL endpoint accepts batched queries
// (an array of query objects). Batch support lets attackers send hundreds of
// mutations or queries in a single HTTP request, bypassing per-request rate
// limits and amplifying brute-force and enumeration attacks.
func checkBatchQuery(ctx context.Context, client *http.Client, asset, url string) *finding.Finding {
	// Send a two-element batch — minimal and idempotent.
	body := bytes.NewBufferString(`[{"query":"{__typename}"},{"query":"{__typename}"}]`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}
	// A batched response is a JSON array starting with '['.
	trimmed := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(trimmed, "[") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckGraphQLBatchQuery,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("GraphQL batch queries enabled at %s", url),
		Description: "The GraphQL endpoint accepts batched requests (an array of query objects). " +
			"Batch support allows attackers to send hundreds of queries or mutations in a single " +
			"HTTP request, bypassing per-request rate limits and amplifying brute-force, " +
			"credential stuffing, and enumeration attacks against the API.",
		Evidence: map[string]any{
			"url":             url,
			"response_prefix": trimmed[:min(len(trimmed), 200)],
		},
		DiscoveredAt: time.Now(),
	}
}

// checkPersistedQueryBypass tests whether the server accepts Automatic Persisted
// Queries (APQ) with an arbitrary unknown hash. Servers that process the query
// payload on an APQ miss (instead of returning PersistedQueryNotFound) allow
// attackers to use the APQ extension to bypass introspection blocks or WAF
// rules that only inspect the top-level "query" field.
// randomSHA256Hex returns a random 64-character hex string to use as a fake
// SHA-256 hash. Using a random value (rather than a fixed all-zeros string)
// avoids theoretical hash collisions with a legitimately persisted query.
func randomSHA256Hex() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use a non-zero but deterministic garbage value. This should
		// never happen in practice (crypto/rand is always available).
		for i := range b {
			b[i] = byte(0xde ^ i)
		}
	}
	return hex.EncodeToString(b)
}

func checkPersistedQueryBypass(ctx context.Context, client *http.Client, asset, url string) *finding.Finding {
	// Use a random SHA-256 hash. A correctly implemented APQ server returns
	// {"errors":[{"message":"PersistedQueryNotFound"}]} and ignores the payload.
	// A misconfigured server executes the query field instead. A random hash
	// avoids false negatives from a fixed value colliding with a real stored query.
	fakeHash := randomSHA256Hex()
	body := bytes.NewBufferString(`{"query":"{__typename}","extensions":{"persistedQuery":{"version":1,"sha256Hash":"` + fakeHash + `"}}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}
	// Parse the response properly to avoid false positives from string matching.
	// `"data": null` and `"data": {}` both contain the `"data"` string but mean
	// different things; only a non-null data value proves the query was executed.
	var gqlResp struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &gqlResp); err != nil {
		return nil
	}
	// A correctly behaving APQ server returns PersistedQueryNotFound in errors.
	for _, e := range gqlResp.Errors {
		if strings.Contains(e.Message, "PersistedQueryNotFound") {
			return nil
		}
	}
	// Only flag if data is present and non-null — the query was actually executed.
	if len(gqlResp.Data) == 0 || string(gqlResp.Data) == "null" {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckGraphQLPersistedQueryBypass,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("GraphQL persisted query bypass at %s", url),
		Description: "The GraphQL endpoint executes queries submitted via the Automatic Persisted " +
			"Query (APQ) extension even when the hash is unknown, instead of returning " +
			"PersistedQueryNotFound. Attackers can use this path to bypass WAF rules and " +
			"introspection blocks that only inspect the top-level 'query' field.",
		Evidence: map[string]any{
			"url":             url,
			"response_snippet": compactSnippet(raw, 300),
		},
		DiscoveredAt: time.Now(),
	}
}

// checkGraphQLGET tests whether the GraphQL endpoint accepts queries via HTTP GET.
// GraphQL over GET enables CSRF attacks because browsers send GET requests with
// cookies automatically — an attacker can craft a link that executes a mutation
// on behalf of an authenticated user.
func checkGraphQLGET(ctx context.Context, client *http.Client, asset, endpoint string) *finding.Finding {
	// Strip any query string from the endpoint URL before appending ours.
	base := endpoint
	if idx := strings.Index(base, "?"); idx != -1 {
		base = base[:idx]
	}
	getURL := base + "?query=" + "{__typename}"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}
	responseBody := string(raw)
	if !strings.Contains(responseBody, `"data"`) || !strings.Contains(responseBody, `"__typename"`) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckGraphQLGETEnabled,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("GraphQL queries accepted via GET at %s", endpoint),
		Description: "The GraphQL endpoint executes queries submitted via HTTP GET with a " +
			"?query= parameter. Because browsers automatically attach cookies to GET requests, " +
			"an attacker can craft a URL that executes arbitrary GraphQL queries (including " +
			"mutations on some implementations) on behalf of an authenticated user — a classic CSRF vector.",
		Evidence: map[string]any{
			"url":              getURL,
			"response_snippet": compactSnippet(raw, 300),
		},
		ProofCommand: fmt.Sprintf("curl -s '%s'", getURL),
		DiscoveredAt: time.Now(),
	}
}

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// compactSnippet re-encodes the JSON body compactly and truncates it to max bytes.
func compactSnippet(raw []byte, max int) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		// Fall back to raw truncation if the body is not valid JSON.
		s := string(raw)
		if len(s) > max {
			return s[:max] + "…"
		}
		return s
	}
	s := buf.String()
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
