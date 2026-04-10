// depth.go implements GraphQL depth, alias, and batch abuse attacks that test
// whether the server enforces query complexity limits. Lack of limits enables
// denial of service via deeply nested queries, alias amplification, or batch
// request flooding.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// DepthResult holds the outcome of a deep-nesting probe.
type DepthResult struct {
	Vulnerable   bool
	DepthSent    int
	DepthResolved int
	Response     string
}

// AliasResult holds the outcome of an alias amplification probe.
type AliasResult struct {
	Vulnerable      bool
	AliasesSent     int
	AliasesResolved int
	Response        string
}

// BatchResult holds the outcome of a batch query probe.
type BatchResult struct {
	Vulnerable    bool
	QueriesSent   int
	QueriesProcessed int
	Response      string
}

// TestDepthAttack sends deeply nested queries to check if the server
// enforces query depth limits. Lack of limits enables DoS.
func TestDepthAttack(ctx context.Context, client *http.Client, endpoint string) *DepthResult {
	const depth = 20
	// Build: { __type(name: "Query") { fields { type { fields { type { ... name } } } } } }
	var sb strings.Builder
	sb.WriteString(`{"query":"{ __type(name: \"Query\") `)
	for range depth {
		sb.WriteString("{ fields { type ")
	}
	sb.WriteString("{ name }")
	for range depth {
		sb.WriteString(" } }")
	}
	sb.WriteString(` }"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewBufferString(sb.String()))
	if err != nil {
		return &DepthResult{Vulnerable: false}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return &DepthResult{Vulnerable: false}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return &DepthResult{Vulnerable: false}
	}

	var gqlResp struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &gqlResp); err != nil {
		return &DepthResult{Vulnerable: false}
	}

	// Check for depth/complexity rejection errors.
	for _, e := range gqlResp.Errors {
		lower := strings.ToLower(e.Message)
		if strings.Contains(lower, "depth") || strings.Contains(lower, "complex") ||
			strings.Contains(lower, "nest") || strings.Contains(lower, "limit") {
			return &DepthResult{Vulnerable: false, Response: compactSnippet(raw, 300)}
		}
	}

	if len(gqlResp.Data) == 0 || string(gqlResp.Data) == "null" {
		return &DepthResult{Vulnerable: false}
	}

	return &DepthResult{
		Vulnerable:    true,
		DepthSent:     depth,
		DepthResolved: depth,
		Response:      compactSnippet(raw, 300),
	}
}

// TestAliasAttack sends a query with many aliases for the same field
// to check if the server limits alias count. Unlimited aliases enable DoS.
func TestAliasAttack(ctx context.Context, client *http.Client, endpoint string) *AliasResult {
	const aliasCount = 1000
	var sb strings.Builder
	sb.WriteString(`{"query":"{ `)
	for i := range aliasCount {
		if i > 0 {
			sb.WriteString(" ")
		}
		_, _ = fmt.Fprintf(&sb, "a%d: __typename", i)
	}
	sb.WriteString(` }"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewBufferString(sb.String()))
	if err != nil {
		return &AliasResult{Vulnerable: false}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return &AliasResult{Vulnerable: false}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return &AliasResult{Vulnerable: false}
	}

	var gqlResp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &gqlResp); err != nil || gqlResp.Data == nil {
		return &AliasResult{Vulnerable: false}
	}

	resolved := 0
	for i := range aliasCount {
		if _, ok := gqlResp.Data[fmt.Sprintf("a%d", i)]; ok {
			resolved++
		}
	}

	// If the server resolved 950+ of 1000 aliases, it's vulnerable.
	if resolved < aliasCount-50 {
		return &AliasResult{
			Vulnerable:      false,
			AliasesSent:     aliasCount,
			AliasesResolved: resolved,
		}
	}

	return &AliasResult{
		Vulnerable:      true,
		AliasesSent:     aliasCount,
		AliasesResolved: resolved,
		Response:        compactSnippet(raw, 300),
	}
}

// TestBatchAttack sends an array of queries in one request to check
// if the server limits batch size.
func TestBatchAttack(ctx context.Context, client *http.Client, endpoint string) *BatchResult {
	const batchSize = 100
	var sb strings.Builder
	sb.WriteString("[")
	for i := range batchSize {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"query":"{ __typename }"}`)
	}
	sb.WriteString("]")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewBufferString(sb.String()))
	if err != nil {
		return &BatchResult{Vulnerable: false}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return &BatchResult{Vulnerable: false}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return &BatchResult{Vulnerable: false}
	}

	trimmed := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(trimmed, "[") {
		return &BatchResult{Vulnerable: false}
	}

	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return &BatchResult{Vulnerable: false}
	}

	// Count how many responses were processed.
	processed := 0
	for _, item := range arr {
		if _, ok := item["data"]; ok {
			processed++
		} else if _, ok := item["errors"]; ok {
			processed++
		}
	}

	// If the server processed 90+ of 100 queries, no batch limit.
	if processed < 90 {
		return &BatchResult{Vulnerable: false, QueriesSent: batchSize, QueriesProcessed: processed}
	}

	return &BatchResult{
		Vulnerable:       true,
		QueriesSent:      batchSize,
		QueriesProcessed: processed,
		Response:         compactSnippet(raw, 300),
	}
}

// checkNoDepthLimit is the scanner integration that emits a finding for
// graphql.no_depth_limit using the TestDepthAttack probe with 20+ levels.
func checkNoDepthLimit(ctx context.Context, client *http.Client, asset, endpoint string) *finding.Finding {
	result := TestDepthAttack(ctx, client, endpoint)
	if !result.Vulnerable {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckGraphQLNoDepthLimit,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("GraphQL server allows %d+ nested levels without depth limit at %s", result.DepthSent, endpoint),
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s accepted a query nested %d levels deep using "+
				"__type introspection chains without returning a depth-limit error. An attacker can "+
				"exploit unbounded query depth to craft queries that recursively resolve nested "+
				"relationships, causing exponential database work and denial of service.",
			endpoint, result.DepthSent),
		Evidence: map[string]any{
			"url":              endpoint,
			"depth_sent":       result.DepthSent,
			"response_snippet": result.Response,
		},
		ProofCommand: fmt.Sprintf(
			`curl -s -X POST '%s' -H 'Content-Type: application/json' -d '{"query":"{ __type(name: \"Query\") { fields { type { fields { type { fields { type { name } } } } } } } }"}'`,
			endpoint),
		DiscoveredAt: time.Now(),
	}
}

// checkBatchNoLimit is the scanner integration that emits a finding for
// graphql.batch_no_limit using the TestBatchAttack probe with 100 queries.
func checkBatchNoLimit(ctx context.Context, client *http.Client, asset, endpoint string) *finding.Finding {
	result := TestBatchAttack(ctx, client, endpoint)
	if !result.Vulnerable {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckGraphQLBatchNoLimit,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("GraphQL server processes %d batched queries without limit at %s", result.QueriesProcessed, endpoint),
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s processed %d out of %d batched queries in a single "+
				"HTTP request without rejecting the batch. An attacker can send hundreds of "+
				"expensive mutations or queries in one request, bypassing per-request rate limits "+
				"and amplifying brute-force, credential stuffing, and enumeration attacks.",
			endpoint, result.QueriesProcessed, result.QueriesSent),
		Evidence: map[string]any{
			"url":               endpoint,
			"queries_sent":      result.QueriesSent,
			"queries_processed": result.QueriesProcessed,
			"response_snippet":  result.Response,
		},
		ProofCommand: fmt.Sprintf(
			`curl -s -X POST '%s' -H 'Content-Type: application/json' -d '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'`,
			endpoint),
		DiscoveredAt: time.Now(),
	}
}
