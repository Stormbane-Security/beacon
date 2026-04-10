package wafbypass

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BypassResult captures the outcome of an adaptive WAF bypass attempt.
type BypassResult struct {
	Bypassed        bool   // true if any encoding variant got past the WAF
	Encoder         string // which encoding succeeded (empty if none)
	OriginalBlocked bool   // true if the unencoded payload was blocked
	StatusCode      int    // HTTP status of the successful response (or last attempt)
	Response        string // truncated response body of the successful request
	EncodedPayload  string // the payload variant that bypassed the WAF
}

// wafBlockStatuses are HTTP status codes that indicate WAF blocking.
var wafBlockStatuses = map[int]bool{
	403: true,
	406: true,
	429: true,
	503: true,
}

// wafBlockSignatures are body substrings that indicate WAF blocking even on 200 responses.
var wafBlockSignatures = []string{
	"access denied",
	"request blocked",
	"your request has been blocked",
	"web application firewall",
	"attention required! | cloudflare",
	"please wait... | cloudflare",
	"powered by incapsula",
	"sucuri website firewall",
	"modsecurity",
	"wordfence",
	"forbidden",
}

// maxResponseSnippet is the max length of response body stored in BypassResult.
const maxResponseSnippet = 1024

// AdaptiveTester tries a baseline payload against a URL parameter. If the WAF
// blocks it, the function retries with every available encoding variant until
// one succeeds or all are exhausted.
//
// The url parameter should be the full base URL (e.g., "https://example.com/").
// The param parameter is the query parameter name to inject into.
// The payload parameter is the raw injection string.
func AdaptiveTester(ctx context.Context, client *http.Client, targetURL, param, payload string) *BypassResult {
	result := &BypassResult{}

	// Step 1: Send the original unencoded payload.
	baseResp, baseBody, baseStatus := sendProbe(ctx, client, targetURL, param, payload)
	_ = baseResp

	if !isBlockedResponse(baseStatus, baseBody) {
		// Original payload was not blocked — no WAF evasion needed.
		result.Bypassed = false
		result.OriginalBlocked = false
		result.StatusCode = baseStatus
		result.Response = truncate(baseBody, maxResponseSnippet)
		return result
	}

	result.OriginalBlocked = true

	// Step 2: Try each encoding variant.
	for _, enc := range AllEncoders() {
		select {
		case <-ctx.Done():
			result.StatusCode = baseStatus
			return result
		default:
		}

		encoded := enc.Encode(payload)
		if encoded == payload {
			continue // encoder didn't change anything
		}

		_, body, status := sendProbe(ctx, client, targetURL, param, encoded)

		if !isBlockedResponse(status, body) {
			// This variant bypassed the WAF.
			result.Bypassed = true
			result.Encoder = enc.Name
			result.StatusCode = status
			result.Response = truncate(body, maxResponseSnippet)
			result.EncodedPayload = encoded
			return result
		}
	}

	// All variants blocked.
	result.Bypassed = false
	result.StatusCode = baseStatus
	result.Response = truncate(baseBody, maxResponseSnippet)
	return result
}

// sendProbe sends a GET request with the payload injected into the query parameter.
func sendProbe(ctx context.Context, client *http.Client, targetURL, param, payload string) (*http.Response, string, int) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, "", 0
	}
	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return nil, "", 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", 0
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp, string(bodyBytes), resp.StatusCode
}

// isBlockedResponse returns true if the response looks like a WAF block page.
func isBlockedResponse(status int, body string) bool {
	if wafBlockStatuses[status] {
		return true
	}
	lower := strings.ToLower(body)
	for _, sig := range wafBlockSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// truncate returns at most n bytes of s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
