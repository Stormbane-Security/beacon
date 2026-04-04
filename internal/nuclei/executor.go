package nuclei

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	maxResponseBody = 2 * 1024 * 1024 // 2 MB max response body
	requestTimeout  = 15 * time.Second
)

// ExecuteResult holds the result of executing a template against a target.
type ExecuteResult struct {
	Matched      bool
	TemplateID   string
	MatcherName  string
	Extractions  map[string]string
	StatusCode   int
	MatchedAt    string // URL that matched
}

// executeTemplate runs all HTTP blocks in a template against the target.
func executeTemplate(ctx context.Context, tmpl *Template, baseURL string, client *http.Client) ([]ExecuteResult, error) {
	var results []ExecuteResult

	for _, block := range tmpl.HTTP {
		if block.Attack != "" && len(block.Payloads) > 0 {
			blockResults, err := executePayloadBlock(ctx, tmpl, &block, baseURL, client)
			if err != nil {
				continue
			}
			results = append(results, blockResults...)
		} else if len(block.Raw) > 0 {
			blockResults, err := executeRawBlock(ctx, tmpl, &block, baseURL, client)
			if err != nil {
				continue
			}
			results = append(results, blockResults...)
		} else {
			blockResults, err := executeSimpleBlock(ctx, tmpl, &block, baseURL, client)
			if err != nil {
				continue
			}
			results = append(results, blockResults...)
		}
	}

	return results, nil
}

// executeSimpleBlock handles method+path style requests.
func executeSimpleBlock(ctx context.Context, tmpl *Template, block *HTTPBlock, baseURL string, client *http.Client) ([]ExecuteResult, error) {
	var results []ExecuteResult
	extractions := make(map[string]string)

	for _, path := range block.Path {
		url := substituteVars(path, baseURL, tmpl.Variables, extractions)
		method := strings.ToUpper(block.Method)
		if method == "" {
			method = "GET"
		}

		body := substituteVars(block.Body, baseURL, tmpl.Variables, extractions)
		var bodyReader io.Reader
		if body != "" {
			bodyReader = strings.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			continue
		}

		// Set headers
		for k, v := range block.Headers {
			req.Header.Set(k, substituteVars(v, baseURL, tmpl.Variables, extractions))
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		}

		resp, err := doRequest(client, req)
		if err != nil {
			continue
		}

		// Run extractors first (results feed into matchers)
		newExtractions := runExtractors(block.Extractors, resp)
		for k, v := range newExtractions {
			extractions[k] = v
		}

		mr := evalMatchers(block, resp, extractions)
		if mr.Matched {
			results = append(results, ExecuteResult{
				Matched:     true,
				TemplateID:  tmpl.ID,
				MatcherName: mr.MatcherName,
				Extractions: copyMap(extractions),
				StatusCode:  resp.StatusCode,
				MatchedAt:   url,
			})
			if block.StopAtFirstMatch {
				return results, nil
			}
		}
	}

	return results, nil
}

// executeRawBlock handles raw HTTP request format.
func executeRawBlock(ctx context.Context, tmpl *Template, block *HTTPBlock, baseURL string, client *http.Client) ([]ExecuteResult, error) {
	var results []ExecuteResult
	extractions := make(map[string]string)

	for _, raw := range block.Raw {
		rawSubst := substituteVars(raw, baseURL, tmpl.Variables, extractions)

		req, err := parseRawRequest(ctx, rawSubst, baseURL)
		if err != nil {
			continue
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		}

		resp, err := doRequest(client, req)
		if err != nil {
			continue
		}

		newExtractions := runExtractors(block.Extractors, resp)
		for k, v := range newExtractions {
			extractions[k] = v
		}

		mr := evalMatchers(block, resp, extractions)
		if mr.Matched {
			results = append(results, ExecuteResult{
				Matched:     true,
				TemplateID:  tmpl.ID,
				MatcherName: mr.MatcherName,
				Extractions: copyMap(extractions),
				StatusCode:  resp.StatusCode,
				MatchedAt:   req.URL.String(),
			})
			if block.StopAtFirstMatch {
				return results, nil
			}
		}
	}

	return results, nil
}

// executePayloadBlock handles attack-mode requests with payloads.
func executePayloadBlock(ctx context.Context, tmpl *Template, block *HTTPBlock, baseURL string, client *http.Client) ([]ExecuteResult, error) {
	var results []ExecuteResult

	combos := generatePayloadCombinations(block.Attack, block.Payloads)

	for _, combo := range combos {
		extractions := make(map[string]string)
		// Merge payload vars into extractions for substitution
		for k, v := range combo {
			extractions[k] = v
		}

		for _, raw := range block.Raw {
			rawSubst := substituteVars(raw, baseURL, tmpl.Variables, extractions)

			req, err := parseRawRequest(ctx, rawSubst, baseURL)
			if err != nil {
				continue
			}
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			}

			resp, err := doRequest(client, req)
			if err != nil {
				continue
			}

			newExtractions := runExtractors(block.Extractors, resp)
			for k, v := range newExtractions {
				extractions[k] = v
			}

			mr := evalMatchers(block, resp, extractions)
			if mr.Matched {
				results = append(results, ExecuteResult{
					Matched:     true,
					TemplateID:  tmpl.ID,
					MatcherName: mr.MatcherName,
					Extractions: copyMap(extractions),
					StatusCode:  resp.StatusCode,
					MatchedAt:   req.URL.String(),
				})
				if block.StopAtFirstMatch {
					return results, nil
				}
			}
		}

		// Also handle simple path-based requests with payloads
		for _, path := range block.Path {
			url := substituteVars(path, baseURL, tmpl.Variables, extractions)
			method := strings.ToUpper(block.Method)
			if method == "" {
				method = "GET"
			}

			body := substituteVars(block.Body, baseURL, tmpl.Variables, extractions)
			var bodyReader io.Reader
			if body != "" {
				bodyReader = strings.NewReader(body)
			}

			req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
			if err != nil {
				continue
			}
			for k, v := range block.Headers {
				req.Header.Set(k, substituteVars(v, baseURL, tmpl.Variables, extractions))
			}
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			}

			resp, err := doRequest(client, req)
			if err != nil {
				continue
			}

			newExtractions := runExtractors(block.Extractors, resp)
			for k, v := range newExtractions {
				extractions[k] = v
			}

			mr := evalMatchers(block, resp, extractions)
			if mr.Matched {
				results = append(results, ExecuteResult{
					Matched:     true,
					TemplateID:  tmpl.ID,
					MatcherName: mr.MatcherName,
					Extractions: copyMap(extractions),
					StatusCode:  resp.StatusCode,
					MatchedAt:   url,
				})
				if block.StopAtFirstMatch {
					return results, nil
				}
			}
		}
	}

	return results, nil
}

// doRequest executes an HTTP request and returns the parsed response.
func doRequest(client *http.Client, req *http.Request) (*Response, error) {
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	bodyBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBody))
	if err != nil {
		return nil, err
	}

	// Build raw headers string
	var headerBuf strings.Builder
	_, _ = fmt.Fprintf(&headerBuf, "%s %s\r\n", httpResp.Proto, httpResp.Status)
	for k, vals := range httpResp.Header {
		for _, v := range vals {
			_, _ = fmt.Fprintf(&headerBuf, "%s: %s\r\n", k, v)
		}
	}
	headers := headerBuf.String()
	body := string(bodyBytes)

	return &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    headers,
		Body:       body,
		Raw:        headers + "\r\n" + body,
		ContentLen: len(bodyBytes),
	}, nil
}

// parseRawRequest parses a raw HTTP request string into an http.Request.
func parseRawRequest(ctx context.Context, raw string, baseURL string) (*http.Request, error) {
	raw = strings.TrimSpace(raw)
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty raw request")
	}

	// Parse request line: "GET /path HTTP/1.1"
	scanner := bufio.NewScanner(strings.NewReader(raw))
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty raw request")
	}
	requestLine := strings.TrimSpace(scanner.Text())
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed request line: %s", requestLine)
	}
	method := parts[0]
	path := parts[1]

	// Build full URL
	url := baseURL
	if strings.HasPrefix(path, "/") {
		url = strings.TrimRight(baseURL, "/") + path
	} else if strings.HasPrefix(path, "http") {
		url = path
	}

	// Parse headers and body
	headers := make(map[string]string)
	var bodyLines []string
	inBody := false
	for scanner.Scan() {
		line := scanner.Text()
		if !inBody {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				inBody = true
				continue
			}
			colonIdx := strings.Index(trimmed, ":")
			if colonIdx > 0 {
				key := strings.TrimSpace(trimmed[:colonIdx])
				val := strings.TrimSpace(trimmed[colonIdx+1:])
				headers[key] = val
			}
		} else {
			bodyLines = append(bodyLines, line)
		}
	}

	body := strings.Join(bodyLines, "\n")
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	return req, nil
}

// substituteVars replaces template variables in a string.
func substituteVars(s string, baseURL string, vars map[string]string, extractions map[string]string) string {
	if s == "" {
		return s
	}

	// Standard Nuclei variables
	hostname := baseURL
	if idx := strings.Index(hostname, "://"); idx != -1 {
		hostname = hostname[idx+3:]
	}
	hostname = strings.TrimRight(hostname, "/")
	// Strip port for Hostname
	hostOnly := hostname
	if idx := strings.LastIndex(hostOnly, ":"); idx > 0 {
		hostOnly = hostOnly[:idx]
	}

	s = strings.ReplaceAll(s, "{{BaseURL}}", strings.TrimRight(baseURL, "/"))
	s = strings.ReplaceAll(s, "{{RootURL}}", strings.TrimRight(baseURL, "/"))
	s = strings.ReplaceAll(s, "{{Hostname}}", hostname)
	s = strings.ReplaceAll(s, "{{Host}}", hostOnly)
	s = strings.ReplaceAll(s, "{{Scheme}}", schemeFromURL(baseURL))

	// Template-defined variables
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}

	// Extracted variables from previous requests
	for k, v := range extractions {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}

	return s
}

func schemeFromURL(url string) string {
	if strings.HasPrefix(url, "https") {
		return "https"
	}
	return "http"
}

// generatePayloadCombinations generates variable combinations based on attack type.
func generatePayloadCombinations(attack string, payloads map[string][]string) []map[string]string {
	if len(payloads) == 0 {
		return nil
	}

	switch strings.ToLower(attack) {
	case "pitchfork":
		return pitchforkCombos(payloads)
	case "clusterbomb":
		return clusterbombCombos(payloads)
	case "batteringram":
		return batteringRamCombos(payloads)
	default:
		// Default to pitchfork
		return pitchforkCombos(payloads)
	}
}

// pitchforkCombos pairs values at the same index across all payload lists.
func pitchforkCombos(payloads map[string][]string) []map[string]string {
	keys := sortedKeys(payloads)
	if len(keys) == 0 {
		return nil
	}

	maxLen := 0
	for _, vals := range payloads {
		if len(vals) > maxLen {
			maxLen = len(vals)
		}
	}

	var combos []map[string]string
	for i := 0; i < maxLen; i++ {
		combo := make(map[string]string)
		for _, k := range keys {
			vals := payloads[k]
			if i < len(vals) {
				combo[k] = vals[i]
			}
		}
		combos = append(combos, combo)
	}
	return combos
}

// clusterbombCombos generates all combinations (cartesian product).
func clusterbombCombos(payloads map[string][]string) []map[string]string {
	keys := sortedKeys(payloads)
	if len(keys) == 0 {
		return nil
	}

	var combos []map[string]string
	var generate func(idx int, current map[string]string)
	generate = func(idx int, current map[string]string) {
		if idx == len(keys) {
			combo := copyMap(current)
			combos = append(combos, combo)
			return
		}
		key := keys[idx]
		for _, val := range payloads[key] {
			current[key] = val
			generate(idx+1, current)
		}
	}
	generate(0, make(map[string]string))

	// Safety limit to avoid explosion
	if len(combos) > 1000 {
		combos = combos[:1000]
	}
	return combos
}

// batteringRamCombos uses the same value for all variables.
func batteringRamCombos(payloads map[string][]string) []map[string]string {
	keys := sortedKeys(payloads)
	if len(keys) == 0 {
		return nil
	}

	// Use the first key's values
	firstKey := keys[0]
	vals := payloads[firstKey]

	var combos []map[string]string
	for _, v := range vals {
		combo := make(map[string]string)
		for _, k := range keys {
			combo[k] = v
		}
		combos = append(combos, combo)
	}
	return combos
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Sort for deterministic ordering
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func copyMap(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// newHTTPClient creates an HTTP client suitable for template execution.
func newHTTPClient(followRedirects bool, maxRedirects int) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if maxRedirects > 0 {
		limit := maxRedirects
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= limit {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	return client
}
