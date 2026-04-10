// beacon-fuzz is a standalone web API fuzzer that mutates request bodies and
// flags anomalous responses. It is designed to be called by beacon during
// authorized scanning.
//
// Usage:
//
//	beacon-fuzz --target https://example.com/api/users --method POST \
//	  --content-type application/json --body '{"name":"test"}' \
//	  --output /tmp/fuzz-results.json --max-requests 100 --rate 5
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---------- output types ----------

// FuzzResult is the top-level JSON output.
type FuzzResult struct {
	Target       string        `json:"target"`
	Method       string        `json:"method"`
	Timestamp    string        `json:"timestamp"`
	TotalSent    int           `json:"total_sent"`
	AnomalyCount int          `json:"anomaly_count"`
	Baseline     *ResponseInfo `json:"baseline"`
	Anomalies    []Anomaly     `json:"anomalies"`
}

// Anomaly describes a response that deviated from the baseline.
type Anomaly struct {
	MutationName string       `json:"mutation"`
	Description  string       `json:"description"`
	Request      RequestInfo  `json:"request"`
	Response     ResponseInfo `json:"response"`
	Reasons      []string     `json:"reasons"`
}

// RequestInfo captures what was sent.
type RequestInfo struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// ResponseInfo captures the interesting parts of a response.
type ResponseInfo struct {
	StatusCode   int           `json:"status_code"`
	BodySize     int           `json:"body_size"`
	ResponseTime time.Duration `json:"response_time_ms"`
	BodySnippet  string        `json:"body_snippet,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// Mutation is a single fuzz case to send.
type Mutation struct {
	Name        string
	Description string
	ContentType string // override content-type if set
	Body        string
}

// ---------- CLI ----------

func main() {
	target := flag.String("target", "", "Target URL (required)")
	method := flag.String("method", "POST", "HTTP method")
	contentType := flag.String("content-type", "application/json", "Content-Type header")
	body := flag.String("body", "", "Request body template")
	output := flag.String("output", "", "Output file for JSON results (required)")
	maxReqs := flag.Int("max-requests", 100, "Maximum number of fuzz requests")
	rate := flag.Float64("rate", 5, "Requests per second")
	timeout := flag.Duration("timeout", 60*time.Second, "Overall timeout")
	unsafe := flag.Bool("unsafe", false, "Allow non-idempotent methods (PUT, DELETE, PATCH)")
	flag.Parse()

	if *target == "" || *output == "" {
		flag.Usage()
		os.Exit(1)
	}

	if !*unsafe && isNonIdempotent(*method) {
		// POST is the typical fuzzing method, allow it.
		// PUT/DELETE/PATCH require --unsafe.
		if strings.EqualFold(*method, "PUT") || strings.EqualFold(*method, "DELETE") || strings.EqualFold(*method, "PATCH") {
			log.Fatalf("method %s is non-idempotent; pass --unsafe to confirm", *method)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := fuzz(ctx, *target, strings.ToUpper(*method), *contentType, *body, *maxReqs, *rate)
	if err != nil {
		log.Fatalf("fuzz failed: %v", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("json marshal: %v", err)
	}

	if err := os.WriteFile(*output, data, 0o644); err != nil {
		log.Fatalf("write output: %v", err)
	}

	fmt.Fprintf(os.Stderr, "beacon-fuzz: %d requests sent, %d anomalies found → %s\n",
		result.TotalSent, result.AnomalyCount, *output)
}

func isNonIdempotent(method string) bool {
	switch strings.ToUpper(method) {
	case "PUT", "DELETE", "PATCH":
		return true
	}
	return false
}

// ---------- fuzzer core ----------

func fuzz(ctx context.Context, target, method, ct, bodyTemplate string, maxReqs int, rate float64) (*FuzzResult, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Send baseline request first.
	baseline, err := sendRequest(ctx, client, method, target, ct, bodyTemplate)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "beacon-fuzz: baseline status=%d size=%d time=%v\n",
		baseline.StatusCode, baseline.BodySize, baseline.ResponseTime)

	// Generate mutations.
	mutations := generateMutations(ct, bodyTemplate)

	// Cap to max requests.
	if len(mutations) > maxReqs {
		mutations = mutations[:maxReqs]
	}

	// Rate limiter: one tick per 1/rate seconds.
	interval := time.Duration(float64(time.Second) / rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var anomalies []Anomaly
	sent := 0
	backoffUntil := time.Time{}

	for _, mut := range mutations {
		if ctx.Err() != nil {
			break
		}

		// Respect backoff from 429.
		if time.Now().Before(backoffUntil) {
			wait := time.Until(backoffUntil)
			fmt.Fprintf(os.Stderr, "beacon-fuzz: rate-limited, backing off %v\n", wait.Round(time.Second))
			select {
			case <-ctx.Done():
				break
			case <-time.After(wait):
			}
		}

		<-ticker.C

		useCT := ct
		if mut.ContentType != "" {
			useCT = mut.ContentType
		}

		resp, err := sendRequest(ctx, client, method, target, useCT, mut.Body)
		sent++

		if err != nil {
			resp = &ResponseInfo{Error: err.Error()}
		}

		// Check for 429 and back off.
		if resp.StatusCode == 429 {
			backoffUntil = time.Now().Add(5 * time.Second)
		}

		// Detect anomalies.
		reasons := detectAnomalies(baseline, resp)
		if len(reasons) > 0 {
			anomalies = append(anomalies, Anomaly{
				MutationName: mut.Name,
				Description:  mut.Description,
				Request: RequestInfo{
					Method:      method,
					URL:         target,
					ContentType: useCT,
					Body:        truncate(mut.Body, 2048),
				},
				Response: *resp,
				Reasons:  reasons,
			})
		}

		if sent%10 == 0 {
			fmt.Fprintf(os.Stderr, "beacon-fuzz: %d/%d sent, %d anomalies\n", sent, len(mutations), len(anomalies))
		}
	}

	return &FuzzResult{
		Target:       target,
		Method:       method,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		TotalSent:    sent,
		AnomalyCount: len(anomalies),
		Baseline:     baseline,
		Anomalies:    anomalies,
	}, nil
}

func sendRequest(ctx context.Context, client *http.Client, method, target, ct, body string) (*ResponseInfo, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("User-Agent", "beacon-fuzz/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return &ResponseInfo{
			ResponseTime: elapsed / time.Millisecond,
			Error:        err.Error(),
		}, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	return &ResponseInfo{
		StatusCode:   resp.StatusCode,
		BodySize:     len(data),
		ResponseTime: elapsed / time.Millisecond,
		BodySnippet:  truncate(string(data), 512),
	}, nil
}

// ---------- anomaly detection ----------

func detectAnomalies(baseline, resp *ResponseInfo) []string {
	var reasons []string

	if resp.Error != "" {
		reasons = append(reasons, "request_error: "+resp.Error)
		return reasons
	}

	// Status code changed.
	if resp.StatusCode != baseline.StatusCode {
		reasons = append(reasons, fmt.Sprintf("status_change: %d → %d", baseline.StatusCode, resp.StatusCode))
	}

	// 5xx — possible crash or unhandled exception.
	if resp.StatusCode >= 500 {
		reasons = append(reasons, fmt.Sprintf("server_error: %d", resp.StatusCode))
	}

	// Significant size change (> 3x or < 1/3).
	if baseline.BodySize > 0 && resp.BodySize > 0 {
		ratio := float64(resp.BodySize) / float64(baseline.BodySize)
		if ratio > 3.0 || ratio < 0.33 {
			reasons = append(reasons, fmt.Sprintf("size_change: %d → %d (%.1fx)", baseline.BodySize, resp.BodySize, ratio))
		}
	}

	// Response time anomaly (> 5x baseline or > 10 seconds absolute).
	if baseline.ResponseTime > 0 && resp.ResponseTime > 0 {
		ratio := float64(resp.ResponseTime) / float64(baseline.ResponseTime)
		if ratio > 5.0 || resp.ResponseTime > 10000 {
			reasons = append(reasons, fmt.Sprintf("slow_response: %vms (baseline %vms, %.1fx)",
				resp.ResponseTime, baseline.ResponseTime, ratio))
		}
	}

	// Crash/error indicators in body.
	snippet := strings.ToLower(resp.BodySnippet)
	crashIndicators := []string{
		"stack trace", "stacktrace", "panic:", "runtime error",
		"segmentation fault", "internal server error", "unhandled exception",
		"traceback (most recent", "fatal error", "null pointer",
		"java.lang.", "at com.", "at org.", "sql syntax",
		"syntax error", "undefined is not", "cannot read propert",
	}
	for _, ind := range crashIndicators {
		if strings.Contains(snippet, ind) {
			reasons = append(reasons, "crash_indicator: "+ind)
			break
		}
	}

	return reasons
}

// ---------- mutation generation ----------

func generateMutations(ct, bodyTemplate string) []Mutation {
	var mutations []Mutation

	isJSON := strings.Contains(ct, "json")

	if isJSON && bodyTemplate != "" {
		mutations = append(mutations, generateJSONMutations(bodyTemplate)...)
	}

	// Generic mutations that work for any content type.
	mutations = append(mutations, generateGenericMutations(bodyTemplate)...)

	// Content-type mismatch mutations.
	mutations = append(mutations, generateContentTypeMutations(ct, bodyTemplate)...)

	return mutations
}

func generateJSONMutations(bodyTemplate string) []Mutation {
	var mutations []Mutation

	// Parse the JSON to manipulate fields.
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(bodyTemplate), &parsed); err != nil {
		// Not a JSON object — try as-is with some generic mutations.
		return mutations
	}

	// --- Type confusion for each field ---
	for key, val := range parsed {
		// String → int
		if _, ok := val.(string); ok {
			mutations = append(mutations, jsonMutation(parsed, key, 12345,
				fmt.Sprintf("type_confusion_%s_str_to_int", key),
				fmt.Sprintf("Change string field %q to integer", key)))
			// String → bool
			mutations = append(mutations, jsonMutation(parsed, key, true,
				fmt.Sprintf("type_confusion_%s_str_to_bool", key),
				fmt.Sprintf("Change string field %q to boolean", key)))
			// String → null
			mutations = append(mutations, jsonMutation(parsed, key, nil,
				fmt.Sprintf("type_confusion_%s_str_to_null", key),
				fmt.Sprintf("Change string field %q to null", key)))
			// String → array
			mutations = append(mutations, jsonMutation(parsed, key, []interface{}{"a", "b"},
				fmt.Sprintf("type_confusion_%s_str_to_array", key),
				fmt.Sprintf("Change string field %q to array", key)))
			// String → object
			mutations = append(mutations, jsonMutation(parsed, key, map[string]interface{}{"$gt": ""},
				fmt.Sprintf("type_confusion_%s_str_to_object", key),
				fmt.Sprintf("Change string field %q to object (NoSQL injection probe)", key)))
		}

		// Number → string
		if _, ok := val.(float64); ok {
			mutations = append(mutations, jsonMutation(parsed, key, "NaN",
				fmt.Sprintf("type_confusion_%s_num_to_str", key),
				fmt.Sprintf("Change number field %q to string", key)))
			mutations = append(mutations, jsonMutation(parsed, key, nil,
				fmt.Sprintf("type_confusion_%s_num_to_null", key),
				fmt.Sprintf("Change number field %q to null", key)))
		}

		// --- Boundary values ---
		mutations = append(mutations, jsonMutation(parsed, key, "",
			fmt.Sprintf("boundary_%s_empty_string", key),
			fmt.Sprintf("Set field %q to empty string", key)))
		mutations = append(mutations, jsonMutation(parsed, key, 0,
			fmt.Sprintf("boundary_%s_zero", key),
			fmt.Sprintf("Set field %q to 0", key)))
		mutations = append(mutations, jsonMutation(parsed, key, -1,
			fmt.Sprintf("boundary_%s_negative", key),
			fmt.Sprintf("Set field %q to -1", key)))
		mutations = append(mutations, jsonMutation(parsed, key, math.MaxInt32,
			fmt.Sprintf("boundary_%s_maxint32", key),
			fmt.Sprintf("Set field %q to MAX_INT32", key)))
		mutations = append(mutations, jsonMutation(parsed, key, strings.Repeat("A", 10240),
			fmt.Sprintf("boundary_%s_long_string", key),
			fmt.Sprintf("Set field %q to 10KB string", key)))

		// --- Encoding mutations ---
		mutations = append(mutations, jsonMutation(parsed, key, "test\x00injected",
			fmt.Sprintf("encoding_%s_null_byte", key),
			fmt.Sprintf("Null byte injection in field %q", key)))
		mutations = append(mutations, jsonMutation(parsed, key, "\u202etest",
			fmt.Sprintf("encoding_%s_unicode_override", key),
			fmt.Sprintf("Unicode right-to-left override in field %q", key)))
		mutations = append(mutations, jsonMutation(parsed, key, "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			fmt.Sprintf("encoding_%s_double_encoded_path", key),
			fmt.Sprintf("Double-encoded path traversal in field %q", key)))
	}

	// --- Missing fields: remove each one ---
	for key := range parsed {
		reduced := copyMap(parsed)
		delete(reduced, key)
		body, _ := json.Marshal(reduced)
		mutations = append(mutations, Mutation{
			Name:        fmt.Sprintf("missing_field_%s", key),
			Description: fmt.Sprintf("Remove field %q from request", key),
			Body:        string(body),
		})
	}

	// --- Duplicate fields ---
	// JSON technically allows duplicate keys; we build the raw string.
	for key, val := range parsed {
		valBytes, _ := json.Marshal(val)
		dupBytes, _ := json.Marshal("DUPLICATE")
		raw := fmt.Sprintf(`{%q:%s, %q:%s}`, key, string(valBytes), key, string(dupBytes))
		mutations = append(mutations, Mutation{
			Name:        fmt.Sprintf("duplicate_field_%s", key),
			Description: fmt.Sprintf("Duplicate key %q with conflicting value", key),
			Body:        raw,
		})
	}

	// --- Whole-body edge cases ---
	mutations = append(mutations,
		Mutation{Name: "empty_object", Description: "Send empty JSON object", Body: "{}"},
		Mutation{Name: "empty_array", Description: "Send JSON array instead of object", Body: "[]"},
		Mutation{Name: "null_body", Description: "Send JSON null", Body: "null"},
		Mutation{Name: "nested_deep", Description: "Deeply nested object (100 levels)",
			Body: deepNest(100)},
		Mutation{Name: "array_of_objects", Description: "Wrap body in array",
			Body: "[" + bodyTemplate + "," + bodyTemplate + "]"},
	)

	return mutations
}

func generateGenericMutations(bodyTemplate string) []Mutation {
	return []Mutation{
		{Name: "empty_body", Description: "Send completely empty body", Body: ""},
		{Name: "whitespace_body", Description: "Body is only whitespace", Body: "   \n\t  "},
		{Name: "xml_injection", Description: "Send XML instead of expected format",
			Body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`},
		{Name: "huge_body", Description: "Send 100KB body", Body: strings.Repeat("A", 100*1024)},
		{Name: "unicode_snowman", Description: "Unicode stress test",
			Body: strings.Repeat("\u2603\U0001F4A9\u0000", 100)},
		{Name: "form_encoded", Description: "Send form-encoded data",
			Body: "key=value&admin=true&__proto__[isAdmin]=true"},
	}
}

func generateContentTypeMutations(ct, bodyTemplate string) []Mutation {
	var mutations []Mutation

	if strings.Contains(ct, "json") {
		// Send the JSON body but claim it is form-encoded.
		mutations = append(mutations, Mutation{
			Name:        "ct_mismatch_json_as_form",
			Description: "Send JSON body with form-urlencoded Content-Type",
			ContentType: "application/x-www-form-urlencoded",
			Body:        bodyTemplate,
		})
		mutations = append(mutations, Mutation{
			Name:        "ct_mismatch_json_as_xml",
			Description: "Send JSON body with XML Content-Type",
			ContentType: "application/xml",
			Body:        bodyTemplate,
		})
		mutations = append(mutations, Mutation{
			Name:        "ct_mismatch_json_as_text",
			Description: "Send JSON body with text/plain Content-Type",
			ContentType: "text/plain",
			Body:        bodyTemplate,
		})
	} else if strings.Contains(ct, "form") {
		mutations = append(mutations, Mutation{
			Name:        "ct_mismatch_form_as_json",
			Description: "Send form body with JSON Content-Type",
			ContentType: "application/json",
			Body:        bodyTemplate,
		})
	}

	return mutations
}

// ---------- helpers ----------

func jsonMutation(original map[string]interface{}, key string, newVal interface{}, name, desc string) Mutation {
	m := copyMap(original)
	m[key] = newVal
	body, _ := json.Marshal(m)
	return Mutation{Name: name, Description: desc, Body: string(body)}
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func deepNest(levels int) string {
	var buf bytes.Buffer
	for i := 0; i < levels; i++ {
		buf.WriteString(`{"a":`)
	}
	buf.WriteString(`"end"`)
	for i := 0; i < levels; i++ {
		buf.WriteString(`}`)
	}
	return buf.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}

