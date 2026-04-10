package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// HAR format types following the HTTP Archive 1.2 spec.
// See: http://www.softwareishard.com/blog/har-12-spec/

type harLog struct {
	Log harLogBody `json:"log"`
}

type harLogBody struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
	Comment         string      `json:"comment"`
}

type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harNVP    `json:"headers"`
	QueryString []harNVP    `json:"queryString"`
	Cookies     []harCookie `json:"cookies"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harNVP    `json:"headers"`
	Content     harContent  `json:"content"`
	Cookies     []harCookie `json:"cookies"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

type harNVP struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RenderHAR produces an HTTP Archive 1.2 JSON document from findings.
// Each finding becomes a HAR entry, with the request reconstructed from
// ProofCommand (curl). This lets bounty hunters import beacon findings
// directly into Burp Suite, OWASP ZAP, or any HAR-consuming tool.
func RenderHAR(findings []finding.Finding) ([]byte, error) {
	entries := make([]harEntry, 0, len(findings))

	for _, f := range findings {
		method, reqURL, headers := parseCurlCommand(f.ProofCommand)

		// Fall back to asset as URL if we couldn't parse one from ProofCommand.
		if reqURL == "" {
			reqURL = buildFallbackURL(f)
		}

		// Parse query string from URL.
		var queryString []harNVP
		if parsed, err := url.Parse(reqURL); err == nil && parsed.RawQuery != "" {
			for key, vals := range parsed.Query() {
				for _, v := range vals {
					queryString = append(queryString, harNVP{Name: key, Value: v})
				}
			}
		}

		// Extract response status from evidence if available.
		status := 200
		statusText := "OK"
		if sc, ok := f.Evidence["status_code"]; ok {
			switch v := sc.(type) {
			case float64:
				status = int(v)
			case int:
				status = v
			}
			statusText = statusTextForCode(status)
		}

		// Response content type from evidence.
		mimeType := "text/html"
		if ct, ok := f.Evidence["content_type"].(string); ok && ct != "" {
			mimeType = ct
		}

		ts := f.DiscoveredAt
		if ts.IsZero() {
			ts = time.Now()
		}

		entry := harEntry{
			StartedDateTime: ts.Format(time.RFC3339),
			Time:            0,
			Request: harRequest{
				Method:      method,
				URL:         reqURL,
				HTTPVersion: "HTTP/1.1",
				Headers:     headers,
				QueryString: queryString,
				Cookies:     []harCookie{},
				HeadersSize: -1,
				BodySize:    -1,
			},
			Response: harResponse{
				Status:      status,
				StatusText:  statusText,
				HTTPVersion: "HTTP/1.1",
				Headers:     []harNVP{},
				Content:     harContent{Size: 0, MimeType: mimeType},
				Cookies:     []harCookie{},
				HeadersSize: -1,
				BodySize:    -1,
			},
			Cache:   struct{}{},
			Timings: harTimings{Send: 0, Wait: 0, Receive: 0},
			Comment: fmt.Sprintf("beacon finding: %s - %s", f.CheckID, f.Title),
		}

		entries = append(entries, entry)
	}

	har := harLog{
		Log: harLogBody{
			Version: "1.2",
			Creator: harCreator{Name: "Beacon", Version: "0.x"},
			Entries: entries,
		},
	}

	return json.MarshalIndent(har, "", "  ")
}

// parseCurlCommand extracts method, URL, and headers from a curl command string.
// Handles common patterns: curl -X METHOD, curl -H "Header: Value", bare curl URL.
func parseCurlCommand(cmd string) (method, reqURL string, headers []harNVP) {
	method = "GET"
	if cmd == "" {
		return method, "", nil
	}

	// Tokenize respecting quoted strings.
	tokens := tokenizeCurl(cmd)

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case tok == "-X" || tok == "--request":
			if i+1 < len(tokens) {
				i++
				method = strings.ToUpper(tokens[i])
			}
		case tok == "-H" || tok == "--header":
			if i+1 < len(tokens) {
				i++
				hdr := tokens[i]
				if idx := strings.Index(hdr, ":"); idx > 0 {
					headers = append(headers, harNVP{
						Name:  strings.TrimSpace(hdr[:idx]),
						Value: strings.TrimSpace(hdr[idx+1:]),
					})
				}
			}
		case tok == "-d" || tok == "--data" || tok == "--data-raw" || tok == "--data-binary":
			if i+1 < len(tokens) {
				i++ // skip the data argument
			}
		case tok == "-k" || tok == "--insecure" || tok == "-s" || tok == "--silent" ||
			tok == "-v" || tok == "--verbose" || tok == "-L" || tok == "--location" ||
			tok == "-I" || tok == "--head":
			// flag without argument — skip
			if tok == "-I" || tok == "--head" {
				method = "HEAD"
			}
		case tok == "-o" || tok == "--output" || tok == "--max-time" || tok == "--connect-timeout":
			if i+1 < len(tokens) {
				i++ // skip the argument
			}
		case strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://"):
			reqURL = tok
		case tok == "curl":
			// skip the command name itself
		}
	}

	return method, reqURL, headers
}

// tokenizeCurl splits a shell-like command into tokens, handling single and
// double-quoted strings. It doesn't handle all shell edge cases but covers the
// vast majority of ProofCommand curl invocations.
func tokenizeCurl(s string) []string {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case (ch == ' ' || ch == '\t' || ch == '\n') && !inSingle && !inDouble:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		case ch == '\\' && inDouble && i+1 < len(s):
			i++
			current.WriteByte(s[i])
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// buildFallbackURL constructs a URL from finding asset and evidence when
// no URL can be parsed from ProofCommand.
func buildFallbackURL(f finding.Finding) string {
	// Try evidence fields first.
	for _, key := range []string{"url", "matched_at", "endpoint", "path"} {
		if v, ok := f.Evidence[key].(string); ok && v != "" {
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				return v
			}
		}
	}

	// Build from asset.
	asset := f.Asset
	if !strings.HasPrefix(asset, "http://") && !strings.HasPrefix(asset, "https://") {
		asset = "https://" + asset
	}

	// Append path from evidence if available.
	if path, ok := f.Evidence["path"].(string); ok && path != "" {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		asset += path
	}

	return asset
}

// statusTextForCode returns a human-readable status text for common HTTP codes.
func statusTextForCode(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "OK"
	}
}
