// Package fileupload detects file upload endpoints and probes them for MIME type
// confusion and dangerous extension bypasses.
//
// It discovers upload endpoints by looking for multipart/form-data forms in crawled
// HTML and by probing known upload paths, then attempts to upload files with:
//   - Double extensions (.php.jpg, .php.png)
//   - MIME type confusion (image/jpeg content with .php extension)
//   - Null byte injection (file.php%00.jpg)
//   - Content-type spoofing (claim image/gif, upload PHP)
//
// Deep mode only (active upload attempts).
package fileupload

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/schemedetect"
)

const (
	scannerName = "fileupload"
	maxBodySize = 32 * 1024
)

// uploadPaths are common file upload endpoint paths.
var uploadPaths = []string{
	"/upload",
	"/api/upload",
	"/api/v1/upload",
	"/api/v2/upload",
	"/file/upload",
	"/files/upload",
	"/media/upload",
	"/image/upload",
	"/images/upload",
	"/avatar",
	"/profile/avatar",
	"/api/avatar",
	"/attachments",
	"/api/attachments",
}

// bypassMutation represents a file upload bypass attempt.
type bypassMutation struct {
	name        string
	filename    string
	contentType string
	// body is the file content to send.
	body []byte
}

// safeCanary is an inert text marker used as upload file content.
// It contains no executable code and cannot be weaponised if left on the server.
// The bypass-detection logic relies on the *filename* and *Content-Type* being
// accepted, not on the file content — so a safe canary works identically.
const safeCanary = "beacon-security-test-file-do-not-execute"

// buildMutations returns the set of bypass mutations to attempt.
func buildMutations() []bypassMutation {
	canary := []byte(safeCanary)
	// GIF89a header prefix makes the file look like a valid GIF to naive
	// magic-byte checks, while the rest is inert text — not executable.
	gifCanary := append([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"), canary...)

	return []bypassMutation{
		{
			name:        "double extension (.php.jpg)",
			filename:    "beacon_test.php.jpg",
			contentType: "image/jpeg",
			body:        canary,
		},
		{
			name:        "MIME confusion (image/gif with dangerous extension)",
			filename:    "beacon_test.php",
			contentType: "image/gif",
			body:        gifCanary,
		},
		{
			name:        "null byte injection (.php%00.jpg)",
			filename:    "beacon_test.php\x00.jpg",
			contentType: "image/jpeg",
			body:        canary,
		},
		{
			name:        "SVG with inert content (type bypass)",
			filename:    "beacon_test.svg",
			contentType: "image/svg+xml",
			// Safe SVG — no script tag, just metadata. Detection is based on
			// filename acceptance (.svg to an upload endpoint meant for images).
			body: []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><title>beacon-test</title></svg>`),
		},
	}
}

// Scanner probes for file upload bypass vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the file upload bypass scan. Deep mode only.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := schemedetect.Base(ctx, client, asset)

	// Find upload endpoints.
	uploadEndpoints := discoverUploadEndpoints(ctx, client, base)
	if len(uploadEndpoints) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	mutations := buildMutations()

	for _, endpoint := range uploadEndpoints {
		for _, m := range mutations {
			f := probeUpload(ctx, client, asset, endpoint, m)
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

// discoverUploadEndpoints finds paths that respond to multipart POST requests.
func discoverUploadEndpoints(ctx context.Context, client *http.Client, base string) []string {
	var endpoints []string
	for _, path := range uploadPaths {
		url := base + path
		// Send a minimal multipart request to see if the endpoint exists.
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("file", "probe.txt")
		if err != nil {
			continue
		}
		fw.Write([]byte("beacon_probe"))
		mw.Close()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		resp.Body.Close()

		// Skip definitive "not found" and "not allowed" responses.
		if resp.StatusCode == http.StatusNotFound ||
			resp.StatusCode == http.StatusMethodNotAllowed ||
			resp.StatusCode == http.StatusNotImplemented {
			continue
		}

		// Auth/validation error codes indicate the endpoint exists but requires
		// authentication or enforces file validation — worth probing further.
		authOrValidation := resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusBadRequest ||
			resp.StatusCode == http.StatusUnprocessableEntity ||
			resp.StatusCode == http.StatusRequestEntityTooLarge

		// For 2xx responses we require the response NOT to be HTML — catch-all
		// SPA routes return 200+HTML for every path and are not upload endpoints.
		respCT := resp.Header.Get("Content-Type")
		isHTML := strings.Contains(respCT, "text/html")
		bodyStr := string(body)
		hasUploadSignal := strings.Contains(bodyStr, "upload") ||
			strings.Contains(bodyStr, "file") ||
			strings.Contains(bodyStr, `"url"`) ||
			strings.Contains(bodyStr, `"path"`)

		successWithoutHTML := resp.StatusCode >= 200 && resp.StatusCode < 300 && !isHTML

		if authOrValidation || successWithoutHTML || (resp.StatusCode >= 200 && resp.StatusCode < 300 && hasUploadSignal) {
			endpoints = append(endpoints, url)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return endpoints
}

// probeUpload attempts to upload a file with a bypass mutation and checks
// whether the server accepted it.
func probeUpload(ctx context.Context, client *http.Client, asset, endpoint string, m bypassMutation) *finding.Finding {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Create a form file part with custom Content-Type header.
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, m.filename))
	h.Set("Content-Type", m.contentType)
	fw, err := mw.CreatePart(h)
	if err != nil {
		return nil
	}
	fw.Write(m.body)
	mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()

	bodyStr := string(body)

	// Success indicators: 200/201 AND strong evidence the file was stored.
	// We require either:
	//   (a) the uploaded filename echoed back in the response (server stored it), OR
	//   (b) a specific JSON key indicating a file storage URL/path.
	// Broad keywords like "upload" or "path" are NOT used — they produce false
	// positives on error responses like {"error":"file upload not allowed"}.
	accepted := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated
	hasFileURL := strings.Contains(bodyStr, m.filename) ||
		strings.Contains(bodyStr, `"file_url"`) ||
		strings.Contains(bodyStr, `"fileUrl"`) ||
		strings.Contains(bodyStr, `"file_path"`) ||
		strings.Contains(bodyStr, `"filePath"`) ||
		strings.Contains(bodyStr, `"download_url"`) ||
		strings.Contains(bodyStr, `"downloadUrl"`) ||
		strings.Contains(bodyStr, `"storage_path"`) ||
		strings.Contains(bodyStr, `"storagePath"`)

	if !accepted || !hasFileURL {
		return nil
	}

	severity := finding.SeverityHigh
	if strings.Contains(m.filename, ".php") || strings.Contains(m.filename, ".svg") {
		severity = finding.SeverityCritical
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebFileUpload,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: severity,
		Title:    fmt.Sprintf("File Upload Bypass — %s", m.name),
		Description: fmt.Sprintf(
			"The upload endpoint %s accepted a file with mutation %q (filename=%q, content-type=%q). "+
				"If the server executes or serves this file, an attacker can achieve remote code execution "+
				"or cross-site scripting.",
			endpoint, m.name, m.filename, m.contentType),
		Asset:    asset,
		DeepOnly: true,
		ProofCommand: fmt.Sprintf(
			`curl -s -F 'file=@shell.php;filename=%s;type=%s' '%s'`,
			m.filename, m.contentType, endpoint),
		Evidence: map[string]any{
			"url":          endpoint,
			"mutation":     m.name,
			"filename":     m.filename,
			"content_type": m.contentType,
			"status":       resp.StatusCode,
		},
		DiscoveredAt: time.Now(),
	}
}

