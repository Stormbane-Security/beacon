// Package deserial fingerprints HTTP responses for insecure deserialization
// indicators. It looks for magic bytes and patterns associated with Java, PHP,
// and Python deserialization in HTTP responses, and tests whether endpoints
// accept and process serialized objects.
//
// Deep mode only (active POST probes with deserialization payloads).
package deserial

import (
	"bytes"
	"context"
	"encoding/base64"
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
	scannerName = "deserial"
	maxBodySize = 64 * 1024
)

// Java serialized object magic bytes: 0xACED0005
var javaMagic = []byte{0xAC, 0xED, 0x00, 0x05}

// javaMagicB64 is a base64-encoded Java serialized object header (commonly
// sent in HTTP parameters when apps serialize to base64).
const javaMagicB64 = "rO0AB" // base64 of 0xACED0005...

// phpSerializedPrefix indicates PHP serialize() output.
const phpSerializedPrefix = "O:"

// probePaths are paths likely to accept or return serialized objects.
var probePaths = []string{
	"/api",
	"/api/v1",
	"/api/v2",
	"/rpc",
	"/invoke",
	"/execute",
	"/deserialize",
	"/object",
	"/session",
	"/viewstate",
}

// Scanner fingerprints for insecure deserialization vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the deserialization scan. Deep mode only.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding

	// Check 1: do any responses contain Java/PHP serialized object magic bytes?
	if f := scanResponsesForMagicBytes(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// Check 2: does any endpoint accept and process a Java serialized object?
	if f := probeJavaDeserialization(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// scanResponsesForMagicBytes checks GET responses for deserialization magic bytes.
func scanResponsesForMagicBytes(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range probePaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		bodyStr := string(body)
		detected := ""
		lang := ""

		if bytes.Contains(body, javaMagic) || strings.Contains(bodyStr, javaMagicB64) {
			detected = "Java serialized object magic bytes (0xACED0005)"
			lang = "Java"
		} else if strings.Contains(bodyStr, phpSerializedPrefix) && strings.Contains(bodyStr, "{s:") {
			detected = "PHP serialized object pattern (O:...{s:...})"
			lang = "PHP"
		}

		if detected == "" {
			continue
		}

		return &finding.Finding{
			CheckID:  finding.CheckWebInsecureDeserialize,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Serialized Object Detected in Response (%s)", lang),
			Description: fmt.Sprintf(
				"The endpoint %s%s returned data containing %s. "+
					"Applications that serialize/deserialize user-controlled objects are vulnerable to "+
					"remote code execution if an attacker can supply a crafted serialized payload.",
				base, path, detected),
			Asset:    asset,
			DeepOnly: true,
			ProofCommand: fmt.Sprintf(
				`curl -s '%s%s' | xxd | head -5`, base, path),
			Evidence: map[string]any{
				"url":      base + path,
				"detected": detected,
				"language": lang,
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// probeJavaDeserialization sends a base64-encoded Java serialized header to
// common endpoints and checks whether the server returns a 500 with a Java
// exception (indicating the payload was deserialized and failed).
func probeJavaDeserialization(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Minimal valid Java serialized object header (no gadget chain — just header bytes).
	// A vulnerable server will try to deserialize it and throw an exception.
	javaPayload := base64.StdEncoding.EncodeToString(append(javaMagic, 0x73, 0x72, 0x00, 0x04, 0x54, 0x65, 0x73, 0x74))

	for _, path := range probePaths {
		url := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
			strings.NewReader(javaPayload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-java-serialized-object")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		bodyStr := string(body)
		// Java deserialization exceptions expose the stack trace or class name.
		if resp.StatusCode == http.StatusInternalServerError &&
			(strings.Contains(bodyStr, "ClassNotFoundException") ||
				strings.Contains(bodyStr, "InvalidClassException") ||
				strings.Contains(bodyStr, "java.io.") ||
				strings.Contains(bodyStr, "StreamCorruptedException")) {
			return &finding.Finding{
				CheckID:  finding.CheckWebInsecureDeserialize,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    "Java Deserialization Endpoint Detected",
				Description: fmt.Sprintf(
					"The endpoint %s returned a Java deserialization exception when sent a crafted "+
						"serialized object. This indicates the endpoint deserializes user input, making "+
						"it a candidate for remote code execution via a known gadget chain (e.g. ysoserial).",
					url),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`# Use ysoserial to generate a payload, then:\ncurl -s -X POST '%s' -H 'Content-Type: application/x-java-serialized-object' --data-binary @payload.ser`,
					url),
				Evidence: map[string]any{
					"url":    url,
					"status": resp.StatusCode,
					"error":  firstLine(bodyStr),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}


func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
