// Package vhost discovers virtual hosts on a server by probing the resolved IP
// with different Host: headers. When a server hosts multiple sites on one IP,
// only one site is reachable by its DNS name. Virtual host probing sends HTTP
// requests to the same IP with candidate hostnames, comparing responses to a
// baseline — sites with materially different content are likely real vhosts.
//
// Why this matters: internal apps (admin panels, staging sites, intranet tools)
// often share an IP with a public site but have separate DNS that isn't
// publicly listed. Finding them expands the attack surface.
package vhost

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "vhost"

// Scanner probes an asset's IP with candidate virtual host names.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// Run resolves asset to an IP via DNS, establishes a baseline response, then
// probes candidate hostnames to discover additional virtual hosts.
//
// Deep mode only: sending crafted Host headers to a shared IP could probe
// virtual hosts belonging to other tenants on shared infrastructure, which
// is inappropriate without explicit authorization.
//
// When the asset is behind a CDN, use RunWithOriginIP instead — pass the real
// backend IP so probes never hit shared CDN edge nodes.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, asset)
	if err != nil || len(addrs) == 0 {
		return nil, nil
	}
	return s.runWithIP(ctx, asset, addrs[0], scanType)
}

// RunWithOriginIP runs the vhost scan against a known origin IP, bypassing
// DNS resolution. Used when the asset is behind a CDN and the real backend IP
// has been discovered by wafdetect — ensures probes reach the target's own
// server and never hit shared CDN edge infrastructure.
func (s *Scanner) RunWithOriginIP(ctx context.Context, asset, originIP string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}
	return s.runWithIP(ctx, asset, originIP, scanType)
}

// runWithIP is the shared implementation used by both Run and RunWithOriginIP.
func (s *Scanner) runWithIP(ctx context.Context, asset, ip string, _ module.ScanType) ([]finding.Finding, error) {
	candidates := buildCandidates(asset)
	if len(candidates) == 0 {
		return nil, nil
	}

	client := buildClient(ip)

	// Baseline: fingerprint the asset itself so we can detect genuine differences.
	baseline := probeHost(ctx, client, ip, asset)
	if baseline == nil {
		return nil, nil // asset not serving HTTP/S — skip
	}

	var findings []finding.Finding
	now := time.Now()
	seen := map[string]bool{}

	for _, candidate := range candidates {
		if candidate == asset || seen[candidate] {
			continue
		}
		seen[candidate] = true

		resp := probeHost(ctx, client, ip, candidate)
		if resp == nil {
			continue
		}
		// Consider it a real vhost if the response differs meaningfully from baseline:
		// different status, substantially different content length, or different title.
		if !materiallyDifferent(baseline, resp) {
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckVHostFound,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("Virtual host discovered: %s at %s", candidate, ip),
			Description: fmt.Sprintf(
				"Probing %s with Host: %s returned a response materially different from the baseline "+
					"(status %d, body length %d). This indicates a separate virtual host responding on the same IP. "+
					"Review this host for additional attack surface — it may be an internal app, staging environment, "+
					"or admin interface not visible from public DNS.",
				ip, candidate, resp.status, resp.bodyLen),
			Evidence:     map[string]any{"ip": ip, "vhost": candidate, "status": resp.status, "body_length": resp.bodyLen, "title": resp.title},
			DiscoveredAt: now,
		})
	}

	return findings, nil
}

// hostResponse captures key response attributes for comparison.
type hostResponse struct {
	status  int
	bodyLen int
	title   string
}

// probeHost makes one HTTP GET to ip with Host: hostname and returns the fingerprint.
func probeHost(ctx context.Context, client *http.Client, ip, hostname string) *hostResponse {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + ip + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Host = hostname
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		return &hostResponse{
			status:  resp.StatusCode,
			bodyLen: len(body),
			title:   extractVHostTitle(string(body)),
		}
	}
	return nil
}

// materiallyDifferent returns true when r differs enough from baseline to
// indicate a genuinely different virtual host rather than the same site
// responding to any Host: header.
func materiallyDifferent(baseline, r *hostResponse) bool {
	if r.status != baseline.status {
		return true
	}
	// Substantial content length difference: >20% OR >500 bytes
	diff := r.bodyLen - baseline.bodyLen
	if diff < 0 {
		diff = -diff
	}
	if diff > 500 {
		larger := r.bodyLen
		if baseline.bodyLen > larger {
			larger = baseline.bodyLen
		}
		if larger > 0 && float64(diff)/float64(larger) > 0.20 {
			return true
		}
	}
	// Different page title is a strong signal
	if r.title != "" && baseline.title != "" && r.title != baseline.title {
		return true
	}
	return false
}

// buildCandidates generates candidate virtual host names to probe based on
// naming patterns common in corporate environments.
func buildCandidates(asset string) []string {
	parts := strings.SplitN(asset, ".", 2)
	if len(parts) < 2 {
		return nil
	}
	prefix := parts[0]
	domain := parts[1]

	// Common patterns: swap or add the prefix
	swapPrefixes := []string{
		"dev", "staging", "stage", "test", "uat", "qa",
		"admin", "internal", "intranet", "corp", "intra",
		"api", "app", "apps", "portal", "dashboard",
		"beta", "alpha", "preview", "demo", "sandbox",
		"vpn", "remote", "secure", "login", "auth",
	}

	seen := map[string]bool{asset: true}
	var candidates []string

	add := func(h string) {
		h = strings.ToLower(h)
		if !seen[h] {
			seen[h] = true
			candidates = append(candidates, h)
		}
	}

	// Swap the current prefix for each alternative
	for _, p := range swapPrefixes {
		if p != prefix {
			add(p + "." + domain)
		}
	}
	// Also try the bare domain and www
	add(domain)
	add("www." + domain)
	// Try adding prefixes to the current asset
	for _, p := range []string{"dev", "staging", "test"} {
		add(p + "-" + asset)
		add(p + "." + asset)
	}

	return candidates
}

// buildClient returns an HTTP client that connects to ip but honours
// arbitrary Host: headers (no TLS verification — we want to observe misconfigs).
func buildClient(ip string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // observe misconfigs
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Always connect to ip regardless of address in URL
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					port = "443"
				}
				d := &net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, ip+":"+port)
			},
		},
	}
}

func extractVHostTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}
