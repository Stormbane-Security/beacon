// Package digitalocean implements authenticated DigitalOcean security scanning.
// It uses the DigitalOcean REST API v2 directly (no SDK dependency). All API
// calls are read-only.
package digitalocean

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

const (
	apiBase    = "https://api.digitalocean.com/v2"
	maxBody    = 10 << 20 // 10 MiB limit on response bodies
	scannerTag = "cloud/digitalocean"
)

// Config holds DigitalOcean authentication configuration.
type Config struct {
	// Token is the DigitalOcean personal access token.
	Token string
}

// Scanner runs authenticated DigitalOcean security checks.
type Scanner struct {
	cfg    Config
	client *http.Client

	// baseURL overrides apiBase for testing. When empty, the production
	// DigitalOcean API endpoint is used.
	baseURL string
}

// New creates a new DigitalOcean cloud scanner.
func New(cfg Config) *Scanner {
	return &Scanner{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetBaseURL overrides the API base URL. Used in tests to point the scanner
// at an httptest server.
func (s *Scanner) SetBaseURL(u string) { s.baseURL = u }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return scannerTag }

// Run implements scanner.Scanner.
// asset is the root domain being scanned -- used only for finding attribution.
func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	if s.cfg.Token == "" {
		return nil, fmt.Errorf("digitalocean: API token not configured")
	}

	var all []finding.Finding

	// Spaces checks.
	spacesFindings, err := scanSpaces(ctx, s, asset)
	if err != nil {
		all = append(all, scanError(asset, fmt.Sprintf("Spaces scan failed: %v", err)))
	} else {
		all = append(all, spacesFindings...)
	}

	// Droplet checks.
	dropletFindings, err := scanDroplets(ctx, s, asset)
	if err != nil {
		all = append(all, scanError(asset, fmt.Sprintf("Droplet scan failed: %v", err)))
	} else {
		all = append(all, dropletFindings...)
	}

	// Firewall checks.
	firewallFindings, err := scanFirewalls(ctx, s, asset)
	if err != nil {
		all = append(all, scanError(asset, fmt.Sprintf("Firewall scan failed: %v", err)))
	} else {
		all = append(all, firewallFindings...)
	}

	return all, nil
}

// doRequest performs an authenticated GET against the DigitalOcean API and
// decodes the JSON response into dst.
func (s *Scanner) doRequest(ctx context.Context, path string, dst any) error {
	base := apiBase
	if s.baseURL != "" {
		base = s.baseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API %s returned %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}

	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// scanError returns a scan-error finding for the DigitalOcean scanner.
func scanError(asset, description string) finding.Finding {
	return finding.Finding{
		CheckID:      finding.CheckCloudDOScanError,
		Title:        "DigitalOcean scan error",
		Description:  description,
		Severity:     finding.SeverityInfo,
		Asset:        asset,
		Scanner:      scannerTag,
		DiscoveredAt: time.Now(),
	}
}

// truncate shortens s to at most maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
