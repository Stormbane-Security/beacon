package cmsplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// wpscanOutput represents the top-level JSON output from wpscan.
type wpscanOutput struct {
	Plugins      map[string]wpscanPlugin `json:"plugins"`
	Themes       map[string]wpscanTheme  `json:"themes"`
	Users        []wpscanUser            `json:"users"`
	MainTheme    *wpscanTheme            `json:"main_theme"`
	Version      *wpscanVersion          `json:"version"`
	Interesting  []wpscanInteresting     `json:"interesting_findings"`
}

type wpscanPlugin struct {
	Slug            string              `json:"slug"`
	Version         *wpscanVersionInfo  `json:"version"`
	Vulnerabilities []wpscanVuln        `json:"vulnerabilities"`
}

type wpscanTheme struct {
	Slug            string              `json:"slug"`
	Version         *wpscanVersionInfo  `json:"version"`
	Vulnerabilities []wpscanVuln        `json:"vulnerabilities"`
}

type wpscanVersionInfo struct {
	Number string `json:"number"`
}

type wpscanVuln struct {
	Title      string           `json:"title"`
	References wpscanReferences `json:"references"`
}

type wpscanReferences struct {
	CVE []string `json:"cve"`
	URL []string `json:"url"`
}

type wpscanUser struct {
	ID   int    `json:"id"`
	Slug string `json:"slug"`
}

type wpscanVersion struct {
	Number string `json:"number"`
}

type wpscanInteresting struct {
	URL    string `json:"url"`
	Type   string `json:"type"`
	Entry  string `json:"to_s"`
}

// runWPScan shells out to wpscan for WordPress vulnerability scanning.
// Returns nil if wpscan is not installed or the --no-wpscan flag was used.
func runWPScan(ctx context.Context, targetURL, wpscanBin string) ([]finding.Finding, error) {
	if wpscanBin == "" {
		return nil, nil
	}

	// Check if wpscan exists in PATH.
	binPath, err := exec.LookPath(wpscanBin)
	if err != nil {
		return nil, nil // silently skip — optional tool
	}

	args := []string{
		"--url", targetURL,
		"--format", "json",
		"--enumerate", "p,t,u",
		"--no-banner",
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// wpscan may return non-zero when it finds vulnerabilities.
		// Check if we still got JSON output.
		if len(output) == 0 {
			if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
				output = exitErr.Stderr
			}
			// If we still have no output, try CombinedOutput approach.
			if len(output) == 0 {
				return nil, nil
			}
		}
	}

	return parseWPScanOutput(output, targetURL)
}

// parseWPScanOutput parses wpscan JSON output and returns findings.
// Exported for testing.
func parseWPScanOutput(data []byte, targetURL string) ([]finding.Finding, error) {
	var result wpscanOutput
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse wpscan output: %w", err)
	}

	asset := extractWPScanHost(targetURL)
	var findings []finding.Finding

	// Vulnerable plugins
	for slug, plugin := range result.Plugins {
		for _, vuln := range plugin.Vulnerabilities {
			ver := ""
			if plugin.Version != nil {
				ver = plugin.Version.Number
			}
			cves := strings.Join(vuln.References.CVE, ", ")
			desc := fmt.Sprintf(
				"wpscan identified a vulnerable WordPress plugin: %s", vuln.Title)
			if cves != "" {
				desc += fmt.Sprintf(" (CVE: %s)", cves)
			}

			ev := map[string]any{
				"tool":       "wpscan",
				"plugin":     slug,
				"vuln_title": vuln.Title,
			}
			if ver != "" {
				ev["version"] = ver
			}
			if len(vuln.References.CVE) > 0 {
				ev["cves"] = vuln.References.CVE
			}
			if len(vuln.References.URL) > 0 {
				ev["references"] = vuln.References.URL
			}

			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCMSPluginVulnerable,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceVerified,
				Title:       fmt.Sprintf("Vulnerable WordPress plugin: %s v%s", slug, ver),
				Description: desc,
				Asset:       asset,
				Evidence:    ev,
				ProofCommand: fmt.Sprintf(
					"wpscan --url '%s' --enumerate p --format json --no-banner", targetURL),
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Vulnerable themes
	for slug, theme := range result.Themes {
		for _, vuln := range theme.Vulnerabilities {
			ver := ""
			if theme.Version != nil {
				ver = theme.Version.Number
			}
			cves := strings.Join(vuln.References.CVE, ", ")
			desc := fmt.Sprintf(
				"wpscan identified a vulnerable WordPress theme: %s", vuln.Title)
			if cves != "" {
				desc += fmt.Sprintf(" (CVE: %s)", cves)
			}

			ev := map[string]any{
				"tool":       "wpscan",
				"theme":      slug,
				"vuln_title": vuln.Title,
			}
			if ver != "" {
				ev["version"] = ver
			}
			if len(vuln.References.CVE) > 0 {
				ev["cves"] = vuln.References.CVE
			}

			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCMSPluginVulnerable,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceVerified,
				Title:       fmt.Sprintf("Vulnerable WordPress theme: %s v%s", slug, ver),
				Description: desc,
				Asset:       asset,
				Evidence:    ev,
				ProofCommand: fmt.Sprintf(
					"wpscan --url '%s' --enumerate t --format json --no-banner", targetURL),
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Enumerated users
	if len(result.Users) > 0 {
		var userSlugs []string
		for _, u := range result.Users {
			userSlugs = append(userSlugs, u.Slug)
		}
		findings = append(findings, finding.Finding{
			CheckID:    finding.CheckCMSPluginFound,
			Module:     "surface",
			Scanner:    scannerName,
			Severity:   finding.SeverityMedium,
			Confidence: finding.ConfidenceVerified,
			Title:      fmt.Sprintf("WordPress user enumeration: %d users found", len(result.Users)),
			Description: fmt.Sprintf(
				"wpscan enumerated %d WordPress users: %s. "+
					"These usernames can be used for brute-force attacks.",
				len(result.Users), strings.Join(userSlugs, ", ")),
			Asset: asset,
			Evidence: map[string]any{
				"tool":       "wpscan",
				"user_count": len(result.Users),
				"usernames":  userSlugs,
			},
			ProofCommand: fmt.Sprintf(
				"wpscan --url '%s' --enumerate u --format json --no-banner", targetURL),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// extractWPScanHost pulls the host from a URL string.
func extractWPScanHost(rawURL string) string {
	s := rawURL
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	return s
}
