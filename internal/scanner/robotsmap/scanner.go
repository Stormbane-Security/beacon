// Package robotsmap parses robots.txt and sitemap.xml for sensitive path
// disclosure, admin panel references, and other information leakage.
package robotsmap

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckRobotsCrawlDelay, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckRobotsSensitivePath, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckSitemapSensitiveURL, finding.SeverityMedium, finding.ModeSurface),
	)
}

const scannerName = "robotsmap"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// sensitivePatterns are path substrings that indicate sensitive endpoints
// when found in robots.txt Disallow directives.
var sensitivePatterns = []string{
	"/admin", "/wp-admin", "/phpmyadmin", "/cpanel", "/webmail",
	"/api/internal", "/debug", "/status", "/health", "/.env",
	"/backup", "/dump", "/sql", "/db", "/console", "/shell",
	"/config", "/secret", "/private", "/internal", "/staging",
	"/test", "/dev", "/jenkins", "/grafana", "/kibana",
	"/elasticsearch", "/solr", "/actuator", "/metrics", "/trace",
	"/swagger", "/graphql", "/graphiql", "/.git", "/.svn",
	"/server-status", "/server-info", "/phpinfo", "/info.php",
	"/wp-login", "/wp-includes", "/cgi-bin", "/manager",
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var findings []finding.Finding
	now := time.Now()

	// Parse robots.txt
	robotsFindings := s.parseRobots(ctx, client, asset, now)
	findings = append(findings, robotsFindings...)

	// Parse sitemap.xml
	sitemapFindings := s.parseSitemap(ctx, client, asset, now)
	findings = append(findings, sitemapFindings...)

	return findings, nil
}

func (s *Scanner) parseRobots(ctx context.Context, client *http.Client, asset string, now time.Time) []finding.Finding {
	url := "https://" + asset + "/robots.txt"
	body, err := fetchBody(ctx, client, url)
	if err != nil {
		url = "http://" + asset + "/robots.txt"
		body, err = fetchBody(ctx, client, url)
		if err != nil {
			return nil
		}
	}

	var findings []finding.Finding
	var sensitiveDisallows []string
	hasCrawlDelay := false

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, line[:len("Disallow:")]))
			pathLower := strings.ToLower(path)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(pathLower, pattern) {
					sensitiveDisallows = append(sensitiveDisallows, path)
					break
				}
			}
		}

		if strings.HasPrefix(lower, "crawl-delay:") {
			hasCrawlDelay = true
		}
	}

	if len(sensitiveDisallows) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckRobotsSensitivePath,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Asset:       asset,
			Title:       fmt.Sprintf("robots.txt reveals %d sensitive path(s) on %s", len(sensitiveDisallows), asset),
			Description: "The robots.txt file contains Disallow directives for paths that suggest admin panels, debug endpoints, or internal infrastructure. While robots.txt prevents crawlers, it publicly advertises these paths to attackers.",
			Evidence: map[string]any{
				"sensitive_paths": sensitiveDisallows,
				"url":            url,
			},
			ProofCommand: fmt.Sprintf("curl -s %s | grep -i disallow", url),
			DiscoveredAt: now,
		})
	}

	if hasCrawlDelay {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckRobotsCrawlDelay,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityInfo,
			Asset:       asset,
			Title:       fmt.Sprintf("robots.txt Crawl-delay set on %s", asset),
			Description: "The robots.txt file includes a Crawl-delay directive, suggesting the server has resource constraints or wants to throttle automated requests.",
			Evidence:    map[string]any{"url": url},
			ProofCommand: fmt.Sprintf("curl -s %s | grep -i crawl-delay", url),
			DiscoveredAt: now,
		})
	}

	return findings
}

type urlset struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

func (s *Scanner) parseSitemap(ctx context.Context, client *http.Client, asset string, now time.Time) []finding.Finding {
	url := "https://" + asset + "/sitemap.xml"
	body, err := fetchBody(ctx, client, url)
	if err != nil {
		url = "http://" + asset + "/sitemap.xml"
		body, err = fetchBody(ctx, client, url)
		if err != nil {
			return nil
		}
	}

	// Check for XML content.
	if !strings.Contains(body, "<url") {
		return nil
	}

	var us urlset
	if err := xml.Unmarshal([]byte(body), &us); err != nil {
		return nil
	}

	var sensitiveURLs []string
	for _, u := range us.URLs {
		lower := strings.ToLower(u.Loc)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(lower, pattern) {
				sensitiveURLs = append(sensitiveURLs, u.Loc)
				break
			}
		}
	}

	if len(sensitiveURLs) == 0 {
		return nil
	}

	return []finding.Finding{{
		CheckID:     finding.CheckSitemapSensitiveURL,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityMedium,
		Asset:       asset,
		Title:       fmt.Sprintf("sitemap.xml reveals %d sensitive URL(s) on %s", len(sensitiveURLs), asset),
		Description: "The sitemap.xml file references URLs that appear to be admin, internal, or debug endpoints. These URLs are publicly indexed and discoverable by search engines and attackers.",
		Evidence: map[string]any{
			"sensitive_urls": sensitiveURLs,
			"url":           url,
		},
		ProofCommand: fmt.Sprintf("curl -s %s | grep -i '<loc>'", url),
		DiscoveredAt: now,
	}}
}

func fetchBody(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return "", err
	}
	return string(body), nil
}
