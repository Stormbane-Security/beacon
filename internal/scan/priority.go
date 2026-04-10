// Package scan — target prioritization for mass-scope automation.
// Sorts discovered assets by "interestingness" so the most valuable findings
// surface early in multi-target scans.
package scan

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PrioritizeTargets sorts a list of discovered assets by how "interesting"
// they are for security testing. Interesting = more attack surface.
// Returns the same slice sorted in descending interest order (most interesting first).
func PrioritizeTargets(ctx context.Context, assets []string) []string {
	type scored struct {
		asset string
		score int
	}

	results := make([]scored, len(assets))
	for i, a := range assets {
		results[i] = scored{asset: a, score: InterestScore(ctx, a)}
	}

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.asset
	}
	return out
}

// InterestScore returns a 0-100 score for how interesting a target is.
// Higher = more likely to have vulnerabilities worth testing.
// Uses fast heuristics that don't require network requests:
//   - Subdomain name patterns (staging, dev, admin, api)
//   - Presence of non-standard ports
//   - Evidence from the scan context if available
//
// Network-dependent scoring (login forms, API endpoints, software versions)
// is done via InterestScoreWithEvidence when classify evidence is available.
func InterestScore(ctx context.Context, asset string) int {
	score := 50 // baseline

	hostname := strings.SplitN(asset, ":", 2)[0]
	port := ""
	if parts := strings.SplitN(asset, ":", 2); len(parts) == 2 {
		port = parts[1]
	}

	// Has non-standard port: +20 (services to explore).
	if port != "" && port != "80" && port != "443" {
		score += 20
	}

	// Is a staging/dev/test subdomain: +20 (often less secured).
	if isStagingSubdomain(hostname) {
		score += 20
	}

	// Is an admin/management subdomain: +25 (high-value target).
	if isAdminSubdomain(hostname) {
		score += 25
	}

	// Is an API subdomain: +15 (business logic to test).
	if isAPISubdomain(hostname) {
		score += 15
	}

	// Cap at 100.
	if score > 100 {
		score = 100
	}

	return score
}

// InterestScoreWithEvidence enhances the interest score using classify-phase
// evidence collected during the scan. Called after evidence is available.
func InterestScoreWithEvidence(ctx context.Context, asset string, ev *AssetEvidence) int {
	score := InterestScore(ctx, asset)

	if ev == nil {
		return score
	}

	if ev.HasLoginForm {
		score += 15 // authenticated content behind it
	}
	if ev.HasAPIEndpoints {
		score += 15 // business logic to test
	}
	if ev.HasDefaultCreds {
		score += 30 // instant win
	}
	if ev.HasAdminPanel {
		score += 25 // high-value target
	}
	if ev.HasOldSoftware {
		score += 10 // likely unpatched
	}
	if ev.HasOpenPorts {
		score += 20 // services to explore
	}
	if ev.IsStaticOnly {
		score -= 20 // boring
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// AssetEvidence holds classify-phase signals used for interest scoring.
// Populated by the surface module after evidence collection.
type AssetEvidence struct {
	HasLoginForm    bool // detected login/auth form
	HasAPIEndpoints bool // discovered API paths
	HasDefaultCreds bool // default credentials work
	HasAdminPanel   bool // admin panel exposed
	HasOldSoftware  bool // outdated software versions
	HasOpenPorts    bool // ports beyond 80/443
	IsStaticOnly    bool // only static content + standard headers
}

// ── Quick-probe helpers ───────────────────────────────────────────────────

// QuickProbeEvidence performs lightweight HTTP probes to populate AssetEvidence.
// Used when full classify evidence isn't available yet. Timeout: 5s per request.
func QuickProbeEvidence(ctx context.Context, asset string) *AssetEvidence {
	ev := &AssetEvidence{}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Probe the main page for login forms and admin panels.
	for _, scheme := range []string{"https", "http"} {
		body, status := quickFetch(ctx, client, scheme+"://"+asset+"/")
		if status == 0 {
			continue
		}

		bodyLower := strings.ToLower(body)
		if strings.Contains(bodyLower, "type=\"password\"") || strings.Contains(bodyLower, "type='password'") {
			ev.HasLoginForm = true
		}
		if loginFormRe.MatchString(bodyLower) {
			ev.HasLoginForm = true
		}
		if adminPanelRe.MatchString(bodyLower) {
			ev.HasAdminPanel = true
		}

		// Check for API indicators.
		if strings.Contains(body, "/api/") || strings.Contains(body, "swagger") || strings.Contains(body, "graphql") {
			ev.HasAPIEndpoints = true
		}

		// Check for old software version headers.
		break // one successful probe is enough
	}

	return ev
}

func quickFetch(ctx context.Context, client *http.Client, rawURL string) (string, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer func() { _ = resp.Body.Close() }()

	// Read limited body for pattern matching.
	buf := make([]byte, 64*1024) // 64KB
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]), resp.StatusCode
}

// ── Pattern matchers ──────────────────────────────────────────────────────

var (
	stagingRe  = regexp.MustCompile(`(?i)^(staging|stage|stg|dev|develop|development|test|testing|qa|uat|sandbox|preview|demo|beta|canary|internal|preprod|pre-prod)\.`)
	adminRe    = regexp.MustCompile(`(?i)^(admin|administrator|manage|management|portal|console|dashboard|backoffice|back-office|cp|panel|cms)\.`)
	apiRe      = regexp.MustCompile(`(?i)^(api|apis|gateway|gw|rest|graphql|grpc|ws|websocket|webhook|webhooks)\.`)
	loginFormRe  = regexp.MustCompile(`(?i)(?:action\s*=\s*["'][^"']*(?:login|signin|auth|session))`)
	adminPanelRe = regexp.MustCompile(`(?i)(?:<title>[^<]*(?:admin|dashboard|panel|console|management)[^<]*</title>)`)
)

func isStagingSubdomain(hostname string) bool {
	return stagingRe.MatchString(hostname)
}

func isAdminSubdomain(hostname string) bool {
	return adminRe.MatchString(hostname)
}

func isAPISubdomain(hostname string) bool {
	return apiRe.MatchString(hostname)
}
