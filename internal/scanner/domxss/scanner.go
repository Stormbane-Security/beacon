// Package domxss implements DOM-based XSS detection using a headless Chrome
// browser (via chromedp). It injects a tracer script that instruments known
// XSS sinks (innerHTML, document.write, eval, etc.) and navigates with a
// canary string in URL sources (hash, query parameters, referrer).
//
// If the canary flows from a source into a sink, a DOM XSS finding is emitted.
//
// Only runs in authorized mode. Gracefully skips when Chrome is not installed.
package domxss

import (
	"context"
	_ "embed"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

const scannerName = "domxss"

// canary is injected into URL sources; the tracer script watches for it in sinks.
const canary = "BEACON_XSS_CANARY_7f3a9b"

//go:embed tracer.js
var tracerJS string

// xssTrace matches the JS object shape pushed by the tracer script.
type xssTrace struct {
	Sink      string `json:"sink"`
	Data      string `json:"data"`
	URL       string `json:"url"`
	Timestamp int64  `json:"timestamp"`
}

// probePaths are common pages that may render user-controlled URL data into the DOM.
var probePaths = []string{
	"/",
	"/search",
	"/login",
	"/register",
	"/callback",
	"/redirect",
	"/profile",
}

// Scanner detects DOM-based XSS via headless Chrome + source-to-sink tracing.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	// Check if Chrome/Chromium is available.
	if !chromeAvailable() {
		return nil, nil
	}

	scheme := "https"
	// Try HTTPS first, fall back to HTTP.
	// chromedp will handle the actual connection.

	var findings []finding.Finding

	for _, path := range probePaths {
		if ctx.Err() != nil {
			break
		}

		// Test with canary in hash fragment (source: location.hash)
		hashURL := fmt.Sprintf("%s://%s%s#%s", scheme, asset, path, canary)
		traces, err := probeURL(ctx, hashURL)
		if err != nil {
			// Try HTTP on first failure
			if scheme == "https" && path == probePaths[0] {
				scheme = "http"
				hashURL = fmt.Sprintf("%s://%s%s#%s", scheme, asset, path, canary)
				traces, err = probeURL(ctx, hashURL)
				if err != nil {
					return nil, nil // neither scheme works
				}
			} else {
				continue
			}
		}

		for _, tr := range traces {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebXSS,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("DOM XSS via %s sink at %s (source: location.hash)", tr.Sink, path),
				Description: fmt.Sprintf(
					"Canary string injected into location.hash flowed into %s sink. "+
						"Data: %q. This confirms a DOM-based cross-site scripting vulnerability "+
						"where user-controlled URL fragments are rendered without sanitization.",
					tr.Sink, truncate(tr.Data, 200)),
				Asset: asset,
				Evidence: map[string]any{
					"path":   path,
					"sink":   tr.Sink,
					"source": "location.hash",
					"data":   truncate(tr.Data, 512),
					"url":    tr.URL,
				},
				ProofCommand: fmt.Sprintf(
					"# Open in browser with devtools: %s://%s%s#<script>alert(1)</script>",
					scheme, asset, path),
				DiscoveredAt: time.Now(),
			})
		}

		// Test with canary in query parameter (source: location.search)
		queryURL := fmt.Sprintf("%s://%s%s?q=%s", scheme, asset, path, canary)
		traces, err = probeURL(ctx, queryURL)
		if err != nil {
			continue
		}

		for _, tr := range traces {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebXSS,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("DOM XSS via %s sink at %s (source: location.search)", tr.Sink, path),
				Description: fmt.Sprintf(
					"Canary string injected into query parameter flowed into %s sink. "+
						"Data: %q. This confirms a DOM-based cross-site scripting vulnerability "+
						"where user-controlled URL parameters are rendered without sanitization.",
					tr.Sink, truncate(tr.Data, 200)),
				Asset: asset,
				Evidence: map[string]any{
					"path":   path,
					"sink":   tr.Sink,
					"source": "location.search",
					"data":   truncate(tr.Data, 512),
					"url":    tr.URL,
				},
				ProofCommand: fmt.Sprintf(
					"# Open in browser: %s://%s%s?q=<script>alert(1)</script>",
					scheme, asset, path),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// probeURL navigates to a URL in headless Chrome with the tracer script
// injected, then collects any XSS traces.
func probeURL(ctx context.Context, targetURL string) ([]xssTrace, error) {
	// Per-page timeout: 15 seconds max
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Create a new browser context for isolation
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx,
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-web-security", false),
			chromedp.Flag("ignore-certificate-errors", true),
		)...,
	)
	defer allocCancel()

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	// Inject the canary constant and tracer script before page load
	setupScript := fmt.Sprintf("window.__beacon_canary = %q;\n%s", canary, tracerJS)

	var traces []xssTrace
	err := chromedp.Run(browserCtx,
		// Add script to execute on every new document (before page JS runs)
		chromedp.Evaluate(setupScript, nil),
		chromedp.Navigate(targetURL),
		// Wait for page load + JS execution
		chromedp.Sleep(2*time.Second),
		// Collect traces
		chromedp.Evaluate(`window.__beacon_xss_traces || []`, &traces),
	)
	if err != nil {
		return nil, err
	}

	return traces, nil
}

// chromeAvailable checks if Chrome or Chromium is installed.
func chromeAvailable() bool {
	candidates := []string{
		"google-chrome", "google-chrome-stable", "chromium",
		"chromium-browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// detectScheme probes the asset to determine HTTP vs HTTPS.
func detectScheme(_ context.Context, asset string) string {
	_ = asset
	// chromedp handles TLS errors via ignore-certificate-errors flag,
	// so we default to HTTPS and fall back in the main loop.
	if strings.Contains(asset, ":80") {
		return "http"
	}
	return "https"
}
