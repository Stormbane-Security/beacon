// Package screenshot captures screenshots of discovered assets using chromedp
// (headless Chrome via DevTools Protocol). Screenshots provide visual evidence
// of what is exposed and are embedded in reports.
// Requires Chrome or Chromium to be installed. Skips gracefully if not available.
package screenshot

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return &Scanner{}
	},
		scan.Check(finding.CheckAssetScreenshot, finding.SeverityInfo, finding.ModeSurface),
	)
}

const scannerName = "screenshot"

// Scanner captures screenshots using chromedp (headless Chrome).
type Scanner struct{}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Skip entirely unless --screenshots was passed. Saves ~2.7s per asset
	// by avoiding Chrome startup when screenshots aren't needed.
	if sctx, ok := scan.FromContext(ctx); !ok || !sctx.ScreenshotsEnabled() {
		return nil, nil
	}

	if !hasBrowser() {
		return nil, nil
	}

	scheme := "https"
	if sctx, ok := scan.FromContext(ctx); ok {
		scheme = sctx.Scheme()
	}
	target := scheme + "://" + asset

	data, err := captureScreenshot(ctx, target)
	if err != nil || len(data) == 0 {
		// Retry with HTTP
		if scheme == "https" {
			target = "http://" + asset
			data, err = captureScreenshot(ctx, target)
			if err != nil || len(data) == 0 {
				return nil, nil
			}
		} else {
			return nil, nil
		}
	}

	b64 := base64.StdEncoding.EncodeToString(data)
	dataURI := "data:image/png;base64," + b64

	return []finding.Finding{{
		CheckID:      finding.CheckAssetScreenshot,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityInfo,
		Title:        fmt.Sprintf("Screenshot captured for %s", asset),
		Description:  fmt.Sprintf("A screenshot of %s was captured during the scan. This provides visual evidence of what is accessible.", asset),
		Asset:        asset,
		ProofCommand: fmt.Sprintf("curl -s '%s' | head -c 200", target),
		Evidence: map[string]any{
			"url":        target,
			"image_b64":  dataURI,
			"size_bytes": len(data),
		},
		DiscoveredAt: time.Now(),
	}}, nil
}

// captureScreenshot uses chromedp to take a full-page screenshot.
func captureScreenshot(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.WindowSize(1280, 800),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	var buf []byte
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // wait for page load
		chromedp.FullScreenshot(&buf, 90),
	)
	return buf, err
}

// DataURI extracts the base64 data URI from a screenshot finding for embedding in HTML.
func DataURI(f finding.Finding) string {
	if f.CheckID != finding.CheckAssetScreenshot {
		return ""
	}
	if v, ok := f.Evidence["image_b64"].(string); ok {
		return v
	}
	return ""
}

// hasBrowser returns true if a compatible Chrome/Chromium installation is found.
func hasBrowser() bool {
	for _, browser := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"} {
		if _, err := exec.LookPath(browser); err == nil {
			return true
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
