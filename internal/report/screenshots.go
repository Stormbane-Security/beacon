package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/stormbane-security/beacon/internal/finding"
)

// CaptureScreenshots takes a headless Chrome screenshot for each finding that
// has a URL in its evidence map. Screenshots are saved as PNG files in outDir
// with the naming convention: finding-{index}-{check_id}.png
//
// If Chrome is not available the function returns an error describing how to
// install it. Individual screenshot failures are logged but do not abort the
// entire batch.
func CaptureScreenshots(findings []finding.Finding, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create screenshot dir: %w", err)
	}

	// Allocate a browser context once and reuse across all captures.
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(1280, 800),
		chromedp.Flag("ignore-certificate-errors", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	var captured int
	var errors []string

	for i, f := range findings {
		url := screenshotURL(f)
		if url == "" {
			continue
		}

		filename := ScreenshotFilename(i, f.CheckID)
		outPath := filepath.Join(outDir, filename)

		if err := captureOne(browserCtx, url, outPath); err != nil {
			errors = append(errors, fmt.Sprintf("finding %d (%s): %v", i, f.CheckID, err))
			continue
		}
		captured++
	}

	if captured == 0 && len(errors) > 0 {
		return fmt.Errorf("all screenshots failed; first error: %s", errors[0])
	}

	if len(errors) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: %d/%d screenshots failed\n", len(errors), len(errors)+captured)
	}

	return nil
}

// ScreenshotFilename returns the standardised screenshot filename for a
// finding at the given index.
func ScreenshotFilename(index int, checkID finding.CheckID) string {
	safe := sanitizeFilename(string(checkID))
	return fmt.Sprintf("finding-%03d-%s.png", index, safe)
}

// screenshotURL extracts the best URL to screenshot from a finding.
func screenshotURL(f finding.Finding) string {
	if f.Evidence == nil {
		return ""
	}
	for _, key := range []string{"url", "matched_at", "endpoint", "base_url", "probe_url", "bucket_url"} {
		if v, ok := f.Evidence[key].(string); ok && strings.HasPrefix(v, "http") {
			return v
		}
	}
	return ""
}

// captureOne navigates to url and saves a full-page screenshot to outPath.
func captureOne(browserCtx context.Context, url, outPath string) error {
	ctx, cancel := context.WithTimeout(browserCtx, 30*time.Second)
	defer cancel()

	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.FullScreenshot(&buf, 90),
	); err != nil {
		return fmt.Errorf("screenshot %s: %w", url, err)
	}

	if err := os.WriteFile(outPath, buf, 0o644); err != nil {
		return fmt.Errorf("write screenshot: %w", err)
	}
	return nil
}

// ChromeAvailable returns true if headless Chrome can be launched.
func ChromeAvailable() bool {
	opts := chromedp.DefaultExecAllocatorOptions[:]
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, ctxCancel := chromedp.NewContext(allocCtx)
	defer ctxCancel()

	// Try to start Chrome with a short timeout.
	tCtx, tCancel := context.WithTimeout(ctx, 5*time.Second)
	defer tCancel()

	if err := chromedp.Run(tCtx); err != nil {
		return false
	}
	return true
}
