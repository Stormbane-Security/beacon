// Package screenshot captures screenshots of discovered assets using gowitness.
// Screenshots provide visual evidence of what is exposed and are embedded in reports.
// gowitness is Apache 2.0 licensed: https://github.com/sensepost/gowitness
// Requires Chrome or Chromium to be installed. Skips gracefully if not available.
package screenshot

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/toolinstall"
)

const scannerName = "screenshot"

// Scanner wraps the gowitness binary as a subprocess.
type Scanner struct {
	bin string
}

func New(bin string) *Scanner {
	if bin == "" {
		bin = "gowitness"
	}
	return &Scanner{bin: bin}
}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("gowitness: %w", err)
	}
	// gowitness requires Chrome/Chromium — can't install a browser automatically
	if !hasBrowser() {
		fmt.Fprintf(os.Stderr, "beacon: screenshots skipped — Chrome or Chromium not found (install from https://www.google.com/chrome/)\n")
		return nil, nil
	}

	// Create a temp directory for the screenshot
	tmpDir, err := os.MkdirTemp("", "beacon-screenshot-*")
	if err != nil {
		return nil, nil
	}
	defer os.RemoveAll(tmpDir)

	target := "https://" + asset
	outFile := filepath.Join(tmpDir, "screenshot.png")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolvedBin,
		"single",
		"--url", target,
		"--screenshot-path", outFile,
		"--no-db",           // don't write a gowitness database
		"--timeout", "20",
		"--resolution-x", "1280",
		"--resolution-y", "800",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Try HTTP fallback
		target = "http://" + asset
		cmd2 := exec.CommandContext(ctx, resolvedBin,
			"single",
			"--url", target,
			"--screenshot-path", outFile,
			"--no-db",
			"--timeout", "20",
			"--resolution-x", "1280",
			"--resolution-y", "800",
		)
		cmd2.Stderr = &stderr
		if err := cmd2.Run(); err != nil {
			return nil, nil
		}
	}

	// Read screenshot and encode as base64 for embedding in the report
	data, err := os.ReadFile(outFile)
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	b64 := base64.StdEncoding.EncodeToString(data)
	dataURI := "data:image/png;base64," + b64

	return []finding.Finding{{
		CheckID:     finding.CheckAssetScreenshot,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("Screenshot captured for %s", asset),
		Description: fmt.Sprintf("A screenshot of %s was captured during the scan. This provides visual evidence of what is accessible.", asset),
		Asset:       asset,
		Evidence: map[string]any{
			"url":       target,
			"image_b64": dataURI,
			"size_bytes": len(data),
		},
		DiscoveredAt: time.Now(),
	}}, nil
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
