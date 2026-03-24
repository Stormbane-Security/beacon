package dirbust

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ffufOutput is the top-level JSON structure written by ffuf -of json.
type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

// ffufResult is a single match entry from ffuf JSON output.
type ffufResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Input  struct {
		FUZZ string `json:"FUZZ"`
	} `json:"input"`
}

// runFfuf runs ffuf as the dirbust backend when available.
// ffuf is faster and better at WAF evasion than the pure-Go prober.
// Returns nil when ffuf is unavailable or fails — caller falls back to Run().
//
// ffuf args used:
//
//	-u TARGET/FUZZ  — fuzz the path component
//	-w wordlist     — temp file with paths from the playbook
//	-mc 200,201,301,302,401,403  — match interesting codes
//	-t 10           — threads (same as Go scanner)
//	-timeout 10     — per-request timeout
//	-s              — silent (no banner)
//	-o output.json  — JSON output for parsing
//	-of json
func runFfuf(ctx context.Context, ffufBin, asset string, paths []string) []Result {
	if ffufBin == "" {
		return nil
	}
	if _, err := exec.LookPath(ffufBin); err != nil {
		return nil
	}

	// Write wordlist to a temp file (strip leading slash — ffuf prepends FUZZ).
	wl, err := os.CreateTemp("", "beacon-ffuf-wl-*.txt")
	if err != nil {
		return nil
	}
	defer os.Remove(wl.Name())

	for _, p := range paths {
		p = strings.TrimPrefix(p, "/")
		if _, err := wl.WriteString(p + "\n"); err != nil {
			wl.Close()
			return nil
		}
	}
	wl.Close()

	// Temp file for JSON output.
	out, err := os.CreateTemp("", "beacon-ffuf-out-*.json")
	if err != nil {
		return nil
	}
	outName := out.Name()
	out.Close()
	defer os.Remove(outName)

	// Determine scheme by attempting a quick HTTPS probe first.
	scheme := probeScheme(ctx, asset)

	target := scheme + "://" + asset + "/FUZZ"

	cmd := exec.CommandContext(ctx, ffufBin,
		"-u", target,
		"-w", wl.Name(),
		"-mc", "200,201,301,302,401,403",
		"-t", "10",
		"-timeout", "10",
		"-s",
		"-o", outName,
		"-of", "json",
	)

	if err := cmd.Run(); err != nil {
		// ffuf exits non-zero when no results are found — that's fine; try to
		// parse whatever was written before giving up.
		if _, statErr := os.Stat(outName); statErr != nil {
			return nil
		}
	}

	data, err := os.ReadFile(outName)
	if err != nil || len(data) == 0 {
		return nil
	}

	var fo ffufOutput
	if err := json.Unmarshal(data, &fo); err != nil {
		return nil
	}

	var results []Result
	for _, r := range fo.Results {
		path := r.Input.FUZZ
		if path == "" {
			// Fall back to extracting path from the URL.
			if idx := strings.Index(r.URL, asset); idx != -1 {
				path = r.URL[idx+len(asset):]
			}
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		results = append(results, Result{Path: path, StatusCode: r.Status})
	}
	return results
}

// probeScheme returns "https" or "http" depending on which scheme the asset
// responds to. Defaults to "https" on any error (ffuf will handle fallback).
func probeScheme(ctx context.Context, asset string) string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+asset, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return "https"
		}
	}
	return "http"
}
