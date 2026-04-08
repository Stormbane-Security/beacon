// Package apifuzz wraps the beacon-fuzz binary as a scanner. It runs against
// JSON API endpoints discovered during the crawl/classify phase, sending
// type confusion, boundary value, and encoding mutations to detect anomalous
// server behavior (crashes, error disclosure, unexpected status codes).
//
// Only runs in Deep or Authorized mode to avoid sending mutated payloads
// during surface scans.
package apifuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/toolinstall"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(cfg scan.ScannerConfig) scan.Scanner {
		return &Scanner{bin: cfg.Get("beacon-fuzz.bin")}
	},
		scan.Check(finding.CheckWebAPIFuzz, finding.SeverityHigh, finding.ModeDeep),
	)
}

const scannerName = "apifuzz"

type Scanner struct {
	bin string
}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType < module.ScanDeep {
		return nil, nil
	}

	bin := s.bin
	if bin == "" {
		bin = "beacon-fuzz"
	}
	resolvedBin, err := toolinstall.Ensure(bin)
	if err != nil {
		return nil, nil // beacon-fuzz not installed, skip silently
	}

	scheme := "https"
	if sctx, ok := scan.FromContext(ctx); ok {
		scheme = sctx.Scheme()
	}
	base := scheme + "://" + asset

	// Probe common JSON API endpoints
	endpoints := []struct {
		path   string
		method string
		body   string
	}{
		{"/api/v1/users", "POST", `{"name":"test","email":"fuzz@test.com"}`},
		{"/api/users", "POST", `{"name":"test","email":"fuzz@test.com"}`},
		{"/api/login", "POST", `{"username":"test","password":"test"}`},
		{"/api/auth", "POST", `{"username":"test","password":"test"}`},
		{"/api/search", "POST", `{"query":"test","limit":10}`},
		{"/graphql", "POST", `{"query":"{ __schema { types { name } } }"}`},
	}

	var findings []finding.Finding

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}

		target := base + ep.path
		result, err := runFuzz(ctx, resolvedBin, target, ep.method, ep.body)
		if err != nil || result == nil {
			continue
		}

		if result.AnomalyCount > 0 {
			findings = append(findings, fuzzResultToFindings(result, asset, ep.path)...)
		}
	}

	return findings, nil
}

// fuzzResult mirrors the beacon-fuzz JSON output.
type fuzzResult struct {
	Target       string    `json:"target"`
	TotalSent    int       `json:"total_sent"`
	AnomalyCount int      `json:"anomaly_count"`
	Anomalies    []struct {
		MutationName string   `json:"mutation"`
		Description  string   `json:"description"`
		Reasons      []string `json:"reasons"`
		Response     struct {
			StatusCode  int    `json:"status_code"`
			BodySnippet string `json:"body_snippet"`
		} `json:"response"`
	} `json:"anomalies"`
}

func runFuzz(ctx context.Context, bin, target, method, body string) (*fuzzResult, error) {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("beacon-fuzz-%d.json", time.Now().UnixNano()))
	defer os.Remove(tmpFile)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := []string{
		"--target", target,
		"--method", method,
		"--content-type", "application/json",
		"--body", body,
		"--output", tmpFile,
		"--max-requests", "15",
		"--rate", "5",
		"--timeout", "25s",
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stderr = nil // suppress noise

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, err
	}

	var result fuzzResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func fuzzResultToFindings(result *fuzzResult, asset, path string) []finding.Finding {
	var findings []finding.Finding

	for _, anomaly := range result.Anomalies {
		sev := finding.SeverityMedium
		checkID := finding.CheckWebAPIFuzz

		// Upgrade to high severity for server errors and crash indicators
		for _, reason := range anomaly.Reasons {
			if strings.HasPrefix(reason, "server_error") || strings.HasPrefix(reason, "crash_indicator") {
				sev = finding.SeverityHigh
				checkID = finding.CheckWebAPIFuzz
				break
			}
		}

		findings = append(findings, finding.Finding{
			CheckID:  checkID,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: sev,
			Title:    fmt.Sprintf("API fuzz anomaly on %s: %s", path, anomaly.MutationName),
			Description: fmt.Sprintf("The API endpoint %s responded anomalously to mutation %q: %s. %s",
				path, anomaly.MutationName, anomaly.Description, strings.Join(anomaly.Reasons, "; ")),
			Asset: asset,
			Evidence: map[string]any{
				"endpoint":    path,
				"mutation":    anomaly.MutationName,
				"description": anomaly.Description,
				"reasons":     anomaly.Reasons,
				"status_code": anomaly.Response.StatusCode,
			},
			ProofCommand: fmt.Sprintf("beacon-fuzz --target '%s%s' --method POST --content-type application/json --body '%s' --output /tmp/fuzz.json --max-requests 15",
				"https://"+asset, path, "{}"),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
