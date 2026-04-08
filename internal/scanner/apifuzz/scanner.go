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
	"net/http"
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

	// Probe common JSON API endpoints across popular frameworks.
	// Each endpoint is tried with a baseline POST — if the server responds
	// with anything other than 404, we fuzz it.
	endpoints := []struct {
		path   string
		method string
		body   string
	}{
		// Standard REST patterns
		{"/api/v1/users", "POST", `{"name":"test","email":"fuzz@test.com"}`},
		{"/api/users", "POST", `{"name":"test","email":"fuzz@test.com"}`},
		{"/api/Users/", "POST", `{"email":"fuzz@test.com","password":"Test1234"}`},
		{"/api/login", "POST", `{"username":"test","password":"test"}`},
		{"/api/auth", "POST", `{"username":"test","password":"test"}`},
		{"/api/auth/login", "POST", `{"email":"test@test.com","password":"test"}`},
		{"/api/auth/signin", "POST", `{"email":"test@test.com","password":"test"}`},
		{"/api/search", "POST", `{"query":"test","limit":10}`},
		// Node.js / Express patterns
		{"/rest/user/login", "POST", `{"email":"test@test.com","password":"test"}`},
		{"/rest/user/register", "POST", `{"email":"fuzz@test.com","password":"test"}`},
		{"/auth/login", "POST", `{"email":"test@test.com","password":"test"}`},
		{"/login", "POST", `{"username":"test","password":"test"}`},
		// GraphQL
		{"/graphql", "POST", `{"query":"{ __schema { types { name } } }"}`},
		// Django / Flask
		{"/api/token/", "POST", `{"username":"test","password":"test"}`},
		{"/accounts/login/", "POST", `{"username":"test","password":"test"}`},
	}

	var findings []finding.Finding

	httpClient := &http.Client{Timeout: 5 * time.Second}
	if sctx, ok := scan.FromContext(ctx); ok {
		httpClient = sctx.HTTPClient()
	}

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}

		target := base + ep.path

		// Quick pre-check: skip endpoints that return 404
		preReq, _ := http.NewRequestWithContext(ctx, ep.method, target, strings.NewReader(ep.body))
		if preReq != nil {
			preReq.Header.Set("Content-Type", "application/json")
			if preResp, err := httpClient.Do(preReq); err == nil {
				preResp.Body.Close()
				if preResp.StatusCode == 404 {
					continue
				}
			}
		}

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
	Anomalies    []fuzzAnomaly `json:"anomalies"`
}

type fuzzAnomaly struct {
	MutationName string       `json:"mutation"`
	Description  string       `json:"description"`
	Reasons      []string     `json:"reasons"`
	Response     struct {
		StatusCode  int    `json:"status_code"`
		BodySnippet string `json:"body_snippet"`
	} `json:"response"`
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
		"--max-requests", "25",
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

		// Classify the anomaly into a vulnerability class for exploit chain routing.
		vulnClass := classifyAnomaly(anomaly.Reasons, anomaly.Response.BodySnippet, anomaly.MutationName)

		// Upgrade severity for server errors and crash indicators
		for _, reason := range anomaly.Reasons {
			if strings.HasPrefix(reason, "server_error") || strings.HasPrefix(reason, "crash_indicator") {
				sev = finding.SeverityHigh
				break
			}
		}

		// If we classified a specific vuln type, upgrade to the specific check ID
		if vulnClass == "sqli" {
			checkID = finding.CheckWebSQLi
			sev = finding.SeverityCritical
		} else if vulnClass == "cmdinj" {
			checkID = finding.CheckWebCmdInjection
			sev = finding.SeverityCritical
		} else if vulnClass == "auth_bypass" {
			sev = finding.SeverityCritical
		}

		ev := map[string]any{
			"endpoint":    path,
			"mutation":    anomaly.MutationName,
			"description": anomaly.Description,
			"reasons":     anomaly.Reasons,
			"status_code": anomaly.Response.StatusCode,
		}
		if vulnClass != "" {
			ev["vuln_class"] = vulnClass
		}

		findings = append(findings, finding.Finding{
			CheckID:     checkID,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    sev,
			Title:       fmt.Sprintf("API fuzz anomaly on %s: %s", path, anomaly.MutationName),
			Description: fmt.Sprintf("The API endpoint %s responded anomalously to mutation %q: %s. %s",
				path, anomaly.MutationName, anomaly.Description, strings.Join(anomaly.Reasons, "; ")),
			Asset: asset,
			Evidence: ev,
			ProofCommand: fmt.Sprintf("beacon-fuzz --target '%s%s' --method POST --content-type application/json --body '%s' --output /tmp/fuzz.json --max-requests 15",
				"https://"+asset, path, "{}"),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// classifyAnomaly analyzes fuzz anomaly reasons and response content to
// determine the vulnerability class. This enables the exploit chain dispatcher
// to automatically route fuzz-discovered vulnerabilities to the appropriate
// exploit module (SQLi, command injection, auth bypass, etc.).
func classifyAnomaly(reasons []string, bodySnippet, mutationName string) string {
	snippet := strings.ToLower(bodySnippet)
	reasonStr := strings.ToLower(strings.Join(reasons, " "))

	// SQL injection indicators
	sqlIndicators := []string{
		"sql syntax", "sqlite3", "mysql", "postgresql", "ora-",
		"unclosed quotation", "quoted string not properly terminated",
		"sqlstate", "sql error", "sequelize",
	}
	for _, ind := range sqlIndicators {
		if strings.Contains(snippet, ind) || strings.Contains(reasonStr, ind) {
			return "sqli"
		}
	}
	// NoSQL operator mutation that got a different response
	if strings.Contains(mutationName, "nosql") || strings.Contains(mutationName, "object") {
		if strings.Contains(reasonStr, "status_change") {
			return "sqli" // NoSQL injection classified under sqli for exploit routing
		}
	}

	// Command injection indicators
	cmdIndicators := []string{
		"command not found", "sh:", "bash:", "/bin/sh",
		"exec format error", "permission denied",
	}
	for _, ind := range cmdIndicators {
		if strings.Contains(snippet, ind) {
			return "cmdinj"
		}
	}

	// Auth bypass: status changed from 401/403 to 200
	if strings.Contains(reasonStr, "status_change: 401") || strings.Contains(reasonStr, "status_change: 403") {
		if strings.Contains(reasonStr, "→ 200") || strings.Contains(reasonStr, "→ 302") {
			return "auth_bypass"
		}
	}

	// Information disclosure: massive size increase
	if strings.Contains(reasonStr, "size_change") {
		for _, r := range reasons {
			if strings.Contains(r, "size_change") {
				// Extract the ratio — if > 10x, likely data leak
				if strings.Contains(r, "10.") || strings.Contains(r, "20.") ||
					strings.Contains(r, "50.") || strings.Contains(r, "100.") {
					return "info_disclosure"
				}
			}
		}
	}

	// Server-side template injection
	if strings.Contains(snippet, "49") && strings.Contains(mutationName, "ssti") {
		return "ssti"
	}

	// Path traversal / LFI
	if strings.Contains(snippet, "root:") && strings.Contains(snippet, "/bin/") {
		return "lfi"
	}

	return ""
}
