// Package aiinfra detects exposed AI/ML infrastructure services that should
// not be publicly accessible. It probes for Jupyter Notebook kernel APIs,
// Ray dashboard job submission, MLflow experiment tracking, and Gradio
// demo servers — all of which enable remote code execution or data
// exfiltration when unauthenticated.
//
// Surface mode only — all probes are safe GET requests.
package aiinfra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckAIInfraGradio, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckAIInfraJupyter, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckAIInfraMLflow, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckAIInfraRay, finding.SeverityCritical, finding.ModeSurface),
	)
}
const scannerName = "aiinfra"

// probe defines an endpoint to check for exposed AI infrastructure.
type probe struct {
	path       string
	checkID    finding.CheckID
	jsonKeys   []string // JSON field names that must appear as keys (not in values)
	minMatches int      // minimum key matches required (0 = 1)
	confirm    string   // optional confirmation path — must also return JSON 200
	title      string
	desc       string
}

var probes = []probe{
	{
		path:       "/api/kernels",
		checkID:    finding.CheckAIInfraJupyter,
		jsonKeys:   []string{"kernel_id", "execution_state", "last_activity"},
		minMatches: 2,
		title:   "Jupyter Notebook kernel API exposed without authentication",
		desc: "The Jupyter Notebook kernel API at %s is accessible without authentication. " +
			"An attacker can create and execute code in kernels, achieving remote code " +
			"execution on the server. Jupyter should require authentication tokens " +
			"and be restricted to internal networks.",
	},
	{
		path:    "/api/contents",
		checkID: finding.CheckAIInfraJupyter,
		// Jupyter contents API returns objects with "writable", "mimetype",
		// "last_modified", "format" — all unique to Jupyter's contents model.
		jsonKeys:   []string{"writable", "mimetype", "last_modified", "format"},
		minMatches: 3,
		title:   "Jupyter Notebook contents API exposed without authentication",
		desc: "The Jupyter Notebook contents API at %s is accessible without authentication. " +
			"An attacker can read and write notebook files, potentially accessing " +
			"sensitive data or executing code.",
	},
	{
		path:    "/api/jobs/",
		checkID: finding.CheckAIInfraRay,
		// Ray job API returns objects with these specific fields.
		// "submission_id" and "runtime_env" are Ray-unique.
		jsonKeys:   []string{"submission_id", "entrypoint", "runtime_env", "driver_info", "job_id"},
		minMatches: 3,
		confirm:    "/api/version", // Ray version endpoint — must contain "ray_version"
		title:   "Ray dashboard job submission API exposed without authentication",
		desc: "The Ray distributed computing dashboard at %s exposes its job submission " +
			"API without authentication. An attacker can submit arbitrary Python jobs " +
			"for execution across the Ray cluster, achieving remote code execution.",
	},
	{
		path:    "/api/2.0/mlflow/experiments/list",
		checkID: finding.CheckAIInfraMLflow,
		jsonKeys: []string{"experiments", "experiment_id", "artifact_location"},
		minMatches: 2,
		title:   "MLflow experiment tracking server exposed without authentication",
		desc: "The MLflow tracking server at %s is accessible without authentication. " +
			"An attacker can access experiment data, model artifacts, and potentially " +
			"registered models. MLflow should be behind authentication and restricted " +
			"to internal networks.",
	},
	{
		path:    "/info",
		checkID: finding.CheckAIInfraGradio,
		jsonKeys: []string{"gradio_version", "api_prefix", "named_endpoints"},
		minMatches: 2,
		title:   "Gradio ML demo server exposed without authentication",
		desc: "A Gradio ML application at %s is publicly accessible. Gradio apps expose " +
			"file upload functionality and direct model interaction. Unrestricted access " +
			"may enable arbitrary file uploads or model abuse.",
	},
	{
		path:    "/api/predict",
		checkID: finding.CheckAIInfraGradio,
		jsonKeys: []string{"average_duration", "fn_index"},
		minMatches: 2,
		confirm: "/info", // confirm it's actually Gradio
		title:   "Gradio prediction API exposed without authentication",
		desc: "The Gradio prediction API at %s is accessible without authentication. " +
			"An attacker can interact directly with the underlying ML model.",
	},
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanSurface && scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding
	seen := make(map[finding.CheckID]bool)

	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		if seen[p.checkID] {
			continue // one finding per service type is enough
		}

		url := base + p.path
		body, status, err := fetchJSON(ctx, client, url)
		if err != nil || status != http.StatusOK {
			continue
		}

		// Extract all JSON keys from the response to match against.
		keys := collectJSONKeys(body)
		matchCount := 0
		for _, k := range p.jsonKeys {
			if keys[k] {
				matchCount++
			}
		}
		minRequired := p.minMatches
		if minRequired <= 0 {
			minRequired = 1
		}
		if matchCount < minRequired {
			continue
		}

		// If a confirmation path is set, it must also return JSON 200.
		if p.confirm != "" {
			confirmURL := base + p.confirm
			_, confirmStatus, confirmErr := fetchJSON(ctx, client, confirmURL)
			if confirmErr != nil || confirmStatus != http.StatusOK {
				continue
			}
		}

		seen[p.checkID] = true
		findings = append(findings, finding.Finding{
			CheckID:     p.checkID,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.Registry[p.checkID].DefaultSeverity,
			Title:       p.title,
			Description: fmt.Sprintf(p.desc, asset),
			Asset:       asset,
			ProofCommand: fmt.Sprintf("curl -si '%s'", url),
			Evidence: map[string]any{
				"url":           url,
				"status":        status,
				"response_size": len(body),
				"matched_keys":  matchCount,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// fetchJSON sends a GET request and returns the raw body only if the response
// is JSON (Content-Type contains "json" and body parses as JSON).
func fetchJSON(ctx context.Context, client *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()

	// Must actually be JSON — reject HTML pages, plaintext, etc.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "json") {
		return nil, resp.StatusCode, fmt.Errorf("not json: %s", ct)
	}

	// Must parse as valid JSON.
	if !json.Valid(body) {
		return nil, resp.StatusCode, fmt.Errorf("invalid json")
	}

	return body, resp.StatusCode, nil
}

// collectJSONKeys recursively collects all key names from a JSON document.
// This lets us check for field presence without substring matching against
// values, which eliminates false positives from keywords appearing in text
// content rather than as API field names.
func collectJSONKeys(data []byte) map[string]bool {
	keys := make(map[string]bool)
	var walk func(v any)
	walk = func(v any) {
		switch val := v.(type) {
		case map[string]any:
			for k, child := range val {
				keys[k] = true
				walk(child)
			}
		case []any:
			for _, child := range val {
				walk(child)
			}
		}
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err == nil {
		walk(parsed)
	}
	return keys
}
