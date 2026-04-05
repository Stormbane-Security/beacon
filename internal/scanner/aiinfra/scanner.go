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
	keywords   []string // response must contain keywords
	minMatches int      // minimum keyword matches required (0 = 1)
	title      string
	desc       string
}

var probes = []probe{
	{
		path:       "/api/kernels",
		checkID:    finding.CheckAIInfraJupyter,
		keywords:   []string{"kernel_id", "execution_state", "last_activity"},
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
		// Require Jupyter-specific fields — generic "content"/"type" match
		// any JSON API (e.g. Nuxt status pages). "writable" and "format"
		// alongside "mimetype" are unique to Jupyter's contents API.
		keywords:   []string{"writable", "mimetype", "last_modified", ".ipynb"},
		minMatches: 2,
		title:   "Jupyter Notebook contents API exposed without authentication",
		desc: "The Jupyter Notebook contents API at %s is accessible without authentication. " +
			"An attacker can read and write notebook files, potentially accessing " +
			"sensitive data or executing code.",
	},
	{
		path:    "/api/jobs/",
		checkID: finding.CheckAIInfraRay,
		keywords: []string{"submission_id", "entrypoint", "job_id", "ray"},
		title:   "Ray dashboard job submission API exposed without authentication",
		desc: "The Ray distributed computing dashboard at %s exposes its job submission " +
			"API without authentication. An attacker can submit arbitrary Python jobs " +
			"for execution across the Ray cluster, achieving remote code execution.",
	},
	{
		path:    "/api/2.0/mlflow/experiments/list",
		checkID: finding.CheckAIInfraMLflow,
		keywords: []string{"experiments", "experiment_id", "artifact_location"},
		title:   "MLflow experiment tracking server exposed without authentication",
		desc: "The MLflow tracking server at %s is accessible without authentication. " +
			"An attacker can access experiment data, model artifacts, and potentially " +
			"registered models. MLflow should be behind authentication and restricted " +
			"to internal networks.",
	},
	{
		path:    "/info",
		checkID: finding.CheckAIInfraGradio,
		keywords: []string{"gradio", "version", "api_prefix"},
		title:   "Gradio ML demo server exposed without authentication",
		desc: "A Gradio ML application at %s is publicly accessible. Gradio apps expose " +
			"file upload functionality and direct model interaction. Unrestricted access " +
			"may enable arbitrary file uploads or model abuse.",
	},
	{
		path:    "/api/predict",
		checkID: finding.CheckAIInfraGradio,
		keywords: []string{"data", "duration", "average_duration"},
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
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyLower := strings.ToLower(string(body))
		matchCount := 0
		for _, kw := range p.keywords {
			if strings.Contains(bodyLower, kw) {
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
				"status":        resp.StatusCode,
				"response_size": len(body),
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}
