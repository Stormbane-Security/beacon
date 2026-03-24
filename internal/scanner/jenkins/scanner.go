// Package jenkins probes for unauthenticated Jenkins Script Console access.
//
// The Jenkins Script Console (/script) provides direct Groovy execution on the
// Jenkins controller, equivalent to full OS-level RCE. In deep mode, after
// confirming the /script path returns 200, we POST a safe read-only Groovy
// payload and check whether the server executes it. The payload only reads a
// JVM system property — no file access, no network calls, no side effects.
//
// # Authorization requirement
//
// This scanner only runs in deep mode, which requires --permission-confirmed.
// The GET to /script is logged by Jenkins as an unauthenticated access attempt.
// The POST to /script (Groovy execution probe) is recorded in the Jenkins audit
// trail as a script execution event. Only run this against targets you own or
// have explicit written permission to test.
package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "jenkins"

// probeMarker is embedded in the Groovy output so we can identify our own
// response even if the page contains other text.
const probeMarker = "BEACON-PROBE-"

// groovyPayload is a safe read-only Groovy expression. It:
//   - Reads a JVM system property (java.version) — no file or network access
//   - Wraps the output in a recognisable marker so we can confirm execution
//   - Has no side effects if the console is actually authenticated downstream
const groovyPayload = `println("` + probeMarker + `"+System.getProperty("java.version")+"` + probeMarker + `")`

// Scanner probes Jenkins for unauthenticated Script Console RCE.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Confirm /script is accessible before sending the Groovy payload.
	// A redirect (3xx) to /login means auth is required — not vulnerable.
	scriptURL := scriptEndpoint(asset)
	if !scriptAccessible(ctx, client, scriptURL) {
		return nil, nil
	}

	// Phase 2: POST the safe Groovy probe and check for execution.
	executed, javaVersion := probeGroovyExecution(ctx, client, scriptURL)
	if !executed {
		// Path is accessible but not executing — report as High (console exposed
		// but may require auth for execution, or CSRF protection blocks POST).
		return []finding.Finding{{
			CheckID:  finding.CheckExposureCICDPanel, // path exposure, not confirmed RCE
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("Jenkins Script Console accessible (unauthenticated) on %s", asset),
			Description: "The Jenkins Script Console (/script) responded with HTTP 200 without " +
				"authentication. Groovy execution could not be confirmed (CSRF token or POST " +
				"restrictions may be in place), but the console is accessible and should be " +
				"restricted. Unauthenticated access to this path is a critical misconfiguration.",
			Evidence: map[string]any{"script_url": scriptURL},
			ProofCommand: fmt.Sprintf(
				"curl -s -o /dev/null -w '%%{http_code}' '%s'\n"+
					"# Expected: 200 — confirms unauthenticated GET access to the Jenkins Script Console",
				scriptURL),
			DiscoveredAt: time.Now(),
		}}, nil
	}

	// Confirmed: server executed our Groovy and returned the output.
	return []finding.Finding{{
		CheckID:  finding.CheckJenkinsGroovyRCE,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("Jenkins Script Console: unauthenticated Groovy RCE confirmed on %s", asset),
		Description: fmt.Sprintf(
			"The Jenkins Script Console at %s executed an unauthenticated Groovy script and "+
				"returned the output. This provides direct OS-level command execution on the "+
				"Jenkins controller. An attacker can exfiltrate credentials stored in Jenkins, "+
				"backdoor build pipelines, move laterally to build agents, and access any "+
				"environment variable or secret the Jenkins process can read.",
			scriptURL,
		),
		Evidence: map[string]any{
			"script_url":   scriptURL,
			"java_version": javaVersion,
			"payload":      groovyPayload,
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -X POST '%s' --data-urlencode 'script=println(\"beacon-rce-\"+\"confirmed\")' | grep beacon-rce-confirmed\n"+
				"# Expected: 'beacon-rce-confirmed' in output — confirms unauthenticated Groovy RCE",
			scriptURL),
		DiscoveredAt: time.Now(),
	}}, nil
}

// scriptEndpoint returns the /script URL for the asset over HTTPS (falls back
// to HTTP only in probing — the actual access check uses both schemes).
func scriptEndpoint(asset string) string {
	return "https://" + asset + "/script"
}

// scriptAccessible returns true if /script responds with 200 AND the response
// body contains Jenkins-specific markers. Redirects (3xx) mean auth is required.
// Checking the body prevents false positives from unrelated apps that happen to
// serve content at the path /script (e.g. blockchain faucets, health endpoints).
func scriptAccessible(ctx context.Context, client *http.Client, scriptURL string) bool {
	for _, u := range variants(scriptURL) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		// Require Jenkins-specific content in the response body.
		// A bare HTTP 200 at /script is not sufficient — many non-Jenkins services
		// serve content at this path.
		bodyLower := strings.ToLower(string(body))
		if strings.Contains(bodyLower, "jenkins") ||
			strings.Contains(bodyLower, "script console") ||
			strings.Contains(bodyLower, "groovy") {
			return true
		}
	}
	return false
}

// crumbResponse is the JSON structure returned by /crumbIssuer/api/json.
type crumbResponse struct {
	Crumb             string `json:"crumb"`
	CrumbRequestField string `json:"crumbRequestField"`
}

// fetchCrumb attempts to retrieve a Jenkins CSRF crumb from the target.
// Jenkins 2.x+ requires a crumb header on all POST requests by default.
// Returns the field name and crumb value, or empty strings if unavailable.
func fetchCrumb(ctx context.Context, client *http.Client, baseURL string) (field, crumb string) {
	crumbURL := strings.TrimSuffix(baseURL, "/script") + "/crumbIssuer/api/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crumbURL, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	var cr crumbResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", ""
	}
	return cr.CrumbRequestField, cr.Crumb
}

// probeGroovyExecution POSTs the safe Groovy payload to the script console
// and checks whether the response contains the execution marker.
// A CSRF crumb is fetched first and included in the POST headers — Jenkins 2.x+
// requires this for state-changing requests even on unauthenticated instances.
// Returns (executed, javaVersion).
func probeGroovyExecution(ctx context.Context, client *http.Client, scriptURL string) (bool, string) {
	for _, u := range variants(scriptURL) {
		crumbField, crumbValue := fetchCrumb(ctx, client, u)

		form := url.Values{"script": {groovyPayload}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
		if crumbField != "" && crumbValue != "" {
			req.Header.Set(crumbField, crumbValue)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		body := string(raw)
		start := strings.Index(body, probeMarker)
		if start == -1 {
			continue
		}
		start += len(probeMarker)
		end := strings.Index(body[start:], probeMarker)
		if end == -1 {
			return true, ""
		}
		return true, body[start : start+end]
	}
	return false, ""
}

// variants returns https and http versions of the given URL.
func variants(httpsURL string) []string {
	httpURL := strings.Replace(httpsURL, "https://", "http://", 1)
	return []string{httpsURL, httpURL}
}
