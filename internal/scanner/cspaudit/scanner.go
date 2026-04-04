// Package cspaudit analyzes Content-Security-Policy headers for bypass
// opportunities. Goes beyond detecting missing CSP — evaluates existing
// policies for data: URIs, unsafe-inline/eval, missing directives, and
// report-only mode.
package cspaudit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckCSPBaseURIMissing, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPDataURI, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCSPFrameAncestors, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPObjectSrc, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPReportOnly, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPUnsafeEval, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPUnsafeInline, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPWildcardSource, finding.SeverityHigh, finding.ModeSurface),
	)
}

const scannerName = "cspaudit"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	url := "https://" + asset + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		url = "http://" + asset + "/"
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, nil
		}
		resp, err = client.Do(req)
		if err != nil {
			return nil, nil
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()

	var findings []finding.Finding
	now := time.Now()

	// Check for CSP in report-only mode.
	cspRO := resp.Header.Get("Content-Security-Policy-Report-Only")
	csp := resp.Header.Get("Content-Security-Policy")

	if cspRO != "" && csp == "" {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckCSPReportOnly,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Asset:       asset,
			Title:       fmt.Sprintf("CSP in report-only mode on %s", asset),
			Description: "The Content-Security-Policy-Report-Only header is set but no enforcing CSP header exists. The policy is not blocking anything — it only reports violations.",
			Evidence:    map[string]any{"csp_report_only": cspRO, "url": url},
			ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
			DiscoveredAt: now,
		})
		// Analyze the report-only policy too.
		csp = cspRO
	}

	if csp == "" {
		return findings, nil
	}

	directives := parseCSP(csp)

	// Check script-src for dangerous values.
	scriptSrc := directives["script-src"]
	if scriptSrc == "" {
		scriptSrc = directives["default-src"]
	}

	if scriptSrc != "" {
		// data: URI in script-src.
		if strings.Contains(scriptSrc, "data:") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCSPDataURI,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Asset:       asset,
				Title:       fmt.Sprintf("CSP script-src allows data: URIs on %s", asset),
				Description: "The CSP script-src directive includes 'data:' which allows inline script execution via data URIs, effectively bypassing the CSP for XSS protection.",
				Evidence:    map[string]any{"script_src": scriptSrc, "csp": csp},
				ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
				DiscoveredAt: now,
			})
		}

		// unsafe-inline in script-src (existing check — but we add context).
		if strings.Contains(scriptSrc, "'unsafe-inline'") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCSPUnsafeInline,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Asset:       asset,
				Title:       fmt.Sprintf("CSP script-src allows 'unsafe-inline' on %s", asset),
				Description: "The CSP script-src directive includes 'unsafe-inline', which allows arbitrary inline script execution and negates XSS protection from the CSP.",
				Evidence:    map[string]any{"script_src": scriptSrc, "csp": csp},
				ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
				DiscoveredAt: now,
			})
		}

		// unsafe-eval in script-src.
		if strings.Contains(scriptSrc, "'unsafe-eval'") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCSPUnsafeEval,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Asset:       asset,
				Title:       fmt.Sprintf("CSP script-src allows 'unsafe-eval' on %s", asset),
				Description: "The CSP script-src directive includes 'unsafe-eval', allowing eval(), Function(), and setTimeout/setInterval with strings. This enables DOM-based XSS via code injection.",
				Evidence:    map[string]any{"script_src": scriptSrc, "csp": csp},
				ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
				DiscoveredAt: now,
			})
		}

		// Wildcard source in script-src.
		if strings.Contains(scriptSrc, "*") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCSPWildcardSource,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Asset:       asset,
				Title:       fmt.Sprintf("CSP script-src contains wildcard on %s", asset),
				Description: "The CSP script-src directive contains a wildcard (*) source, allowing scripts from any domain. This effectively disables CSP protection against XSS.",
				Evidence:    map[string]any{"script_src": scriptSrc, "csp": csp},
				ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
				DiscoveredAt: now,
			})
		}
	}

	// Missing base-uri directive.
	if _, ok := directives["base-uri"]; !ok {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckCSPBaseURIMissing,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Asset:       asset,
			Title:       fmt.Sprintf("CSP missing base-uri directive on %s", asset),
			Description: "The CSP does not include a base-uri directive. An attacker who can inject a <base> tag can redirect all relative URLs to their server, hijacking script and resource loading.",
			Evidence:    map[string]any{"csp": csp},
			ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
			DiscoveredAt: now,
		})
	}

	// Missing frame-ancestors directive.
	if _, ok := directives["frame-ancestors"]; !ok {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckCSPFrameAncestors,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Asset:       asset,
			Title:       fmt.Sprintf("CSP missing frame-ancestors directive on %s", asset),
			Description: "The CSP does not include frame-ancestors. Without this directive, the page can be framed by any origin, enabling clickjacking attacks. frame-ancestors supersedes X-Frame-Options.",
			Evidence:    map[string]any{"csp": csp},
			ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
			DiscoveredAt: now,
		})
	}

	// Missing object-src directive.
	if _, ok := directives["object-src"]; !ok {
		defaultSrc := directives["default-src"]
		if defaultSrc == "" || !strings.Contains(defaultSrc, "'none'") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCSPObjectSrc,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Asset:       asset,
				Title:       fmt.Sprintf("CSP missing object-src directive on %s", asset),
				Description: "The CSP does not restrict object-src and default-src is not 'none'. This allows embedding Flash/Java plugins that can bypass other CSP restrictions.",
				Evidence:    map[string]any{"csp": csp},
				ProofCommand: fmt.Sprintf("curl -sI %s | grep -i content-security-policy", url),
				DiscoveredAt: now,
			})
		}
	}

	return findings, nil
}

// parseCSP splits a CSP header into directive-name → value pairs.
func parseCSP(csp string) map[string]string {
	directives := map[string]string{}
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, " ", 2)
		name := strings.ToLower(fields[0])
		value := ""
		if len(fields) > 1 {
			value = fields[1]
		}
		directives[name] = value
	}
	return directives
}
