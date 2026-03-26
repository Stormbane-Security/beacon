// Package ratelimit probes API endpoints to detect missing or bypassable
// rate limiting. It uses an escalating multi-phase strategy to build
// confidence before reporting:
//
//   Phase 1 — 8-request sanity burst   (500 ms spacing, ~4 s)
//   Phase 2 — 16-request burst          (200 ms spacing, ~3 s)
//   Phase 3 — 32-request rapid burst    (no delay, ~1 s with network latency)
//   Phase 4 — 20-request sustained      (1 req/sec, ~20 s)
//
// Each phase exits early if a throttle signal is detected. Only if all four
// phases complete without any signal is a "missing rate limiting" finding
// reported — at Medium severity, not High, because absence of 429 across
// ~76 requests is medium-confidence evidence, not proof.
//
// Signal detection goes beyond HTTP 429:
//   - HTTP 403 appearing after a run of 200 OK  (possible WAF block)
//   - Response latency spiking >5× the per-phase baseline
//   - Challenge / CAPTCHA page keywords in the body
//   - Response body hash changing mid-burst  (soft-block)
//   - Rate-limit response headers (X-RateLimit-*, RateLimit-*, Retry-After)
//
// If rate-limit headers are observed the server has rate limiting configured
// even though the threshold was not triggered; no "missing" finding is emitted.
//
// Only runs in deep mode — the probe sends active HTTP requests.
package ratelimit

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName = "ratelimit"

	// bypassForge uses TEST-NET-2 (RFC 5737 §3, 198.51.100.0/24) —
	// documentation-only, never routes on the public internet.
	// RFC 1918 addresses (10.x, 192.168.x) look like internal network
	// reconnaissance and may trigger separate IDS alerts.
	bypassForge = "198.51.100.1"
)

// throttleSignal categorises what was observed during a burst probe.
type throttleSignal int

const (
	signalNone        throttleSignal = iota
	signal429                        // explicit HTTP 429 — definitive
	signal403                        // HTTP 403 after 200 OK run — possible WAF throttle
	signalConnReset                  // connection errors after initially clean responses
	signalLatency                    // latency spiked >5× baseline after 3-req warmup
	signalChallenge                  // CAPTCHA / challenge page body detected
	signalBodyChange                 // response body hash changed mid-burst
	signalHeaders                    // rate-limit headers observed — RL is present, skip "missing"
)

// probeRun holds per-request observations collected during burstProbe.
type probeRun struct {
	statusCodes   map[int]int
	latencies     []time.Duration
	bodyHashes    []uint32 // FNV-32a of first 512 bytes
	connErrors    int
	rlHeaders     []string // rate-limit headers observed
	challengeSeen bool
	totalRequests int
}

// probePhase describes one stage of the escalating burst strategy.
type probePhase struct {
	count int
	delay time.Duration
	label string
}

var burstPhases = []probePhase{
	{8, 500 * time.Millisecond, "8-request sanity burst (500 ms spacing)"},
	{16, 200 * time.Millisecond, "16-request burst (200 ms spacing)"},
	{32, 0, "32-request rapid burst"},
}

// sustainedPhase is the final fallback when all burst phases find no signal.
var sustainedPhase = probePhase{20, 1 * time.Second, "20-second sustained probe at 1 req/sec"}

// rateLimitHeaderNames are response headers that indicate rate limiting is
// configured even if no 429 was returned.
var rateLimitHeaderNames = []string{
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
	"X-RateLimit-Policy",
	"RateLimit-Limit",
	"RateLimit-Remaining",
	"RateLimit-Reset",
	"Retry-After",
}

// challengeKeywords trigger signalChallenge when found in a response body.
var challengeKeywords = []string{
	"captcha",
	"challenge",
	"verify you are human",
	"are you a robot",
	"ddos-guard",
}

// Scanner probes for missing or bypassable rate limiting.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// apiProbes are endpoint patterns to probe.
var apiProbes = []string{
	"/api/v1/",
	"/api/v2/",
	"/api/",
	"/graphql",
	"/login",
	"/auth/login",
	"/auth/token",
	"/oauth/token",
	"/",
}

// bypassHeaders are headers used to forge a client IP address.
// All forged values use TEST-NET-2 (RFC 5737 §3, 198.51.100.0/24) or
// TEST-NET-3 (203.0.113.0/24) — documentation ranges that never route on
// the public internet, so there is no risk of accidentally implicating a
// real host.
var bypassHeaders = []struct {
	name  string
	value string
}{
	// De-facto standard IP forwarding headers
	{"X-Forwarded-For", bypassForge},
	{"X-Real-IP", bypassForge},
	{"X-Originating-IP", bypassForge},
	// CDN / platform-specific forwarding headers
	{"CF-Connecting-IP", bypassForge},
	{"True-Client-IP", bypassForge},
	{"X-Client-IP", bypassForge},
	{"X-Cluster-Client-IP", bypassForge},
	// RFC 7239 standard forwarding header
	{"Forwarded", "for=" + bypassForge},
	// Some rate limiters key on the second IP in a comma-separated XFF chain
	// (the "client" IP after a trusted proxy strips the first hop).
	{"X-Forwarded-For", bypassForge + ", 203.0.113.1"},
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	_, probeURL := findProbeTarget(ctx, client, asset, apiProbes)
	if probeURL == "" {
		return nil, nil
	}

	now := time.Now()

	// Escalating burst phases — stop at first throttle signal.
	var lastRun *probeRun
	var triggeredPhase *probePhase
	var sig throttleSignal

	for i := range burstPhases {
		ph := &burstPhases[i]
		run := burstProbe(ctx, client, probeURL, ph.count, ph.delay)
		lastRun = run
		sig = detectSignal(run)
		if sig != signalNone {
			triggeredPhase = ph
			break
		}
	}

	// If no burst signal, run the sustained probe.
	if sig == signalNone {
		run := burstProbe(ctx, client, probeURL, sustainedPhase.count, sustainedPhase.delay)
		lastRun = run
		sig = detectSignal(run)
		if sig != signalNone {
			triggeredPhase = &sustainedPhase
		}
	}

	// Count total requests sent across all phases.
	totalSent := lastRun.totalRequests
	_ = triggeredPhase

	// Rate-limit headers seen: the server has rate limiting configured but the
	// threshold was not triggered at our probe volume. No "missing" finding.
	if sig == signalHeaders {
		return nil, nil
	}

	// Definitive 429: check for Retry-After absence and bypass headers.
	if sig == signal429 {
		return s.handle429(ctx, client, asset, probeURL, lastRun, now)
	}

	// Secondary signal (403, latency, challenge, body change, conn reset):
	// medium-confidence indication of throttling — report informational.
	if sig != signalNone {
		label, detail := signalDetails(sig, lastRun)
		phaseLabel := sustainedPhase.label
		if triggeredPhase != nil {
			phaseLabel = triggeredPhase.label
		}
		return []finding.Finding{{
			CheckID:  finding.CheckRateLimitMissing,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    asset,
			Title:    fmt.Sprintf("Possible rate limiting signal on %s: %s", probeURL, label),
			Description: fmt.Sprintf(
				"A %s was observed during the %s against %s. "+
					"This may indicate WAF-based throttling, a challenge page, or application-level "+
					"rate limiting that does not use HTTP 429. Manual verification is recommended "+
					"to confirm whether rate limiting is properly enforced.",
				label, phaseLabel, probeURL,
			),
			Evidence: map[string]any{
				"probe_url":      probeURL,
				"signal":         label,
				"signal_detail":  detail,
				"total_requests": totalSent,
				"confidence":     "medium",
				"status_codes":   lastRun.statusCodes,
			},
			DiscoveredAt: now,
		}}, nil
	}

	// No signal at all — report missing rate limiting at Medium severity.
	// Confidence language reflects how hard we probed.
	confidence := "low"
	summary := fmt.Sprintf(
		"A small burst test (%d requests) did not trigger rate limiting. "+
			"Rate limiting may be absent or configured above the tested threshold. "+
			"Further verification with higher-volume and time-windowed probes is recommended.",
		totalSent,
	)
	if totalSent >= burstPhases[0].count+burstPhases[1].count+burstPhases[2].count {
		confidence = "medium"
		summary = fmt.Sprintf(
			"No rate limiting was observed during %d requests across escalating burst and "+
				"sustained probing patterns (8-request sanity burst, 16-request burst, "+
				"32-request rapid burst, and 20-second sustained probe at 1 req/sec). "+
				"This is medium-confidence evidence that rate limiting is absent or configured "+
				"well above the tested thresholds. Without rate limiting, this endpoint may be "+
				"vulnerable to credential stuffing, enumeration, scraping, and brute-force attacks.",
			totalSent,
		)
	}

	return []finding.Finding{{
		CheckID:     finding.CheckRateLimitMissing,
		Module:      "deep",
		Scanner:     scannerName,
		Severity:    finding.SeverityMedium,
		Asset:       asset,
		Title:       fmt.Sprintf("No rate limiting detected on %s", probeURL),
		Description: summary,
		Evidence: map[string]any{
			"probe_url":      probeURL,
			"total_requests": totalSent,
			"confidence":     confidence,
			"status_codes":   lastRun.statusCodes,
		},
		DiscoveredAt: now,
	}}, nil
}

// handle429 checks Retry-After presence and bypass header effectiveness
// once a 429 has been confirmed.
func (s *Scanner) handle429(
	ctx context.Context,
	client *http.Client,
	asset, probeURL string,
	run *probeRun,
	now time.Time,
) ([]finding.Finding, error) {
	var findings []finding.Finding

	if !retryAfterPresent(ctx, client, probeURL) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckRateLimitNoRetryAfter,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("Rate limited but no Retry-After header on %s", probeURL),
			Description: fmt.Sprintf(
				"%s returns HTTP 429 but does not include a Retry-After header. "+
					"Well-behaved clients need this to back off correctly; its absence "+
					"also means automated tooling will retry immediately, worsening "+
					"any overload condition the rate limit was meant to protect against.",
				probeURL,
			),
			Evidence:     map[string]any{"probe_url": probeURL},
			DiscoveredAt: now,
		})
	}

	// Only test bypass headers if the rate-limit window is still active.
	if controlProbe(ctx, client, probeURL) != http.StatusTooManyRequests {
		return findings, nil
	}

	for _, hdr := range bypassHeaders {
		bypassed, code := bypassProbe(ctx, client, probeURL, hdr.name, hdr.value)
		if bypassed {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckRateLimitBypass,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("Rate limit bypassed via %s header on %s", hdr.name, probeURL),
				Description: fmt.Sprintf(
					"The server returned HTTP 429 during burst probing but responded with %d "+
						"when the %s: %s header was added. This indicates rate limiting is based "+
						"solely on the client IP reported by this header, which an attacker can "+
						"forge to reset their quota on every request.",
					code, hdr.name, hdr.value,
				),
				Evidence: map[string]any{
					"probe_url":      probeURL,
					"bypass_header":  hdr.name,
					"bypass_value":   hdr.value,
					"bypass_status":  code,
					"blocked_status": http.StatusTooManyRequests,
				},
				ProofCommand: fmt.Sprintf(
					"# First trigger the rate limit:\nfor i in $(seq 1 20); do curl -so /dev/null -w '%%{http_code}\\n' '%s'; done\n"+
						"# Then bypass it with the forged header:\ncurl -si -H '%s: %s' '%s' | head -5",
					probeURL, hdr.name, hdr.value, probeURL),
				DiscoveredAt: now,
			})
		}
	}
	return findings, nil
}

// ── Core probe ────────────────────────────────────────────────────────────────

// burstProbe sends count sequential GET requests to url with delay between
// each, recording status codes, latencies, body hashes, and rate-limit signals.
func burstProbe(ctx context.Context, client *http.Client, url string, count int, delay time.Duration) *probeRun {
	r := &probeRun{
		statusCodes: make(map[int]int),
	}

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			break
		}

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		r.totalRequests++

		if err != nil {
			r.connErrors++
			r.statusCodes[-1]++
		} else {
			r.statusCodes[resp.StatusCode]++
			r.latencies = append(r.latencies, elapsed)

			// Observe rate-limit headers.
			for _, name := range rateLimitHeaderNames {
				if v := resp.Header.Get(name); v != "" {
					r.rlHeaders = append(r.rlHeaders, name+": "+v)
				}
			}

			// Hash first 512 bytes of body for change detection.
			buf := make([]byte, 512)
			n, _ := io.ReadFull(resp.Body, buf)
			resp.Body.Close()

			h := fnv.New32a()
			h.Write(buf[:n])
			r.bodyHashes = append(r.bodyHashes, h.Sum32())

			// Challenge-page detection.
			bodyLower := strings.ToLower(string(buf[:n]))
			for _, kw := range challengeKeywords {
				if strings.Contains(bodyLower, kw) {
					r.challengeSeen = true
					break
				}
			}
		}

		if i < count-1 && delay > 0 {
			select {
			case <-ctx.Done():
				return r
			case <-time.After(delay):
			}
		}
	}

	return r
}

// ── Signal detection ─────────────────────────────────────────────────────────

// detectSignal analyses a probeRun and returns the strongest throttle signal
// observed. Signals are checked in priority order: 429 → headers → 403 →
// challenge → body change → latency → conn reset.
func detectSignal(r *probeRun) throttleSignal {
	if r.statusCodes[http.StatusTooManyRequests] > 0 {
		return signal429
	}

	// Rate-limit headers mean RL is configured — don't report it as missing.
	if len(r.rlHeaders) > 0 {
		return signalHeaders
	}

	// 403 appearing after successful 200s suggests WAF throttling, not auth.
	if r.statusCodes[http.StatusForbidden] > 0 && r.statusCodes[http.StatusOK] > 0 {
		return signal403
	}

	if r.challengeSeen {
		return signalChallenge
	}

	if bodyChangedMidBurst(r.bodyHashes) {
		return signalBodyChange
	}

	if latencySpike(r.latencies) {
		return signalLatency
	}

	// Connection errors that started after some clean responses.
	if r.connErrors > 0 && len(r.latencies) > 3 {
		return signalConnReset
	}

	return signalNone
}

// signalDetails returns a human-readable label and detail string for a signal.
func signalDetails(sig throttleSignal, r *probeRun) (label, detail string) {
	switch sig {
	case signal403:
		return "403 Forbidden after 200 OK responses",
			fmt.Sprintf("%d OK responses followed by %d 403 responses", r.statusCodes[200], r.statusCodes[403])
	case signalConnReset:
		return "connection resets mid-burst",
			fmt.Sprintf("%d connection errors after %d successful responses", r.connErrors, len(r.latencies))
	case signalLatency:
		return "response latency spike detected",
			fmt.Sprintf("baseline: %v, spike observed", medianDuration(r.latencies[:3]))
	case signalChallenge:
		return "challenge/CAPTCHA page detected", "challenge keywords found in response body"
	case signalBodyChange:
		return "response body changed mid-burst", "response body hash changed after initial requests"
	default:
		return "unknown signal", ""
	}
}

// ── Signal helpers ────────────────────────────────────────────────────────────

func bodyChangedMidBurst(hashes []uint32) bool {
	if len(hashes) < 5 {
		return false
	}
	baseline := hashes[0]
	changed := 0
	tail := hashes[3:]
	for _, h := range tail {
		if h != baseline {
			changed++
		}
	}
	// Flag only if >half of later responses differ — reduces false positives
	// from pages that include a timestamp or nonce in every response.
	return changed > len(tail)/2
}

func latencySpike(latencies []time.Duration) bool {
	if len(latencies) < 5 {
		return false
	}
	baseline := medianDuration(latencies[:3])
	// Anchor to 50 ms minimum so fast responses on localhost don't
	// cause 5× = 250 ms to be flagged as a "spike".
	const minBaseline = 50 * time.Millisecond
	if baseline < minBaseline {
		baseline = minBaseline
	}
	threshold := baseline * 5
	// Require 2+ spiky requests to reduce noise from a single slow response.
	spikes := 0
	for _, lat := range latencies[3:] {
		if lat > threshold {
			spikes++
		}
	}
	return spikes >= 2
}

func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(ds))
	copy(sorted, ds)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// ── Existing helpers (unchanged API) ────────────────────────────────────────

// controlProbe sends a single plain GET to url and returns the HTTP status
// code. Used to verify the server is still rate-limiting before testing bypass
// headers.
func controlProbe(ctx context.Context, client *http.Client, url string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// bypassProbe sends a single request with the given header. Returns true and
// the status code when the server responds with a 2xx — indicating the rate
// limit was bypassed.
func bypassProbe(ctx context.Context, client *http.Client, url, headerName, headerValue string) (bool, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, 0
	}
	req.Header.Set(headerName, headerValue)

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	resp.Body.Close()

	code := resp.StatusCode
	bypassed := code >= 200 && code < 300
	return bypassed, code
}

// retryAfterPresent sends a single request to url and returns true if the
// response includes a non-empty Retry-After header.
func retryAfterPresent(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return true // assume present on error — avoid false positive
	}
	resp, err := client.Do(req)
	if err != nil {
		return true
	}
	resp.Body.Close()
	return resp.Header.Get("Retry-After") != ""
}

// findProbeTarget returns the first API path that responds with a non-404,
// non-500 status code on the target asset.
func findProbeTarget(ctx context.Context, client *http.Client, asset string, probes []string) (string, string) {
	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + asset
		for _, path := range probes {
			url := base + path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound && resp.StatusCode < 500 {
				return base, url
			}
		}
	}
	return "", ""
}
