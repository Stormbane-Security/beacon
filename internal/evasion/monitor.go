package evasion

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// DetectionType categorizes the defense mechanism that was detected.
type DetectionType string

const (
	DetectionRateLimit    DetectionType = "rate_limit"
	DetectionIPBlock      DetectionType = "ip_block"
	DetectionCAPTCHA      DetectionType = "captcha"
	DetectionWAFChallenge DetectionType = "waf_challenge"
	DetectionTarpit       DetectionType = "tarpit"
)

// Detection describes a detected defense mechanism.
type Detection struct {
	Type       DetectionType
	Confidence float64
	Evidence   string
}

// Monitor tracks HTTP response patterns and detects when target defenses
// (WAF, IDS, rate limiting) are responding to scanning activity.
type Monitor struct {
	mu              sync.Mutex
	baselineStatus  map[string]int           // URL → last known good status
	baselineLatency map[string]time.Duration // URL → rolling average latency
	latencyCount    map[string]int           // URL → number of samples
	blocked         bool
	rateLimited     bool
	captchaDetected bool
	tarpitDetected  bool

	// strategy is the evasion strategy to adapt when defenses are detected.
	strategy *Strategy

	// findings collects ids.detected findings emitted by the monitor.
	findings []finding.Finding
}

// NewMonitor creates a Monitor that can optionally adapt an evasion Strategy.
// strategy may be nil if no adaptive behavior is desired.
func NewMonitor(strategy *Strategy) *Monitor {
	return &Monitor{
		baselineStatus:  make(map[string]int),
		baselineLatency: make(map[string]time.Duration),
		latencyCount:    make(map[string]int),
		strategy:        strategy,
	}
}

// Blocked returns true if the monitor has detected an IP block on the current target.
func (m *Monitor) Blocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blocked
}

// RateLimited returns true if the monitor has detected rate limiting.
func (m *Monitor) RateLimited() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rateLimited
}

// CaptchaDetected returns true if a CAPTCHA or WAF challenge was seen.
func (m *Monitor) CaptchaDetected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.captchaDetected
}

// TarpitDetected returns true if tarpit behavior was observed.
func (m *Monitor) TarpitDetected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tarpitDetected
}

// Findings returns all ids.detected findings accumulated by the monitor.
func (m *Monitor) Findings() []finding.Finding {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]finding.Finding, len(m.findings))
	copy(out, m.findings)
	return out
}

// CheckResponse analyzes an HTTP response for defense signals. It returns a
// Detection if a defense mechanism was identified, or nil if the response
// looks normal. A nil resp is treated as a connection failure (potential IP block).
func (m *Monitor) CheckResponse(url string, resp *http.Response, latency time.Duration) *Detection {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Connection failure after prior successes → possible IP block.
	if resp == nil {
		if _, ok := m.baselineStatus[url]; ok {
			det := &Detection{
				Type:       DetectionIPBlock,
				Confidence: 0.7,
				Evidence:   "connection failed after prior successful responses",
			}
			m.blocked = true
			m.emitFinding(url, det)
			m.adapt(det)
			return det
		}
		return nil
	}

	// Read a limited amount of body for pattern matching.
	var bodySnippet string
	if resp.Body != nil {
		limited := io.LimitReader(resp.Body, 8192)
		raw, _ := io.ReadAll(limited)
		bodySnippet = strings.ToLower(string(raw))
	}

	// --- Rate limit detection ---
	if resp.StatusCode == 429 || (resp.StatusCode == 503 && m.baselineStatus[url] == 200) {
		det := &Detection{
			Type:       DetectionRateLimit,
			Confidence: 0.9,
			Evidence:   "HTTP " + http.StatusText(resp.StatusCode) + " after prior 200 responses",
		}
		m.rateLimited = true
		m.emitFinding(url, det)
		m.adapt(det)
		return det
	}

	// --- CAPTCHA detection ---
	captchaSignals := []string{"captcha", "challenge", "recaptcha", "hcaptcha", "cf-turnstile"}
	for _, sig := range captchaSignals {
		if strings.Contains(bodySnippet, sig) {
			det := &Detection{
				Type:       DetectionCAPTCHA,
				Confidence: 0.85,
				Evidence:   "response body contains \"" + sig + "\"",
			}
			m.captchaDetected = true
			m.emitFinding(url, det)
			m.adapt(det)
			return det
		}
	}

	// --- WAF challenge detection ---
	wafSignals := []string{"security check", "ray id", "cloudflare", "akamai"}
	for _, sig := range wafSignals {
		if strings.Contains(bodySnippet, sig) {
			det := &Detection{
				Type:       DetectionWAFChallenge,
				Confidence: 0.8,
				Evidence:   "response body contains WAF indicator \"" + sig + "\"",
			}
			m.captchaDetected = true
			m.emitFinding(url, det)
			m.adapt(det)
			return det
		}
	}

	// --- Tarpit detection ---
	if avg, ok := m.baselineLatency[url]; ok && m.latencyCount[url] >= 2 && avg > 0 {
		if latency > avg*10 {
			det := &Detection{
				Type:       DetectionTarpit,
				Confidence: 0.75,
				Evidence:   "response latency " + latency.String() + " exceeds 10x baseline average " + avg.String(),
			}
			m.tarpitDetected = true
			m.emitFinding(url, det)
			m.adapt(det)
			return det
		}
	}

	// No detection — update baselines.
	m.baselineStatus[url] = resp.StatusCode
	m.updateLatency(url, latency)

	return nil
}

// updateLatency maintains a rolling average latency for a URL.
func (m *Monitor) updateLatency(url string, latency time.Duration) {
	count := m.latencyCount[url]
	if count == 0 {
		m.baselineLatency[url] = latency
		m.latencyCount[url] = 1
		return
	}
	// Incremental average: avg = avg + (new - avg) / (count + 1)
	avg := m.baselineLatency[url]
	count++
	avg = avg + (latency-avg)/time.Duration(count)
	m.baselineLatency[url] = avg
	m.latencyCount[url] = count
}

// adapt modifies the evasion strategy in response to a detection.
func (m *Monitor) adapt(det *Detection) {
	if m.strategy == nil {
		return
	}
	switch det.Type {
	case DetectionRateLimit:
		// Double jitter and add 5s base delay.
		if m.strategy.MaxJitterMs == 0 {
			m.strategy.MaxJitterMs = 5000
		} else {
			m.strategy.MaxJitterMs *= 2
		}
		m.strategy.BaseDelayMs += 5000
	case DetectionCAPTCHA, DetectionWAFChallenge:
		// Signal scanners to skip remaining probes for this host.
		// Handled via the CaptchaDetected() / Blocked() checks.
	case DetectionTarpit:
		// Signal scanners to skip this host.
		// Handled via TarpitDetected() check.
	case DetectionIPBlock:
		// Signal scanners to stop entirely for this target.
		m.blocked = true
	}
}

// emitFinding creates an ids.detected finding for the given detection.
func (m *Monitor) emitFinding(url string, det *Detection) {
	f := finding.Finding{
		CheckID:     finding.CheckIDSDetected,
		Module:      "surface",
		Scanner:     "evasion_monitor",
		Severity:    finding.SeverityInfo,
		Title:       "Defense detected: " + string(det.Type),
		Description: recommendation(det.Type),
		Asset:       url,
		Evidence: map[string]any{
			"detection_type": string(det.Type),
			"confidence":     det.Confidence,
			"evidence":       det.Evidence,
		},
		ProofCommand: "curl -v " + url,
		Confidence:   finding.ConfidenceObserved,
		DiscoveredAt: time.Now(),
	}
	m.findings = append(m.findings, f)
}

// recommendation returns a human-readable recommendation for a detection type.
func recommendation(dt DetectionType) string {
	switch dt {
	case DetectionRateLimit:
		return "Target is rate limiting requests. Beacon has increased request jitter and base delay to reduce scan footprint."
	case DetectionIPBlock:
		return "Target appears to have blocked our IP. Scanning of this target has been stopped. Consider using proxy rotation."
	case DetectionCAPTCHA:
		return "Target is presenting a CAPTCHA challenge. Remaining probes for this host have been skipped."
	case DetectionWAFChallenge:
		return "Target WAF is presenting a security challenge. Remaining probes for this host have been skipped."
	case DetectionTarpit:
		return "Target appears to be tarpitting connections (extremely slow responses). This host has been skipped."
	default:
		return "Unknown defense mechanism detected."
	}
}

// HostTimeoutChecker is the interface used by MonitoredTransport to record
// timeouts and successes without importing the scan package (avoiding cycles).
type HostTimeoutChecker interface {
	RecordTimeout(host string) bool
	RecordSuccess(host string)
	ShouldSkip(host string) bool
}

// MonitoredTransport wraps an http.RoundTripper and automatically checks every
// response through the Monitor for defense signals. When an AdaptiveRate is
// configured, it waits before each request based on observed WAF/rate patterns,
// automatically slowing down when blocks are detected and speeding up when
// responses normalize.
type MonitoredTransport struct {
	Base    http.RoundTripper
	Monitor *Monitor

	// Rate is an optional adaptive rate limiter. When set, each request waits
	// Rate.Wait() before sending, and each response updates the rate via
	// Rate.RecordResponse(). This creates a feedback loop: WAF blocks → slow
	// down → blocks stop → speed back up.
	Rate *AdaptiveRate

	// HostTimeouts is an optional tracker for consecutive per-host timeouts.
	// When set, timeout errors increment the host's counter and successful
	// responses reset it. After the threshold is reached, requests to the
	// host are short-circuited with ErrHostBailed.
	HostTimeouts HostTimeoutChecker
}

// ErrHostBailed is returned when a host has been marked as unresponsive
// after too many consecutive timeouts. Callers should treat this as a
// permanent skip — no further probes will succeed.
var ErrHostBailed = fmt.Errorf("host bailed: too many consecutive timeouts")

// RoundTrip executes the request using the base transport, then feeds the
// response through the Monitor's detection logic.
func (t *MonitoredTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Fast path: if the host has already been bailed on, don't even try.
	if t.HostTimeouts != nil {
		host := req.URL.Hostname()
		if t.HostTimeouts.ShouldSkip(host) {
			return nil, ErrHostBailed
		}
	}

	// Wait for adaptive rate limiter before sending request.
	if t.Rate != nil {
		t.Rate.Wait(req.Context())
	}

	start := time.Now()
	resp, err := t.Base.RoundTrip(req)
	latency := time.Since(start)

	reqURL := req.URL.String()

	if err != nil {
		// Track consecutive timeouts per host.
		if t.HostTimeouts != nil && isTimeoutErr(err) {
			host := req.URL.Hostname()
			t.HostTimeouts.RecordTimeout(host)
		}
		// Pass nil resp to signal connection failure.
		t.Monitor.CheckResponse(reqURL, nil, latency)
		return nil, err
	}

	// Successful response — reset the host's timeout counter.
	if t.HostTimeouts != nil {
		host := req.URL.Hostname()
		t.HostTimeouts.RecordSuccess(host)
	}

	// We need to read part of the body for detection without consuming it
	// for the caller. Buffer the body, check it, then re-wrap.
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	// Create a temporary response with the body for the monitor to inspect.
	checkResp := *resp
	if len(bodyBytes) > 0 {
		checkResp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}
	t.Monitor.CheckResponse(reqURL, &checkResp, latency)

	// Feed the response into the adaptive rate limiter for automatic speed adjustment.
	if t.Rate != nil {
		t.Rate.RecordResponse(latency, resp.StatusCode)
	}

	// Restore the original body for the caller.
	if len(bodyBytes) > 0 {
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	} else {
		resp.Body = io.NopCloser(strings.NewReader(""))
	}

	return resp, nil
}

// isTimeoutErr returns true if the error is a network timeout.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "i/o timeout")
}
