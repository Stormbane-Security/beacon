package ratelimit

// Unit tests for the ratelimit scanner helpers.
//
// Tests are written against expected correct behaviour, not to rubber-stamp
// the existing implementation. Each test documents the precise contract it
// verifies so failures are immediately actionable.
//
// Real HTTP servers are used (httptest) to avoid mocking the stdlib.
// Inter-request delays inside burstProbe are avoided by using count=1
// or by passing delay=0 — the delay guard (i < count-1) means the last
// request never waits.
//
// Contracts tested:
//   burstProbe:    429 detection, status code tallying, network error counting,
//                  rate-limit header recording, body-hash recording,
//                  challenge keyword detection, context cancellation
//   detectSignal:  429 → signal429; rl headers → signalHeaders (no "missing");
//                  403-after-200 → signal403; challenge page → signalChallenge
//   bodyChangedMidBurst: stable body → false; changed body → true
//   latencySpike:  uniform latencies → false; spike ≥2 → true
//   controlProbe:  correct status code pass-through
//   bypassProbe:   2xx → bypass=true; 429/403/3xx → bypass=false
//   findProbeTarget: first non-404/non-5xx path wins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── burstProbe ────────────────────────────────────────────────────────────────

func TestBurstProbe_Detects429(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	run := burstProbe(context.Background(), ts.Client(), ts.URL, 4, 0)
	if run.statusCodes[http.StatusTooManyRequests] == 0 {
		t.Errorf("burstProbe: expected 429 in status code tally, got %v", run.statusCodes)
	}
	if detectSignal(run) != signal429 {
		t.Error("burstProbe: expected detectSignal to return signal429")
	}
}

func TestBurstProbe_No429_NoSignal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	run := burstProbe(context.Background(), ts.Client(), ts.URL, 4, 0)
	if run.statusCodes[http.StatusOK] == 0 {
		t.Errorf("burstProbe: expected 200 in tally, got %v", run.statusCodes)
	}
	if detectSignal(run) != signalNone {
		t.Errorf("burstProbe: expected signalNone for all-200 responses, got %v", detectSignal(run))
	}
}

func TestBurstProbe_NetworkError_CountsAsMinusOne(t *testing.T) {
	run := burstProbe(context.Background(), &http.Client{}, "http://127.0.0.1:1", 2, 0)
	if run.statusCodes[-1] == 0 {
		t.Error("burstProbe: expected network errors to be tallied under key -1")
	}
}

func TestBurstProbe_ContextCancelled_StopsEarly(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before any request

	burstProbe(ctx, ts.Client(), ts.URL, 8, 0) // must not hang
	if requestCount > 1 {
		t.Errorf("burstProbe with cancelled ctx: expected ≤1 requests, got %d", requestCount)
	}
}

func TestBurstProbe_RateLimitHeadersRecorded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "95")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	run := burstProbe(context.Background(), ts.Client(), ts.URL, 2, 0)
	if len(run.rlHeaders) == 0 {
		t.Error("burstProbe: expected rate-limit headers to be recorded")
	}
}

func TestBurstProbe_ChallengeKeywordDetected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>Please solve the CAPTCHA challenge to continue.</body></html>`))
	}))
	defer ts.Close()

	run := burstProbe(context.Background(), ts.Client(), ts.URL, 2, 0)
	if !run.challengeSeen {
		t.Error("burstProbe: expected challengeSeen=true when body contains CAPTCHA keyword")
	}
}

func TestBurstProbe_TotalRequestsAccurate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	const want = 5
	run := burstProbe(context.Background(), ts.Client(), ts.URL, want, 0)
	if run.totalRequests != want {
		t.Errorf("burstProbe: totalRequests = %d, want %d", run.totalRequests, want)
	}
}

// ── detectSignal ──────────────────────────────────────────────────────────────

func TestDetectSignal_429(t *testing.T) {
	r := &probeRun{statusCodes: map[int]int{429: 1, 200: 5}}
	if got := detectSignal(r); got != signal429 {
		t.Errorf("detectSignal: got %v, want signal429", got)
	}
}

func TestDetectSignal_RateLimitHeaders_ReturnsSignalHeaders(t *testing.T) {
	// When rate-limit headers are present, the server has rate limiting configured
	// even though no 429 was returned. We return signalHeaders so the caller can
	// skip emitting a "missing rate limit" finding.
	r := &probeRun{
		statusCodes: map[int]int{200: 8},
		rlHeaders:   []string{"X-RateLimit-Limit: 100"},
	}
	if got := detectSignal(r); got != signalHeaders {
		t.Errorf("detectSignal: got %v, want signalHeaders — server has RL, just not triggered", got)
	}
}

func TestDetectSignal_403AfterOK_Returns403Signal(t *testing.T) {
	// 403 appearing after 200 OKs suggests WAF throttling, not auth.
	r := &probeRun{statusCodes: map[int]int{200: 6, 403: 2}}
	if got := detectSignal(r); got != signal403 {
		t.Errorf("detectSignal: got %v, want signal403", got)
	}
}

func TestDetectSignal_403Only_NoSignal(t *testing.T) {
	// 403 with no preceding 200s is just auth-required, not throttling.
	r := &probeRun{statusCodes: map[int]int{403: 8}}
	if got := detectSignal(r); got != signalNone {
		t.Errorf("detectSignal: got %v, want signalNone (403-only is auth, not rate limit)", got)
	}
}

func TestDetectSignal_ChallengePage(t *testing.T) {
	r := &probeRun{
		statusCodes:   map[int]int{200: 8},
		challengeSeen: true,
	}
	if got := detectSignal(r); got != signalChallenge {
		t.Errorf("detectSignal: got %v, want signalChallenge", got)
	}
}

func TestDetectSignal_NoSignal(t *testing.T) {
	r := &probeRun{statusCodes: map[int]int{200: 8}}
	if got := detectSignal(r); got != signalNone {
		t.Errorf("detectSignal: got %v, want signalNone for clean 200-only run", got)
	}
}

// ── bodyChangedMidBurst ───────────────────────────────────────────────────────

func TestBodyChanged_StableBody_ReturnsFalse(t *testing.T) {
	hashes := []uint32{111, 111, 111, 111, 111, 111}
	if bodyChangedMidBurst(hashes) {
		t.Error("bodyChangedMidBurst: expected false for stable body hashes")
	}
}

func TestBodyChanged_ChangedMidBurst_ReturnsTrue(t *testing.T) {
	// First 2 requests match baseline, then all subsequent differ.
	hashes := []uint32{111, 111, 222, 222, 222, 222}
	if !bodyChangedMidBurst(hashes) {
		t.Error("bodyChangedMidBurst: expected true when >50% of later hashes differ from baseline")
	}
}

func TestBodyChanged_TooFewHashes_ReturnsFalse(t *testing.T) {
	// Need ≥5 hashes to draw a conclusion.
	hashes := []uint32{111, 222, 333}
	if bodyChangedMidBurst(hashes) {
		t.Error("bodyChangedMidBurst: expected false when fewer than 5 hashes")
	}
}

func TestBodyChanged_MinorVariation_ReturnsFalse(t *testing.T) {
	// Only 1 of 5 later responses differs — below the >50% threshold.
	hashes := []uint32{111, 111, 111, 111, 111, 222}
	if bodyChangedMidBurst(hashes) {
		t.Error("bodyChangedMidBurst: expected false when only 1 of 5 later hashes differ")
	}
}

// ── latencySpike ──────────────────────────────────────────────────────────────

func TestLatencySpike_UniformLatencies_ReturnsFalse(t *testing.T) {
	lats := []time.Duration{100, 110, 95, 105, 100, 108}
	lats = ms(lats)
	if latencySpike(lats) {
		t.Error("latencySpike: expected false for uniform latencies")
	}
}

func TestLatencySpike_TwoSpikes_ReturnsTrue(t *testing.T) {
	// Baseline ~100 ms, two later requests at 700 ms (>5× threshold).
	lats := ms([]time.Duration{100, 100, 100, 700, 700, 100})
	if !latencySpike(lats) {
		t.Error("latencySpike: expected true when 2+ requests exceed 5× baseline")
	}
}

func TestLatencySpike_OnlyOneSpike_ReturnsFalse(t *testing.T) {
	// A single slow response is noise — require ≥2 spikes.
	lats := ms([]time.Duration{100, 100, 100, 700, 100, 100})
	if latencySpike(lats) {
		t.Error("latencySpike: expected false for a single spike (could be noise)")
	}
}

func TestLatencySpike_TooFewLatencies_ReturnsFalse(t *testing.T) {
	// Need ≥5 samples to distinguish warmup from spike.
	lats := ms([]time.Duration{100, 100, 700})
	if latencySpike(lats) {
		t.Error("latencySpike: expected false when fewer than 5 latency samples")
	}
}

func TestLatencySpike_FastLocalServer_NoFalsePositive(t *testing.T) {
	// A server returning in <50 ms shouldn't false-positive: the 50 ms minimum
	// baseline prevents 5× = 250 ms from looking like a spike on a fast LAN.
	lats := ms([]time.Duration{1, 1, 1, 200, 200, 1})
	// 200 ms spike on a 1 ms baseline would be 200×, but the min baseline
	// floors it to 50 ms, so threshold = 250 ms — 200 ms does NOT exceed it.
	if latencySpike(lats) {
		t.Error("latencySpike: expected false for sub-50ms baseline (min baseline guard)")
	}
}

// ms converts a slice of duration values to milliseconds for readability.
func ms(ds []time.Duration) []time.Duration {
	out := make([]time.Duration, len(ds))
	for i, d := range ds {
		out[i] = d * time.Millisecond
	}
	return out
}

// ── controlProbe ──────────────────────────────────────────────────────────────

func TestControlProbe_Returns429(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	if got := controlProbe(context.Background(), ts.Client(), ts.URL); got != 429 {
		t.Errorf("controlProbe: got %d, want 429", got)
	}
}

func TestControlProbe_Returns200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if got := controlProbe(context.Background(), ts.Client(), ts.URL); got != 200 {
		t.Errorf("controlProbe: got %d, want 200", got)
	}
}

func TestControlProbe_NetworkError_ReturnsZero(t *testing.T) {
	if got := controlProbe(context.Background(), &http.Client{}, "http://127.0.0.1:1"); got != 0 {
		t.Errorf("controlProbe: got %d, want 0 on network error", got)
	}
}

// ── bypassProbe ───────────────────────────────────────────────────────────────

func TestBypassProbe_200_Bypassed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer ts.Close()

	bypassed, code := bypassProbe(context.Background(), ts.Client(), ts.URL, "X-Forwarded-For", bypassForge)
	if !bypassed || code != 200 {
		t.Errorf("bypassProbe: got bypassed=%v code=%d; want true/200", bypassed, code)
	}
}

func TestBypassProbe_429_NotBypassed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	bypassed, _ := bypassProbe(context.Background(), ts.Client(), ts.URL, "X-Forwarded-For", bypassForge)
	if bypassed {
		t.Error("bypassProbe: expected false when server returns 429")
	}
}

func TestBypassProbe_403_NotBypassed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	bypassed, _ := bypassProbe(context.Background(), ts.Client(), ts.URL, "X-Real-IP", bypassForge)
	if bypassed {
		t.Error("bypassProbe: expected false when server returns 403")
	}
}

func TestBypassProbe_301_NotBypassed(t *testing.T) {
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	}))
	defer ts.Close()

	bypassed, code := bypassProbe(context.Background(), client, ts.URL, "X-Forwarded-For", bypassForge)
	if bypassed {
		t.Error("bypassProbe: expected false for 3xx (redirect to /login is not a bypass)")
	}
	if code != 301 {
		t.Errorf("bypassProbe: got %d, want 301", code)
	}
}

func TestBypassProbe_NetworkError_NotBypassed(t *testing.T) {
	bypassed, code := bypassProbe(context.Background(), &http.Client{}, "http://127.0.0.1:1", "X-Forwarded-For", bypassForge)
	if bypassed || code != 0 {
		t.Errorf("bypassProbe: got bypassed=%v code=%d; want false/0 on network error", bypassed, code)
	}
}

// Verify bypassForge uses an RFC 5737 documentation range, not RFC 1918.
func TestBypassForge_IsRFC5737(t *testing.T) {
	ip := bypassForge
	validPrefix := strings.HasPrefix(ip, "192.0.2.") ||
		strings.HasPrefix(ip, "198.51.100.") ||
		strings.HasPrefix(ip, "203.0.113.")
	if !validPrefix {
		t.Errorf("bypassForge %q is not in an RFC 5737 TEST-NET range", ip)
	}
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		t.Errorf("bypassForge %q is in RFC 1918 range; use TEST-NET (RFC 5737)", ip)
	}
}

// ── findProbeTarget ───────────────────────────────────────────────────────────

func TestFindProbeTarget_PicksFirstNon404Path(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v2/":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	_, probeURL := findProbeTarget(context.Background(), ts.Client(), host, []string{"/api/v1/", "/api/v2/"})
	if !strings.HasSuffix(probeURL, "/api/v2/") {
		t.Errorf("findProbeTarget: expected /api/v2/, got %q", probeURL)
	}
}

func TestFindProbeTarget_AllPaths404_ReturnsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	_, probeURL := findProbeTarget(context.Background(), ts.Client(), host, []string{"/api/v1/", "/api/"})
	if probeURL != "" {
		t.Errorf("findProbeTarget: expected empty when all 404, got %q", probeURL)
	}
}

func TestFindProbeTarget_SkipsServerErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	_, probeURL := findProbeTarget(context.Background(), ts.Client(), host, []string{"/api/v1/", "/api/v2/"})
	if !strings.HasSuffix(probeURL, "/api/v2/") {
		t.Errorf("findProbeTarget: expected /api/v2/ (5xx skipped), got %q", probeURL)
	}
}
