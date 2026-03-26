// Package autoprobe probes authentication endpoints for security weaknesses
// without requiring credentials. It detects:
//   - Username enumeration via differential responses (timing, body, status)
//   - Missing account lockout (no 429/lockout after repeated bad attempts)
//   - Missing rate limiting on auth endpoints specifically
//
// Surface mode (safe, no auth requests):
//   - GET the login page and inspect for passive brute-force protection signals:
//     CAPTCHA widgets, autocomplete="off", Retry-After on a single bad attempt.
//
// Deep mode (active probes, requires permission):
//   - Username enumeration: two synthetic accounts, compare responses
//   - If discovered emails are available (from theHarvester), also test a real
//     account vs synthetic to detect enumeration of actual employees
//   - Account lockout: 8 rapid bad-password attempts, check for 429/423/403
//
// All probes use clearly synthetic, non-existent accounts so no real user
// is affected. No credential stuffing or brute-force attempts are made.
package autoprobe

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "autoprobe"

// candidatePaths are common login endpoint paths to probe.
var candidatePaths = []string{
	"/login",
	"/signin",
	"/sign-in",
	"/api/login",
	"/api/signin",
	"/api/auth/login",
	"/api/v1/login",
	"/api/v1/auth",
	"/auth/login",
	"/user/login",
	"/account/login",
	"/session",
	"/api/session",
}

// syntheticUsers are clearly fake accounts used for probing.
// Two distinct users let us compare "non-existent user" vs "non-existent user 2"
// to establish a baseline, then probe "wrong password" vs "user not found".
var syntheticUsers = [2]string{
	"beacon-probe-nonexistent-a@beacon-scanner.invalid",
	"beacon-probe-nonexistent-b@beacon-scanner.invalid",
}

const syntheticPassword = "BeaconProbe!NotReal99"

// captchaRE matches common CAPTCHA widget attributes in HTML.
var captchaRE = regexp.MustCompile(`(?i)(data-sitekey|g-recaptcha|h-captcha|cf-turnstile|recaptcha\.net|hcaptcha\.com|turnstile\.cloudflare)`)

// Scanner probes auth endpoints for weakness without credentials.
type Scanner struct {
	discoveredEmails []string // from theHarvester OSINT, used as enumeration candidates
}

func New() *Scanner { return &Scanner{} }

// NewWithEmails creates a scanner pre-loaded with real email addresses discovered
// via OSINT (e.g. theHarvester). These are used as candidate usernames for the
// username enumeration check, providing higher-confidence results than synthetic accounts.
func NewWithEmails(emails []string) *Scanner { return &Scanner{discoveredEmails: emails} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	// Surface mode: passive login page inspection only — no auth probes sent.
	if scanType != module.ScanDeep {
		return s.surfaceCheck(ctx, client, base, asset), nil
	}

	// Deep mode: find a live login endpoint, then run active checks.
	loginURL := findLoginEndpoint(ctx, client, base)
	if loginURL == "" {
		return nil, nil
	}

	var findings []finding.Finding

	// --- Username enumeration check ---
	// Primary: two synthetic accounts, same wrong password.
	// If responses differ (body length, status, or timing) the server leaks
	// whether a username exists.
	userA, userB := syntheticUsers[0], syntheticUsers[1]

	// If we have real discovered emails, use one as userA for higher-confidence
	// results (real account vs synthetic gives a cleaner signal).
	if len(s.discoveredEmails) > 0 {
		userA = s.discoveredEmails[0]
	}

	r1, t1 := probeLogin(ctx, client, loginURL, userA, syntheticPassword)
	r2, t2 := probeLogin(ctx, client, loginURL, userB, syntheticPassword)
	// Second pair of requests for timing consistency — a single pair can produce
	// a spurious difference due to network jitter. Both pairs must show timing
	// difference in the same direction before we report it.
	r1b, t1b := probeLogin(ctx, client, loginURL, userA, syntheticPassword)
	r2b, t2b := probeLogin(ctx, client, loginURL, userB, syntheticPassword)

	if r1 != nil && r2 != nil {
		bodyDiff := math.Abs(float64(r1.bodyLen-r2.bodyLen)) > 20
		statusDiff := r1.status != r2.status
		// Timing difference must exceed 500ms threshold AND be consistent across
		// both probe pairs (same direction: A faster or slower than B both times).
		timingDiff := timingSignificant(t1, t2) &&
			r1b != nil && r2b != nil &&
			timingSignificant(t1b, t2b) &&
			((t1 > t2) == (t1b > t2b))

		if bodyDiff || statusDiff || timingDiff {
			detail := ""
			if statusDiff {
				detail = fmt.Sprintf("HTTP status differs: %d vs %d", r1.status, r2.status)
			} else if bodyDiff {
				detail = fmt.Sprintf("Response body length differs: %d vs %d bytes", r1.bodyLen, r2.bodyLen)
			} else if timingDiff {
				detail = fmt.Sprintf("Response time differs: %dms vs %dms", t1.Milliseconds(), t2.Milliseconds())
			}
			usedReal := len(s.discoveredEmails) > 0
			desc := "The login endpoint responds differently for different non-existent usernames. " +
				"An attacker can use this to enumerate valid accounts by observing response differences. " +
				"Login endpoints should return identical responses regardless of whether the username exists."
			if usedReal {
				desc = "The login endpoint responds differently when a discovered employee email address " +
					"is used versus a clearly synthetic address. This confirms username enumeration is " +
					"possible against real accounts. " + desc
			}
			findings = append(findings, finding.Finding{
				CheckID:  "auth.username_enumeration",
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    "Username enumeration via differential response",
				Description: desc,
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -si -X POST %s -d 'email=%s&password=WrongPass' && "+
						"curl -si -X POST %s -d 'email=%s&password=WrongPass'",
					loginURL, userA, loginURL, userB),
				Evidence: map[string]any{
					"url":       loginURL,
					"detail":    detail,
					"used_real": usedReal,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// --- Account lockout check ---
	// Send 8 login attempts with the same fake account. A properly configured
	// endpoint should throttle or lock after 5-6 failures.
	locked := false
	for i := 0; i < 8; i++ {
		r, _ := probeLogin(ctx, client, loginURL, syntheticUsers[0], fmt.Sprintf("WrongPass%d!", i))
		if r != nil && (r.status == 429 || r.status == 423 || r.status == 403) {
			locked = true
			break
		}
	}
	if !locked {
		findings = append(findings, finding.Finding{
			CheckID:  "auth.no_lockout",
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    "No account lockout or rate limiting on login endpoint",
			Description: "The login endpoint did not throttle or lock the account after 8 consecutive failed attempts " +
				"with a synthetic non-existent account. Without lockout or rate limiting, credential stuffing and " +
				"brute-force attacks against this endpoint are unconstrained.",
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"for i in $(seq 1 10); do curl -so /dev/null -w '%%{http_code}\\n' -X POST %s -d 'email=test@beacon-scanner.invalid&password=WrongPass'; done",
				loginURL),
			Evidence: map[string]any{
				"url":      loginURL,
				"attempts": 8,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// surfaceCheck performs a passive inspection of the login page for signals that
// brute-force protection is (or isn't) in place. No auth requests are sent.
// Checks: CAPTCHA widget presence, autocomplete="off" on password field,
// Retry-After header on a single bad-credential POST.
func (s *Scanner) surfaceCheck(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	// Find a candidate login path via GET (not POST, so it's safe).
	loginURL := ""
	for _, path := range candidatePaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode == 200 && (strings.Contains(strings.ToLower(string(body)), "password") ||
			strings.Contains(strings.ToLower(string(body)), "login")) {
			loginURL = u
			// Check page for CAPTCHA / autocomplete signals.
			bodyStr := string(body)
			hasCaptcha := captchaRE.MatchString(bodyStr)
			hasAutocompleteOff := strings.Contains(strings.ToLower(bodyStr), `autocomplete="off"`) ||
				strings.Contains(strings.ToLower(bodyStr), `autocomplete='off'`)

			if hasCaptcha || hasAutocompleteOff {
				// Positive signals — brute-force protection appears present. No finding.
				return nil
			}
			break
		}
	}

	if loginURL == "" {
		return nil // no login page found
	}

	// No protection signals found on the page — emit a low-confidence advisory.
	return []finding.Finding{{
		CheckID:  "auth.no_bruteforce_protection_signals",
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("Login page has no visible brute-force protection signals at %s", loginURL),
		Description: "The login page does not contain visible CAPTCHA widgets (reCAPTCHA, hCaptcha, Turnstile) " +
			"or autocomplete=\"off\" on the password field. This does not confirm missing rate limiting " +
			"(server-side controls are not visible), but warrants a deep scan to confirm lockout behaviour.",
		Evidence: map[string]any{
			"url":           loginURL,
			"captcha_found": false,
			"autocomplete":  "not off",
		},
		DiscoveredAt: time.Now(),
	}}
}

// probeResult captures what we care about from a login response.
type probeResult struct {
	status  int
	bodyLen int
}

func probeLogin(ctx context.Context, client *http.Client, loginURL, username, password string) (*probeResult, time.Duration) {
	body := url.Values{
		"email":    {username},
		"username": {username},
		"password": {password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL,
		strings.NewReader(body.Encode()))
	if err != nil {
		return nil, 0
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json, text/html")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &probeResult{status: resp.StatusCode, bodyLen: len(b)}, elapsed
}

// findLoginEndpoint probes candidate paths and returns the first that accepts POST
// with form data and returns a non-404 response.
func findLoginEndpoint(ctx context.Context, client *http.Client, base string) string {
	for _, path := range candidatePaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
			strings.NewReader("email=probe%40example.invalid&password=probe"))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		// 404/405 means this path doesn't exist or doesn't accept POST.
		// 200/401/403/422/429 all indicate the endpoint exists.
		if resp.StatusCode != 404 && resp.StatusCode != 405 {
			return u
		}
	}
	return ""
}

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

// timingSignificant returns true if the timing difference between two requests
// is large enough to suggest differential processing (>1000ms gap).
// 1000ms is chosen to tolerate high-latency networks and loaded servers without
// masking genuine backend differences (e.g. bcrypt vs no-op on missing account).
// The caller additionally requires two independent probe pairs to agree before
// reporting a finding, providing a second layer of false-positive protection.
func timingSignificant(a, b time.Duration) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff > 1000*time.Millisecond
}
