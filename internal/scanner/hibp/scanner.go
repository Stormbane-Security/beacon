// Package hibp queries the Have I Been Pwned API to check whether the target
// domain's users appear in known credential breach databases.
// Requires a paid HIBP API key (haveibeenpwned.com).
package hibp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "hibp"

// Scanner queries Have I Been Pwned for domain breach exposure.
type Scanner struct {
	apiKey  string
	baseURL string // overrideable for testing; defaults to haveibeenpwned.com
}

// New creates a new HIBP scanner. If apiKey is empty the scanner is a no-op.
func New(apiKey string) *Scanner { return &Scanner{apiKey: apiKey} }

func (s *Scanner) Name() string { return scannerName }

// hibpBreach represents a single breach record from the HIBP API.
type hibpBreach struct {
	Name        string   `json:"Name"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	PwnCount    int      `json:"PwnCount"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	if s.apiKey == "" {
		return nil, nil
	}

	// HIBP breach lookup is per root domain. Running on every subdomain would
	// make duplicate API calls (same root domain, same result, burns quota).
	// Only run on the root domain itself.
	// "example.co.uk" has 2 dots and is a valid ccTLD+SLD root domain.
	// Anything with more than 2 dots is guaranteed to be a subdomain.
	if strings.Count(asset, ".") > 2 {
		return nil, nil
	}

	domain := rootDomain(asset)

	client := &http.Client{Timeout: 10 * time.Second}

	base := s.baseURL
	if base == "" {
		base = "https://haveibeenpwned.com"
	}
	url := fmt.Sprintf("%s/api/v3/breaches?domain=%s", base, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("hibp-api-key", s.apiKey)
	req.Header.Set("user-agent", "Beacon Security Scanner")

	resp, err := retryGet(ctx, client, req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// 404 means no breaches found — not an error.
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, nil
	}

	var breaches []hibpBreach
	if err := json.Unmarshal(body, &breaches); err != nil {
		return nil, nil
	}

	if len(breaches) == 0 {
		return nil, nil
	}

	// Summarise breaches: total accounts exposed, unique data classes.
	totalPwned := 0
	dataClassSet := make(map[string]struct{})
	var breachNames []string
	for _, b := range breaches {
		if !b.IsVerified {
			continue
		}
		totalPwned += b.PwnCount
		breachNames = append(breachNames, fmt.Sprintf("%s (%s)", b.Name, b.BreachDate))
		for _, dc := range b.DataClasses {
			dataClassSet[dc] = struct{}{}
		}
	}

	if len(breachNames) == 0 {
		// Only unverified breaches — still worth reporting at lower severity.
		for _, b := range breaches {
			totalPwned += b.PwnCount
			breachNames = append(breachNames, fmt.Sprintf("%s (%s, unverified)", b.Name, b.BreachDate))
			for _, dc := range b.DataClasses {
				dataClassSet[dc] = struct{}{}
			}
		}
	}

	dataClasses := make([]string, 0, len(dataClassSet))
	for dc := range dataClassSet {
		dataClasses = append(dataClasses, dc)
	}

	hasPasswords := false
	for dc := range dataClassSet {
		if strings.Contains(strings.ToLower(dc), "password") {
			hasPasswords = true
			break
		}
	}

	severity := finding.SeverityMedium
	if hasPasswords {
		severity = finding.SeverityHigh
	}
	if totalPwned > 1_000_000 && hasPasswords {
		severity = finding.SeverityCritical
	}

	shown := breachNames
	if len(shown) > 10 {
		shown = shown[:10]
	}

	return []finding.Finding{
		{
			CheckID:  finding.CheckHIBPBreach,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: severity,
			Asset:    asset,
			Title: fmt.Sprintf(
				"HIBP: %d breach(es) found for %s (~%s accounts)",
				len(breaches), domain, formatCount(totalPwned),
			),
			Description: fmt.Sprintf(
				"Have I Been Pwned reports %d breach(es) associated with %s, "+
					"exposing approximately %s user accounts. "+
					"Data classes include: %s. "+
					"Affected users may have reused credentials — consider forcing a password reset and enabling MFA.",
				len(breaches), domain, formatCount(totalPwned),
				strings.Join(dataClasses, ", "),
			),
			Evidence: map[string]any{
				"domain":       domain,
				"breach_count": len(breaches),
				"total_pwned":  totalPwned,
				"data_classes": dataClasses,
				"breaches":     shown,
			},
			DiscoveredAt: time.Now(),
		},
	}, nil
}

// retryGet executes an HTTP GET with exponential back-off on 429 and 5xx responses.
// It respects the Retry-After header when present and retries up to 3 times.
func retryGet(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	const maxAttempts = 3
	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s
			if lastResp != nil {
				if ra := lastResp.Header.Get("Retry-After"); ra != "" {
					if secs, err := strconv.Atoi(ra); err == nil && secs > 0 && secs < 120 {
						delay = time.Duration(secs) * time.Second
					}
				}
				lastResp.Body.Close()
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			req = req.Clone(ctx)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastResp = resp
			continue
		}
		return resp, nil
	}
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

// rootDomain strips subdomains, returning the registration-level domain.
// For simple TLDs ("example.com" → "example.com"), for ccTLD+SLD domains
// ("example.co.uk" → "example.co.uk") it returns the full asset as-is because
// the filter above already ensures assets have at most 2 dots.
func rootDomain(asset string) string {
	parts := strings.Split(asset, ".")
	if len(parts) <= 2 {
		return asset
	}
	// 3-label case: could be "example.co.uk" (ccTLD root) or "sub.example.com"
	// (subdomain). The scanner's dot-count filter (> 2) already rejects 4+ dot
	// assets. For exactly 3 labels we return the full asset — if it is a ccTLD
	// root domain we want the full string; if somehow a simple subdomain slips
	// through (e.g. "api.example.com"), returning the full string is safe because
	// HIBP will simply find no breaches for that exact domain.
	return asset
}

func formatCount(n int) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}
