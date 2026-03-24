// Package whois performs domain registration lookups via the RDAP protocol.
// RDAP (Registration Data Access Protocol) is a REST/JSON replacement for
// WHOIS — no parsing fragile text, no rate limits, no API key required.
package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "whois"

// rdapResponse is the subset of RDAP domain response fields we care about.
type rdapResponse struct {
	LDHName    string `json:"ldhName"`    // domain name
	Status     []string `json:"status"`
	Events     []rdapEvent `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []rdapNameserver `json:"nameservers"`
}

type rdapEvent struct {
	EventAction string `json:"eventAction"` // "registration", "expiration", "last changed"
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles       []string `json:"roles"`
	VCardArray  []any    `json:"vcardArray"`
}

type rdapNameserver struct {
	LDHName string `json:"ldhName"`
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Only run WHOIS on the root domain, not subdomains
	// (subdomains share the same registration record).
	// "example.co.uk" has 2 dots and is a valid ccTLD+SLD root domain.
	// Anything with more than 2 dots is guaranteed to be a subdomain.
	if strings.Count(asset, ".") > 2 {
		return nil, nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://rdap.org/domain/%s", asset)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, nil
	}

	var rdap rdapResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		return nil, nil
	}

	var findings []finding.Finding
	now := time.Now()

	// Extract key dates
	var registeredAt, expiresAt, updatedAt time.Time
	for _, ev := range rdap.Events {
		t, err := time.Parse(time.RFC3339, ev.EventDate)
		if err != nil {
			continue
		}
		switch ev.EventAction {
		case "registration":
			registeredAt = t
		case "expiration":
			expiresAt = t
		case "last changed":
			updatedAt = t
		}
	}

	// Extract nameservers
	var nameservers []string
	for _, ns := range rdap.Nameservers {
		if ns.LDHName != "" {
			nameservers = append(nameservers, strings.ToLower(ns.LDHName))
		}
	}

	// Extract registrar name from entities
	registrar := ""
	for _, e := range rdap.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				registrar = extractVCardFN(e.VCardArray)
				break
			}
		}
	}

	// Domain expiry checks
	if !expiresAt.IsZero() {
		daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)

		if daysUntilExpiry <= 7 {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckWHOISDomainExpiry7d,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityCritical,
				Title:       fmt.Sprintf("Domain %s expires in %d days", asset, daysUntilExpiry),
				Description: fmt.Sprintf("The domain %s is registered until %s (%d days). If not renewed, the domain will expire and can be registered by anyone — including attackers who could serve malicious content.", asset, expiresAt.Format("Jan 2, 2006"), daysUntilExpiry),
				Asset:       asset,
				Evidence:    map[string]any{"expires_at": expiresAt.Format(time.RFC3339), "days_remaining": daysUntilExpiry},
				DiscoveredAt: now,
			})
		} else if daysUntilExpiry <= 30 {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckWHOISDomainExpiry30d,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Title:       fmt.Sprintf("Domain %s expires in %d days", asset, daysUntilExpiry),
				Description: fmt.Sprintf("The domain %s expires on %s. Renew it soon to prevent accidental expiry.", asset, expiresAt.Format("Jan 2, 2006")),
				Asset:       asset,
				Evidence:    map[string]any{"expires_at": expiresAt.Format(time.RFC3339), "days_remaining": daysUntilExpiry},
				DiscoveredAt: now,
			})
		}
	}

	// Informational domain registration record
	evidence := map[string]any{
		"registrar":    registrar,
		"nameservers":  nameservers,
		"status":       rdap.Status,
	}
	if !registeredAt.IsZero() {
		evidence["registered_at"] = registeredAt.Format(time.RFC3339)
	}
	if !expiresAt.IsZero() {
		evidence["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	if !updatedAt.IsZero() {
		evidence["updated_at"] = updatedAt.Format(time.RFC3339)
	}

	findings = append(findings, finding.Finding{
		CheckID:     finding.CheckWHOISDomainInfo,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("Domain registration info for %s", asset),
		Description: fmt.Sprintf("Registrar: %s. Nameservers: %s.", registrar, strings.Join(nameservers, ", ")),
		Asset:       asset,
		Evidence:    evidence,
		DiscoveredAt: now,
	})

	return findings, nil
}

// extractVCardFN pulls the FN (full name) field from a vCard array.
// RDAP encodes entity names as jCard (RFC 7095) — a JSON encoding of vCard.
func extractVCardFN(vcardArray []any) string {
	if len(vcardArray) < 2 {
		return ""
	}
	// vcardArray[1] is an array of property arrays: [name, params, type, value]
	props, ok := vcardArray[1].([]any)
	if !ok {
		return ""
	}
	for _, prop := range props {
		arr, ok := prop.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		if name, ok := arr[0].(string); ok && name == "fn" {
			if val, ok := arr[3].(string); ok {
				return val
			}
		}
	}
	return ""
}
