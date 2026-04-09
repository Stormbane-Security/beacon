// Package ctlog discovers subdomains by querying Certificate Transparency
// logs via crt.sh. This supplements passive DNS by finding certificates
// issued for subdomains that may not have DNS records yet (pre-production,
// internal services with public certs).
package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckCTLogSubdomain, finding.SeverityInfo, finding.ModeSurface),
	)
}

const scannerName = "ctlog"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

type crtEntry struct {
	NameValue string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	if scan.IsPrivateTarget(asset) {
		return nil, nil
	}
	// Only run on root domains to avoid duplicate queries.
	if strings.Count(asset, ".") > 1 {
		return nil, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB limit
	if err != nil {
		return nil, nil
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil
	}

	// Deduplicate subdomains.
	seen := map[string]bool{}
	var subdomains []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == asset || seen[name] {
				continue
			}
			if !strings.HasSuffix(name, "."+asset) {
				continue
			}
			seen[name] = true
			subdomains = append(subdomains, name)
		}
	}

	if len(subdomains) == 0 {
		return nil, nil
	}

	// Cap at 500 to avoid massive findings.
	if len(subdomains) > 500 {
		subdomains = subdomains[:500]
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCTLogSubdomain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("CT logs reveal %d subdomain(s) for %s", len(subdomains), asset),
		Description: fmt.Sprintf(
			"Certificate Transparency logs contain %d unique subdomain(s) for %s. "+
				"These include subdomains from certificates that may be pre-production, "+
				"internal services, or no longer active.",
			len(subdomains), asset,
		),
		Evidence: map[string]any{
			"subdomains":    subdomains,
			"total_certs":   len(entries),
			"source":        "crt.sh",
		},
		ProofCommand: fmt.Sprintf("curl -s 'https://crt.sh/?q=%%25.%s&output=json' | jq '.[].name_value' | sort -u", asset),
		DiscoveredAt: time.Now(),
	}}, nil
}
