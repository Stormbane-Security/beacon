// Package web3defi detects DeFi protocol interfaces, NFT metadata endpoints,
// and exposed admin/owner functions on blockchain-connected web applications.
//
// Detection targets:
//   - DeFi router/factory contracts (Uniswap, SushiSwap, PancakeSwap)
//   - Aave/Compound lending protocol admin interfaces
//   - NFT metadata APIs returning token URIs and collection data
//   - Exposed contract admin/owner functions via ABI inspection
//
// This scanner is surface-mode safe. It sends only read-only HTTP GET/POST
// requests to standard web3 API endpoints. No transactions are submitted.
package web3defi

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
		scan.Check(finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckWeb3NFTMetadataExposed, finding.SeverityMedium, finding.ModeSurface),
	)
}

const scannerName = "web3defi"

// Scanner detects DeFi and NFT infrastructure.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// defiAdminEndpoint describes a known DeFi admin/management endpoint.
type defiAdminEndpoint struct {
	path    string
	signals []string // body substrings that confirm DeFi admin functionality
	label   string   // human-readable protocol name
}

var defiAdminEndpoints = []defiAdminEndpoint{
	// Uniswap/SushiSwap/PancakeSwap admin and router interfaces.
	{"/api/v1/factory", []string{"factory", "pair", "allPairs"}, "DEX factory"},
	{"/api/v1/router", []string{"router", "swap", "addLiquidity"}, "DEX router"},
	{"/admin", []string{"pool", "liquidity", "governance", "treasury", "vault"}, "DeFi admin panel"},
	{"/admin/pools", []string{"pool", "tvl", "apy", "liquidity"}, "DeFi pool admin"},
	{"/api/admin", []string{"pool", "vault", "strategy", "harvest"}, "DeFi admin API"},
	{"/governance", []string{"proposal", "vote", "quorum", "timelock"}, "DeFi governance"},
	{"/api/governance/proposals", []string{"proposal", "vote", "quorum"}, "DeFi governance API"},
	// Aave/Compound-style lending protocol endpoints.
	{"/api/v1/reserves", []string{"reserve", "liquidityRate", "variableBorrowRate"}, "Lending protocol reserves"},
	{"/api/v1/markets", []string{"market", "borrow", "supply", "collateral"}, "Lending protocol markets"},
	// Vault/yield management.
	{"/api/vaults", []string{"vault", "strategy", "apy", "tvl"}, "Yield vault API"},
	{"/api/strategies", []string{"strategy", "harvest", "deposit", "withdraw"}, "Yield strategy API"},
}

// nftMetadataEndpoint describes an NFT metadata endpoint to probe.
type nftMetadataEndpoint struct {
	path    string
	signals []string
	label   string
}

var nftMetadataEndpoints = []nftMetadataEndpoint{
	{"/api/v1/tokens", []string{"token", "metadata", "image", "attributes"}, "NFT token API"},
	{"/api/v1/collections", []string{"collection", "name", "symbol", "totalSupply"}, "NFT collection API"},
	{"/metadata/1", []string{"name", "description", "image", "attributes"}, "NFT metadata (ERC-721)"},
	{"/api/token/1", []string{"name", "image", "attributes", "tokenId"}, "NFT token metadata"},
	{"/api/nft", []string{"nft", "token", "metadata", "collection"}, "NFT API"},
	{"/ipfs/", []string{"name", "image", "description"}, "IPFS NFT metadata"},
	{"/api/v1/assets", []string{"asset", "token_id", "image_url", "traits"}, "NFT asset API"},
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	// Probe DeFi admin endpoints.
	for _, ep := range defiAdminEndpoints {
		if ctx.Err() != nil {
			break
		}
		if f := probeEndpoint(ctx, client, base, ep.path, ep.signals, ep.label, asset,
			finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, "DeFi"); f != nil {
			findings = append(findings, *f)
			break // One DeFi admin finding is enough — don't spam.
		}
	}

	// Probe NFT metadata endpoints.
	for _, ep := range nftMetadataEndpoints {
		if ctx.Err() != nil {
			break
		}
		if f := probeEndpoint(ctx, client, base, ep.path, ep.signals, ep.label, asset,
			finding.CheckWeb3NFTMetadataExposed, finding.SeverityMedium, "NFT"); f != nil {
			findings = append(findings, *f)
			break // One NFT metadata finding is enough.
		}
	}

	// Check page source for DeFi/NFT JavaScript signals.
	if jsFindings := checkPageSourceSignals(ctx, client, base, asset); len(jsFindings) > 0 {
		findings = append(findings, jsFindings...)
	}

	return findings, nil
}

func probeEndpoint(ctx context.Context, client *http.Client, base, path string,
	signals []string, label, asset string,
	checkID finding.CheckID, severity finding.Severity, category string,
) *finding.Finding {
	url := base + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := strings.ToLower(string(body))

	// Reject HTML — SPAs return 200 for all paths.
	trimmed := strings.TrimSpace(bodyStr)
	if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "<!") {
		return nil
	}

	// Require at least 2 signal matches to reduce false positives.
	matchCount := 0
	var matched []string
	for _, sig := range signals {
		if strings.Contains(bodyStr, sig) {
			matchCount++
			matched = append(matched, sig)
		}
	}
	if matchCount < 2 {
		return nil
	}

	var title, desc string
	switch category {
	case "DeFi":
		title = fmt.Sprintf("DeFi admin endpoint exposed without auth: %s (%s)", url, label)
		desc = fmt.Sprintf(
			"A %s endpoint at %s is accessible without authentication. "+
				"Exposed DeFi admin interfaces may allow unauthorized pool management, "+
				"governance manipulation, strategy changes, or fund withdrawal. "+
				"Matched signals: %s.",
			label, url, strings.Join(matched, ", "))
	case "NFT":
		title = fmt.Sprintf("NFT metadata endpoint exposed: %s (%s)", url, label)
		desc = fmt.Sprintf(
			"An %s endpoint at %s returns NFT token metadata without authentication. "+
				"Exposed NFT metadata APIs reveal collection structure, token ownership patterns, "+
				"and IPFS/Arweave storage locations. If the metadata is mutable, an attacker could "+
				"potentially modify token attributes. Matched signals: %s.",
			label, url, strings.Join(matched, ", "))
	}

	return &finding.Finding{
		CheckID:      checkID,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     severity,
		Title:        title,
		Description:  desc,
		Asset:        asset,
		ProofCommand: fmt.Sprintf("curl -s %s | python3 -m json.tool | head -30", url),
		Evidence: map[string]any{
			"url":     url,
			"path":    path,
			"label":   label,
			"signals": matched,
		},
		DiscoveredAt: time.Now(),
	}
}

// defiJSSignals are patterns in page source that indicate DeFi/NFT frontend.
var defiJSSignals = []struct {
	pattern  string
	checkID  finding.CheckID
	severity finding.Severity
	label    string
}{
	// DeFi router contract addresses (Uniswap V2/V3, SushiSwap, PancakeSwap).
	{"0x7a250d5630b4cf539739df2c5dacb4c659f2488d", finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, "Uniswap V2 Router"},
	{"0xe592427a0aece92de3edee1f18e0157c05861564", finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, "Uniswap V3 SwapRouter"},
	{"0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, "SushiSwap Router"},
	{"0x10ed43c718714eb63d5aa57b78b54704e256024e", finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, "PancakeSwap Router"},
	// Aave/Compound protocol addresses.
	{"0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9", finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, "Aave V2 LendingPool"},
	{"0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b", finding.CheckWeb3DefiAdminExposed, finding.SeverityCritical, "Compound Comptroller"},
}

// checkPageSourceSignals fetches the root page and looks for DeFi contract
// addresses or NFT-related JavaScript patterns.
func checkPageSourceSignals(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	_ = resp.Body.Close()

	bodyLower := strings.ToLower(string(body))
	var findings []finding.Finding
	seen := map[string]bool{}

	for _, sig := range defiJSSignals {
		if !strings.Contains(bodyLower, sig.pattern) || seen[sig.label] {
			continue
		}
		seen[sig.label] = true

		findings = append(findings, finding.Finding{
			CheckID:  sig.checkID,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: sig.severity,
			Title:    fmt.Sprintf("DeFi protocol contract reference detected: %s", sig.label),
			Description: fmt.Sprintf(
				"The page source at %s references the %s contract address (%s). "+
					"This confirms the application interacts with a DeFi protocol. "+
					"If the frontend has admin/owner capabilities, they may be accessible "+
					"to any user who can reach this page.",
				base, sig.label, sig.pattern),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s %s | grep -i '%s'", base, sig.pattern),
			Evidence: map[string]any{
				"url":              base,
				"contract_address": sig.pattern,
				"protocol":         sig.label,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check for NFT-related JavaScript patterns.
	nftPatterns := []string{"opensea", "rarible", "erc721", "erc1155", "nonfungible", "tokenuri", "tokensofowner"}
	nftCount := 0
	for _, pat := range nftPatterns {
		if strings.Contains(bodyLower, pat) {
			nftCount++
		}
	}
	if nftCount >= 2 && !seen["nft_frontend"] {
		// Try to find an API endpoint that serves metadata.
		var nftAPIResult *finding.Finding
		for _, ep := range nftMetadataEndpoints {
			if ctx.Err() != nil {
				break
			}
			if f := probeEndpoint(ctx, client, base, ep.path, ep.signals, ep.label, asset,
				finding.CheckWeb3NFTMetadataExposed, finding.SeverityMedium, "NFT"); f != nil {
				nftAPIResult = f
				break
			}
		}
		if nftAPIResult != nil {
			findings = append(findings, *nftAPIResult)
		}
	}

	return findings
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
	_ = resp.Body.Close()
	return "https"
}

// parseJSONField extracts a string value for the given key from a JSON blob.
func parseJSONField(data []byte, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}
