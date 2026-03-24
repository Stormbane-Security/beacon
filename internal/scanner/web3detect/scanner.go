// Package web3detect passively detects Web3/blockchain signals from page
// content and JavaScript bundles. It reads existing content without sending
// active probes or modifying requests beyond what a normal browser would do.
//
// Surface mode only.
package web3detect

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName  = "web3detect"
	maxBodySize  = 512 * 1024 // 512 KB per JS file
	maxJSFiles   = 3
	jsTimeout    = 5 * time.Second
)

// walletLibPatterns are substrings / regex tokens that indicate a wallet
// integration library is bundled on the page.
var walletLibPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bethers\b`),
	regexp.MustCompile(`\bviem\b`),
	regexp.MustCompile(`\bweb3\.js\b`),
	regexp.MustCompile(`\bwagmi\b`),
	regexp.MustCompile(`\bwalletconnect\b`),
	regexp.MustCompile(`@web3-react`),
	regexp.MustCompile(`@rainbow-me`),
	regexp.MustCompile(`window\.ethereum`),
}

// walletLibNames maps pattern index to a human-readable library name.
var walletLibNames = []string{
	"ethers",
	"viem",
	"web3.js",
	"wagmi",
	"walletconnect",
	"@web3-react",
	"@rainbow-me",
	"window.ethereum",
}

// evmAddressRe matches a 0x-prefixed 40-hex-character Ethereum address with
// word boundaries, to avoid matching partial hashes in comments.
var evmAddressRe = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)

// rpcEndpointRe matches well-known RPC provider hostnames.
var rpcEndpointRe = regexp.MustCompile(
	`https://[a-z0-9.\-]+(\.infura\.io|\.alchemyapi\.io|\.ankr\.com|\.quicknode\.io|\.alchemy\.com)[^\s"'<>]*`)

// wssEthRe matches WebSocket RPC endpoints that appear near Ethereum context.
var wssEthRe = regexp.MustCompile(`wss://[a-z0-9.\-]+\.[a-z]{2,}[^\s"'<>]*`)

// scriptSrcRe extracts JS file URLs from <script src="..."> tags.
var scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js[^"']*)["']`)

// Scanner passively detects Web3/blockchain signals.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the Web3 passive detection scan. Only runs in surface mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanSurface {
		return nil, nil
	}

	client := &http.Client{
		Timeout: jsTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	// Fetch the root page.
	htmlBody, err := fetchBody(ctx, client, base+"/", maxBodySize)
	if err != nil {
		return nil, nil
	}

	// Collect all content (HTML + JS files) for analysis.
	contents := []string{htmlBody}
	jsSrcs := extractJSSources(htmlBody, base)
	for i, src := range jsSrcs {
		if i >= maxJSFiles {
			break
		}
		js, err := fetchBody(ctx, client, src, maxBodySize)
		if err != nil {
			continue
		}
		contents = append(contents, js)
	}

	combined := strings.Join(contents, "\n")

	var findings []finding.Finding

	// --- Wallet library detection ---
	libs := detectWalletLibs(combined)
	if len(libs) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWeb3WalletLibDetected,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    "Web3 wallet library detected in page source",
			Description: "The application bundles one or more Web3 wallet integration " +
				"libraries. This confirms blockchain/DeFi functionality is present and " +
				"suggests the surface attack area includes wallet connection flows, " +
				"smart contract interactions, and transaction signing.",
			Asset: asset,
			Evidence: map[string]any{
				"libraries": libs,
				"url":       base + "/",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// --- RPC endpoint detection ---
	rpcURLs := detectRPCEndpoints(combined)
	if len(rpcURLs) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWeb3RPCEndpointExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    "Blockchain RPC endpoint URL exposed in page source",
			Description: "One or more RPC provider URLs (Infura, Alchemy, Ankr, etc.) " +
				"are hard-coded in publicly accessible JavaScript. Provider URLs often " +
				"contain API keys embedded in the path or subdomain. Exposure allows " +
				"key extraction, quota exhaustion, and potential billing abuse.",
			Asset: asset,
			Evidence: map[string]any{
				"rpc_urls": rpcURLs,
				"url":      base + "/",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// --- Contract address detection ---
	addrs := detectContractAddresses(combined)
	if len(addrs) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWeb3ContractFound,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    "Ethereum contract address(es) found in page source",
			Description: "One or more 0x-prefixed Ethereum addresses were found in the " +
				"page source or JavaScript bundles. These may be smart contract addresses " +
				"used by the application. Knowing the contract addresses enables on-chain " +
				"analysis of logic, funds, and permissions.",
			Asset: asset,
			Evidence: map[string]any{
				"addresses": addrs,
				"url":       base + "/",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// detectWalletLibs returns the names of wallet libraries found in content.
func detectWalletLibs(content string) []string {
	var found []string
	seen := map[string]bool{}
	for i, re := range walletLibPatterns {
		name := walletLibNames[i]
		if !seen[name] && re.MatchString(content) {
			found = append(found, name)
			seen[name] = true
		}
	}
	return found
}

// detectRPCEndpoints returns deduplicated RPC provider URLs found in content.
func detectRPCEndpoints(content string) []string {
	matches := rpcEndpointRe.FindAllString(content, -1)
	return deduplicate(matches)
}

// detectContractAddresses returns deduplicated EVM addresses found in content.
func detectContractAddresses(content string) []string {
	matches := evmAddressRe.FindAllString(content, -1)
	return deduplicate(matches)
}

// extractJSSources extracts JS file URLs from HTML, resolving relative paths.
func extractJSSources(html, base string) []string {
	matches := scriptSrcRe.FindAllStringSubmatch(html, -1)
	var srcs []string
	seen := map[string]bool{}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		src := m[1]
		if strings.HasPrefix(src, "//") {
			src = "https:" + src
		} else if strings.HasPrefix(src, "/") {
			src = base + src
		} else if !strings.HasPrefix(src, "http") {
			src = base + "/" + src
		}
		if !seen[src] {
			srcs = append(srcs, src)
			seen[src] = true
		}
	}
	return srcs
}

// fetchBody fetches a URL and returns the body capped at maxBytes.
func fetchBody(ctx context.Context, client *http.Client, rawURL string, maxBytes int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// deduplicate returns a slice with duplicate strings removed, preserving order.
func deduplicate(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "http"
	}
	resp.Body.Close()
	return "https"
}
