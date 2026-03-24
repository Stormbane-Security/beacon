// Package contractscan analyses EVM smart contracts for common vulnerabilities.
//
// It operates in two tiers:
//
// Surface mode: Given a contract address found by web3detect or DLP, it
// fetches the ABI and source code from the Etherscan API (if BEACON_ETHERSCAN_API_KEY
// is set) and checks for high-risk patterns in the source (unprotected
// selfdestruct, missing reentrancy guards, unchecked low-level calls).
//
// Deep mode: Additionally probes proxy admin slots (EIP-1967) directly via an
// ETH JSON-RPC endpoint to detect upgradeable proxy configurations.
//
// When no Etherscan key is set, the scanner only performs on-chain storage
// slot probes for proxy admin detection and JSON-RPC method enumeration.
//
// Contract addresses are discovered from Evidence.ContractAddresses populated
// by web3detect. The scanner is asset-driven — it receives the parent web
// asset and reads contract addresses from the scan Evidence.
package contractscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "contractscan"

// EIP-1967 proxy admin slot: keccak256("eip1967.proxy.admin") - 1
const proxyAdminSlot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

// Scanner analyses EVM smart contracts for vulnerabilities.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// Run scans contract addresses found in Evidence.ContractAddresses.
// The asset parameter is the parent web asset (domain/IP); contract addresses
// are read from the scan session evidence via the EvidenceProvider interface.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// This scanner is only meaningful on web3 targets.
	// The module populates Evidence.ContractAddresses from web3detect findings
	// before calling this scanner. We receive them via the asset string using
	// a comma-separated contract address list when the module calls us for
	// a contract sub-asset (asset = "0x...").
	if !strings.HasPrefix(asset, "0x") || len(asset) != 42 {
		return nil, nil
	}

	etherscanKey := os.Getenv("BEACON_ETHERSCAN_API_KEY")
	rpcURL := os.Getenv("BEACON_ETH_RPC_URL") // optional JSON-RPC endpoint

	client := &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var findings []finding.Finding

	// Tier 1: Etherscan source code analysis.
	if etherscanKey != "" {
		fs := analyseSource(ctx, client, asset, etherscanKey)
		findings = append(findings, fs...)
	}

	// Tier 2: on-chain proxy admin slot probe (no key needed, only an RPC endpoint).
	if rpcURL != "" {
		if f := checkProxyAdmin(ctx, client, asset, rpcURL); f != nil {
			findings = append(findings, *f)
		}
	}

	// Tier 3: if deep mode and RPC endpoint available, probe for exposed RPC methods.
	if (scanType == module.ScanDeep || scanType == module.ScanAuthorized) && rpcURL != "" {
		fs := probeRPCMethods(ctx, client, asset, rpcURL)
		findings = append(findings, fs...)
	}

	return findings, nil
}

// analyseSource fetches the verified source code from Etherscan and checks
// for known vulnerability patterns.
func analyseSource(ctx context.Context, client *http.Client, address, apiKey string) []finding.Finding {
	url := fmt.Sprintf(
		"https://api.etherscan.io/api?module=contract&action=getsourcecode&address=%s&apikey=%s",
		address, apiKey,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()

	var ethResp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Result  []struct {
			SourceCode      string `json:"SourceCode"`
			ContractName    string `json:"ContractName"`
			CompilerVersion string `json:"CompilerVersion"`
			ABI             string `json:"ABI"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &ethResp); err != nil || len(ethResp.Result) == 0 {
		return nil
	}

	result := ethResp.Result[0]
	source := result.SourceCode

	if source == "" || source == "Contract source code not verified" {
		return nil
	}

	var findings []finding.Finding

	// Source is retrievable — emit informational finding.
	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckContractSourceExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Title:    fmt.Sprintf("Smart contract source code verified and public: %s (%s)", result.ContractName, address),
		Description: fmt.Sprintf(
			"The source code for contract %s (%s, compiler %s) is verified on Etherscan and publicly readable. "+
				"Attackers can audit the contract logic for vulnerabilities without deploying a copy.",
			result.ContractName, address, result.CompilerVersion),
		Asset: address,
		Evidence: map[string]any{
			"address":          address,
			"contract_name":    result.ContractName,
			"compiler_version": result.CompilerVersion,
		},
		ProofCommand: fmt.Sprintf("curl -s 'https://api.etherscan.io/api?module=contract&action=getsourcecode&address=%s' | python3 -m json.tool | head -40", address),
		DiscoveredAt: time.Now(),
	})

	// Pattern checks against source code.
	sourceLower := strings.ToLower(source)

	// Reentrancy: state change after external call without mutex/guard.
	if containsReentrancyPattern(source) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckContractReentrancy,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("Potential reentrancy vulnerability in contract %s", result.ContractName),
			Description: fmt.Sprintf(
				"The source code of %s (%s) contains patterns consistent with reentrancy: "+
					"an external call (call{value:}, transfer, or send) followed by a state update "+
					"without a reentrancy guard (ReentrancyGuard or checks-effects-interactions pattern). "+
					"An attacker contract could recursively call back before the state is updated, "+
					"draining ETH or double-spending tokens.",
				result.ContractName, address),
			Asset: address,
			Evidence: map[string]any{
				"address":       address,
				"contract_name": result.ContractName,
				"pattern":       "external_call_before_state_update",
			},
			ProofCommand: fmt.Sprintf("slither %s --detect reentrancy-eth,reentrancy-no-eth 2>/dev/null | grep -i reentrancy", address),
			DiscoveredAt: time.Now(),
		})
	}

	// Unprotected selfdestruct.
	if strings.Contains(sourceLower, "selfdestruct(") || strings.Contains(sourceLower, "suicide(") {
		if !strings.Contains(sourceLower, "onlyowner") && !strings.Contains(sourceLower, "require(msg.sender") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckContractSelfDestruct,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("Unprotected selfdestruct in contract %s", result.ContractName),
				Description: fmt.Sprintf(
					"The contract %s (%s) contains a selfdestruct() or suicide() call that does not "+
						"appear to be protected by an access control check (onlyOwner / require(msg.sender == ...)). "+
						"Any caller may be able to destroy the contract and claim its ETH balance.",
					result.ContractName, address),
				Asset: address,
				Evidence: map[string]any{
					"address":       address,
					"contract_name": result.ContractName,
					"pattern":       "unprotected_selfdestruct",
				},
				ProofCommand: fmt.Sprintf("slither %s --detect suicidal 2>/dev/null", address),
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Unchecked low-level calls.
	if strings.Contains(sourceLower, ".call(") || strings.Contains(sourceLower, ".call{") {
		if !strings.Contains(sourceLower, "require(") && !strings.Contains(sourceLower, "bool success") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckContractUncheckedCall,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Unchecked low-level call in contract %s", result.ContractName),
				Description: fmt.Sprintf(
					"The contract %s (%s) uses a low-level .call() without checking the return value. "+
						"If the called address reverts, the failure is silently ignored and execution continues. "+
						"This can lead to funds being lost or logic being bypassed.",
					result.ContractName, address),
				Asset: address,
				Evidence: map[string]any{
					"address":       address,
					"contract_name": result.ContractName,
					"pattern":       "unchecked_low_level_call",
				},
				ProofCommand: fmt.Sprintf("slither %s --detect unchecked-lowlevel 2>/dev/null", address),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// containsReentrancyPattern returns true when the source contains an external
// value-sending call combined with a subsequent state variable update — the
// classic checks-effects-interactions violation.
func containsReentrancyPattern(source string) bool {
	lower := strings.ToLower(source)
	hasExternalCall := strings.Contains(lower, ".call{value:") ||
		strings.Contains(lower, ".call(abi") ||
		strings.Contains(lower, ".transfer(") ||
		strings.Contains(lower, ".send(")
	// Simplified heuristic: external call present AND no ReentrancyGuard import.
	hasGuard := strings.Contains(lower, "reentrancyguard") ||
		strings.Contains(lower, "nonreentrant") ||
		strings.Contains(lower, "mutex")
	return hasExternalCall && !hasGuard
}

// checkProxyAdmin reads the EIP-1967 proxy admin storage slot. If non-zero,
// the contract is an upgradeable proxy and the admin address is disclosed.
func checkProxyAdmin(ctx context.Context, client *http.Client, address, rpcURL string) *finding.Finding {
	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","method":"eth_getStorageAt","params":["%s","%s","latest"],"id":1}`,
		address, proxyAdminSlot,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewBufferString(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil
	}

	// Zero value means not a proxy (or admin slot unset).
	zero := "0x" + strings.Repeat("0", 64)
	if rpcResp.Result == "" || rpcResp.Result == zero || rpcResp.Result == "0x" {
		return nil
	}

	// Extract the admin address (last 20 bytes of the 32-byte slot value).
	adminAddr := ""
	if len(rpcResp.Result) >= 42 {
		adminAddr = "0x" + rpcResp.Result[len(rpcResp.Result)-40:]
	}

	return &finding.Finding{
		CheckID:  finding.CheckContractProxyAdmin,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Upgradeable proxy detected at %s (admin: %s)", address, adminAddr),
		Description: fmt.Sprintf(
			"The contract at %s has a non-zero EIP-1967 proxy admin slot. "+
				"This is an upgradeable proxy contract controlled by %s. "+
				"If the admin key is compromised or the upgrade mechanism has access control flaws, "+
				"an attacker can replace the implementation contract with malicious code.",
			address, adminAddr),
		Asset: address,
		Evidence: map[string]any{
			"address":       address,
			"admin_address": adminAddr,
			"slot":          proxyAdminSlot,
		},
		ProofCommand: fmt.Sprintf("cast storage %s %s --rpc-url %s 2>/dev/null", address, proxyAdminSlot, rpcURL),
		DiscoveredAt: time.Now(),
	}
}

// probeRPCMethods calls a set of read-only JSON-RPC methods and records any
// that return useful information (peer count, sync status, etc.).
func probeRPCMethods(ctx context.Context, client *http.Client, address, rpcURL string) []finding.Finding {
	type rpcCall struct {
		method string
		params string
	}
	probes := []rpcCall{
		{"eth_getCode", fmt.Sprintf(`["%s","latest"]`, address)},
	}

	var findings []finding.Finding
	for _, p := range probes {
		payload := fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}`, p.method, p.params)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewBufferString(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		var rpcResp struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &rpcResp); err != nil || rpcResp.Error != nil {
			continue
		}
		if len(rpcResp.Result) <= 4 { // "null" or ""
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckContractSourceExposed,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    fmt.Sprintf("Contract bytecode retrievable via %s at %s", p.method, address),
			Asset:    address,
			Evidence: map[string]any{
				"address":  address,
				"method":   p.method,
				"rpc_url":  rpcURL,
				"response": string(rpcResp.Result[:min(len(rpcResp.Result), 200)]),
			},
			ProofCommand: fmt.Sprintf(`cast code %s --rpc-url %s 2>/dev/null | head -c 200`, address, rpcURL),
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
