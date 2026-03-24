// Package chainnode detects blockchain nodes, validators, and miners exposed
// on the network. It probes common JSON-RPC ports and beacon node APIs to
// identify Ethereum full nodes, validators, PoW miners, and other chain
// infrastructure (Bitcoin, Solana).
//
// Exposed blockchain nodes are high-severity findings because they:
//   - Reveal peer topology (net_peerCount, admin_peers)
//   - Leak wallet addresses and transaction history (eth_accounts, eth_coinbase)
//   - Allow state-changing calls if auth is absent (eth_sendTransaction,
//     personal_unlockAccount, miner_start)
//   - Expose validator keys and withdrawal credentials if beacon APIs are open
//
// Detection matrix:
//
//	Port  | Protocol   | Chain        | What to probe
//	------|-----------|--------------|---------------------------
//	8545  | HTTP RPC  | Ethereum     | eth_chainId, net_peerCount
//	8546  | WS RPC    | Ethereum     | Upgrade: websocket header
//	8551  | Auth RPC  | Ethereum     | JWT-protected engine API
//	30303 | P2P TCP   | Ethereum     | TCP connect only
//	9000  | HTTP      | ETH2 Beacon  | /eth/v1/node/syncing
//	5052  | HTTP      | ETH2 Beacon  | /eth/v1/node/syncing
//	4000  | HTTP      | Prysm        | /eth/v1/node/syncing
//	8332  | HTTP RPC  | Bitcoin      | getblockchaininfo
//	8899  | HTTP RPC  | Solana       | getHealth
//	8900  | WS        | Solana       | TCP connect
//	26657 | HTTP RPC  | Cosmos/Tendermint | /status
//	26660 | Metrics   | Cosmos       | /metrics
//	9615  | Metrics   | ETH2 Prysm   | /metrics
package chainnode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "chainnode"

const dialTimeout = 3 * time.Second
const httpTimeout = 8 * time.Second

// nodePort describes a port to probe and how to interpret a response.
type nodePort struct {
	port     string
	scheme   string // "http" | "ws" | "tcp"
	chain    string
	nodeType string // "full_node", "validator", "miner", "rpc"
	probe    func(ctx context.Context, client *http.Client, base string) *probeResult
}

type probeResult struct {
	open        bool
	chainID     string
	nodeVersion string
	syncing     bool
	peerCount   int
	isMining    bool
	isValidator bool
	extraInfo   map[string]any
}

// Scanner detects blockchain nodes and validators.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Strip port from asset if present — we probe our own ports.
	host := asset
	if h, _, err := net.SplitHostPort(asset); err == nil {
		host = h
	}

	client := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var findings []finding.Finding

	// Ethereum JSON-RPC (port 8545)
	if f := probeEthRPC(ctx, client, host, "8545"); len(f) > 0 {
		findings = append(findings, f...)
	}

	// Ethereum WebSocket RPC (port 8546)
	if isPortOpen(ctx, host, "8546") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckChainNodeWSExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Ethereum WebSocket JSON-RPC exposed on %s:8546", host),
			Description: "Port 8546 (Ethereum WebSocket RPC) is open and accessible. " +
				"WebSocket RPC enables real-time subscription to events and full JSON-RPC access. " +
				"Without authentication, attackers can subscribe to mempool transactions, read wallet state, " +
				"and in some configurations send transactions.",
			Asset: asset,
			Evidence: map[string]any{"host": host, "port": "8546", "chain": "ethereum"},
			ProofCommand: fmt.Sprintf("wscat -c ws://%s:8546 -x '{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}' 2>/dev/null", host),
			DiscoveredAt: time.Now(),
		})
	}

	// ETH2 Beacon Node APIs (ports 9000, 5052, 4000 — Lighthouse / Teku / Prysm)
	for _, port := range []string{"9000", "5052", "4000"} {
		if f := probeBeaconNode(ctx, client, host, port, asset); f != nil {
			findings = append(findings, *f)
		}
	}

	// Prysm / Lighthouse metrics (port 9615)
	if f := probeMetrics(ctx, client, host, "9615", "ETH2 beacon node", asset); f != nil {
		findings = append(findings, *f)
	}

	// Bitcoin JSON-RPC (port 8332)
	if f := probeBitcoinRPC(ctx, client, host, asset); f != nil {
		findings = append(findings, *f)
	}

	// Solana JSON-RPC (port 8899)
	if f := probeSolanaRPC(ctx, client, host, asset); f != nil {
		findings = append(findings, *f)
	}

	// Cosmos/Tendermint RPC (port 26657)
	if f := probeCosmosRPC(ctx, client, host, asset); f != nil {
		findings = append(findings, *f)
	}

	// Cosmos metrics (port 26660)
	if f := probeMetrics(ctx, client, host, "26660", "Cosmos/Tendermint node", asset); f != nil {
		findings = append(findings, *f)
	}

	// Deep mode: enumerate sensitive RPC methods.
	if (scanType == module.ScanDeep || scanType == module.ScanAuthorized) && len(findings) > 0 {
		if f := probeEthSensitiveMethods(ctx, client, host, asset); len(f) > 0 {
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// probeEthRPC calls eth_chainId and net_peerCount on the given port.
func probeEthRPC(ctx context.Context, client *http.Client, host, port string) []finding.Finding {
	base := fmt.Sprintf("http://%s:%s", host, port)
	payload := `{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, bytes.NewBufferString(payload))
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
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil || rpcResp.Error != nil {
		return nil
	}
	if rpcResp.Result == "" {
		return nil
	}

	chainID := rpcResp.Result
	chainName := resolveChainID(chainID)

	var findings []finding.Finding
	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckChainNodeRPCExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Ethereum JSON-RPC exposed on %s:%s (chain: %s)", host, port, chainName),
		Description: fmt.Sprintf(
			"Port %s is running an Ethereum JSON-RPC server responding to eth_chainId (%s = %s). "+
				"An unauthenticated JSON-RPC port exposes wallet state, transaction history, peer topology, "+
				"and in some configurations allows sending transactions or unlocking accounts. "+
				"This should be firewalled and never exposed to the internet.",
			port, chainID, chainName),
		Asset: host,
		Evidence: map[string]any{
			"host":     host,
			"port":     port,
			"chain_id": chainID,
			"chain":    chainName,
		},
		ProofCommand: fmt.Sprintf(`curl -s -X POST http://%s:%s -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'`, host, port),
		DiscoveredAt: time.Now(),
	})

	// Also get peer count.
	if peerCount := getEthPeerCount(ctx, client, base); peerCount >= 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckChainNodePeerCountLeak,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("Ethereum node peer count leaked on %s:%s (%d peers)", host, port, peerCount),
			Description: fmt.Sprintf(
				"net_peerCount returned %d on the exposed JSON-RPC endpoint. "+
					"Peer count and peer addresses reveal network topology and can be used to "+
					"target eclipse attacks against the node.",
				peerCount),
			Asset: host,
			Evidence: map[string]any{
				"host":       host,
				"port":       port,
				"peer_count": peerCount,
			},
			ProofCommand: fmt.Sprintf(`curl -s -X POST http://%s:%s -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'`, host, port),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

func getEthPeerCount(ctx context.Context, client *http.Client, base string) int {
	payload := `{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, bytes.NewBufferString(payload))
	if err != nil {
		return -1
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	resp.Body.Close()

	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil || rpcResp.Result == "" {
		return -1
	}
	var count int
	fmt.Sscanf(rpcResp.Result, "0x%x", &count)
	return count
}

// probeEthSensitiveMethods checks for eth_mining, eth_coinbase, eth_accounts.
func probeEthSensitiveMethods(ctx context.Context, client *http.Client, host, asset string) []finding.Finding {
	base := fmt.Sprintf("http://%s:8545", host)
	var findings []finding.Finding

	// eth_mining — reveals active PoW miner.
	miningPayload := `{"jsonrpc":"2.0","method":"eth_mining","params":[],"id":1}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, bytes.NewBufferString(miningPayload))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			var rpc struct{ Result bool `json:"result"` }
			if json.Unmarshal(body, &rpc) == nil && rpc.Result {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckChainNodeMinerExposed,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("Active PoW miner detected via eth_mining on %s", host),
					Description: "eth_mining returned true, indicating this node is actively mining. " +
						"The miner's coinbase address is discoverable via eth_coinbase, " +
						"and unprotected miner_* RPC methods may allow an attacker to stop mining " +
						"or redirect block rewards.",
					Asset: asset,
					Evidence: map[string]any{"host": host, "method": "eth_mining", "result": true},
					ProofCommand: fmt.Sprintf(`curl -s -X POST http://%s:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_coinbase","params":[],"id":1}'`, host),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// eth_accounts — reveals unlocked wallet addresses on the node.
	accountsPayload := `{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}`
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, base, bytes.NewBufferString(accountsPayload))
	if err == nil {
		req2.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req2); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			var rpc struct {
				Result []string `json:"result"`
			}
			if json.Unmarshal(body, &rpc) == nil && len(rpc.Result) > 0 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckChainNodeUnauthorized,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("Ethereum node exposes %d unlocked account(s) via eth_accounts on %s", len(rpc.Result), host),
					Description: fmt.Sprintf(
						"eth_accounts returned %d wallet address(es) from the keystore. "+
							"If personal_unlockAccount is also available, an attacker may be able to "+
							"sign and broadcast transactions from these addresses without knowing the passphrase.",
						len(rpc.Result)),
					Asset: asset,
					Evidence: map[string]any{
						"host":     host,
						"accounts": rpc.Result,
					},
					ProofCommand: fmt.Sprintf(`curl -s -X POST http://%s:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}'`, host),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}

// probeBeaconNode probes ETH2 beacon node REST APIs.
func probeBeaconNode(ctx context.Context, client *http.Client, host, port, asset string) *finding.Finding {
	url := fmt.Sprintf("http://%s:%s/eth/v1/node/syncing", host, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if !bytes.Contains(body, []byte("head_slot")) && !bytes.Contains(body, []byte("is_syncing")) {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckChainNodeValidatorExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("ETH2 beacon node REST API exposed on %s:%s", host, port),
		Description: fmt.Sprintf(
			"The Ethereum 2.0 beacon node REST API (/eth/v1/node/syncing) is responding on port %s. "+
				"This API exposes validator indices, withdrawal credentials, sync committee participation, "+
				"and peer topology. On Prysm/Lighthouse/Teku nodes without keymanager auth, "+
				"the /eth/v1/keystores endpoint may allow reading or deleting validator keys.",
			port),
		Asset: asset,
		Evidence: map[string]any{
			"host":     host,
			"port":     port,
			"endpoint": "/eth/v1/node/syncing",
			"response": string(body[:min(len(body), 300)]),
		},
		ProofCommand: fmt.Sprintf("curl -s http://%s:%s/eth/v1/node/syncing | python3 -m json.tool", host, port),
		DiscoveredAt: time.Now(),
	}
}

// probeBitcoinRPC probes port 8332 for a Bitcoin node.
func probeBitcoinRPC(ctx context.Context, client *http.Client, host, asset string) *finding.Finding {
	url := fmt.Sprintf("http://%s:8332", host)
	payload := `{"jsonrpc":"1.0","method":"getblockchaininfo","params":[],"id":1}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(payload))
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

	// Bitcoin RPC returns 401 without credentials — that still confirms the port is a BTC node.
	if resp.StatusCode == http.StatusUnauthorized {
		return &finding.Finding{
			CheckID:  finding.CheckChainNodeRPCExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Bitcoin JSON-RPC port exposed on %s:8332 (auth required)", host),
			Description: "Port 8332 is running a Bitcoin node that requires HTTP Basic Auth. " +
				"The port is publicly reachable and susceptible to credential brute-force. " +
				"Bitcoin RPC should only be accessible from localhost or a trusted management network.",
			Asset: asset,
			Evidence: map[string]any{"host": host, "port": "8332", "chain": "bitcoin", "auth_required": true},
			ProofCommand: fmt.Sprintf(`curl -s -u user:password -X POST http://%s:8332 -H 'Content-Type: application/json' -d '{"method":"getblockchaininfo","params":[],"id":1}'`, host),
			DiscoveredAt: time.Now(),
		}
	}

	if !bytes.Contains(body, []byte("chain")) && !bytes.Contains(body, []byte("blocks")) {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckChainNodeUnauthorized,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Bitcoin JSON-RPC exposed WITHOUT authentication on %s:8332", host),
		Description: "The Bitcoin node on port 8332 accepted a JSON-RPC call without credentials. " +
			"An unauthenticated Bitcoin RPC server allows an attacker to read wallet balances, " +
			"list UTXOs, import arbitrary addresses, and potentially send transactions.",
		Asset: asset,
		Evidence: map[string]any{
			"host":     host,
			"port":     "8332",
			"chain":    "bitcoin",
			"response": string(body[:min(len(body), 300)]),
		},
		ProofCommand: fmt.Sprintf(`curl -s -X POST http://%s:8332 -H 'Content-Type: application/json' -d '{"method":"getblockchaininfo","params":[],"id":1}'`, host),
		DiscoveredAt: time.Now(),
	}
}

// probeSolanaRPC probes port 8899 for a Solana node.
func probeSolanaRPC(ctx context.Context, client *http.Client, host, asset string) *finding.Finding {
	url := fmt.Sprintf("http://%s:8899", host)
	payload := `{"jsonrpc":"2.0","method":"getHealth","params":[],"id":1}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(payload))
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

	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if !bytes.Contains(body, []byte("ok")) && !bytes.Contains(body, []byte("result")) {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckChainNodeRPCExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Solana JSON-RPC exposed on %s:8899", host),
		Description: "Port 8899 is running a Solana JSON-RPC server. " +
			"Solana RPC exposes validator identity, stake accounts, token balances, " +
			"and vote account information. If the validator identity keypair is on the same host, " +
			"compromise of the node can lead to slashing and loss of staked SOL.",
		Asset: asset,
		Evidence: map[string]any{
			"host":     host,
			"port":     "8899",
			"chain":    "solana",
			"response": string(body[:min(len(body), 300)]),
		},
		ProofCommand: fmt.Sprintf(`curl -s -X POST http://%s:8899 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"getVersion","params":[],"id":1}'`, host),
		DiscoveredAt: time.Now(),
	}
}

// probeCosmosRPC probes port 26657 for a Cosmos/Tendermint node.
func probeCosmosRPC(ctx context.Context, client *http.Client, host, asset string) *finding.Finding {
	url := fmt.Sprintf("http://%s:26657/status", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if !bytes.Contains(body, []byte("node_info")) && !bytes.Contains(body, []byte("sync_info")) {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckChainNodeRPCExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Cosmos/Tendermint RPC exposed on %s:26657", host),
		Description: "Port 26657 is running a Cosmos/Tendermint node RPC server. " +
			"The /status endpoint reveals node ID, validator address, consensus state, " +
			"and peer list. If the validator private key (priv_validator_key.json) is on this host, " +
			"node compromise leads to double-signing and tombstoning.",
		Asset: asset,
		Evidence: map[string]any{
			"host":     host,
			"port":     "26657",
			"chain":    "cosmos/tendermint",
			"response": string(body[:min(len(body), 300)]),
		},
		ProofCommand: fmt.Sprintf("curl -s http://%s:26657/status | python3 -m json.tool | head -30", host),
		DiscoveredAt: time.Now(),
	}
}

// probeMetrics checks if a Prometheus metrics endpoint is open without auth.
func probeMetrics(ctx context.Context, client *http.Client, host, port, nodeDesc, asset string) *finding.Finding {
	url := fmt.Sprintf("http://%s:%s/metrics", host, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Prometheus metrics always start with "# HELP" or "# TYPE".
	if !bytes.Contains(body, []byte("# HELP")) && !bytes.Contains(body, []byte("# TYPE")) {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckChainNodeGrafanaExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("%s Prometheus metrics exposed on %s:%s", nodeDesc, host, port),
		Description: fmt.Sprintf(
			"The %s is exposing Prometheus metrics on port %s without authentication. "+
				"Metrics leak internal performance counters, peer counts, validator status, "+
				"chain head information, and memory/CPU usage that aids targeting of the node.",
			nodeDesc, port),
		Asset: asset,
		Evidence: map[string]any{
			"host":     host,
			"port":     port,
			"endpoint": "/metrics",
		},
		ProofCommand: fmt.Sprintf("curl -s http://%s:%s/metrics | grep -E '^# HELP|^beacon|^eth|^p2p' | head -20", host, port),
		DiscoveredAt: time.Now(),
	}
}

// isPortOpen checks TCP reachability within dialTimeout.
func isPortOpen(ctx context.Context, host, port string) bool {
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// resolveChainID maps common EVM chain IDs to human-readable names.
func resolveChainID(hexID string) string {
	chainNames := map[string]string{
		"0x1":     "Ethereum Mainnet",
		"0x5":     "Goerli Testnet",
		"0xaa36a7": "Sepolia Testnet",
		"0x89":    "Polygon",
		"0xa":     "Optimism",
		"0xa4b1":  "Arbitrum One",
		"0x2105":  "Base",
		"0x38":    "BNB Smart Chain",
		"0xa86a":  "Avalanche C-Chain",
		"0x144":   "zkSync Era",
		"0x539":   "Local / Hardhat (1337)",
		"0x7a69":  "Local / Anvil (31337)",
	}
	lower := strings.ToLower(hexID)
	if name, ok := chainNames[lower]; ok {
		return name
	}
	return hexID
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
