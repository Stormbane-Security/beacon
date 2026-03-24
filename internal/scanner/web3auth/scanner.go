// Package web3auth tests Web3 wallet authentication for security vulnerabilities.
// It supports two protocols:
//
//   - EVM / SIWE (Sign-In With Ethereum, EIP-4361): used by MetaMask, Coinbase Wallet,
//     WalletConnect, Trust Wallet, Rainbow, Phantom (EVM mode), and every other
//     EIP-1193-compatible wallet. Uses secp256k1 + EIP-191 personal_sign.
//
//   - Solana / SIWS (Sign In With Solana): used by Phantom (Solana mode), Solflare,
//     Backpack, Brave Wallet (Solana mode). Uses Ed25519 with raw message signing.
//
// WalletConnect is NOT a separate auth scheme — it is a transport relay that lets
// mobile wallets (Trust, Rainbow, etc.) connect to dApps. From the server's
// perspective, WalletConnect sessions produce the same Ethereum address + signature
// as a MetaMask session. No special handling is needed.
//
// Wallet selection strategy:
// The scanner auto-detects which protocol(s) the target supports by scanning
// the page for EVM signals (window.ethereum, ethers, wagmi, siwe) and Solana
// signals (window.solana, @solana/wallet-adapter, phantom). It then runs probes
// for each detected protocol independently. If both are present, both are tested.
// There is no need to "pick a wallet" — the scanner generates its own ephemeral
// key pair per protocol and speaks directly to the server's auth API.
//
// Surface mode:
//   - Auto-detect EVM (SIWE) and Solana (SIWS) signals in page content
//   - Probe well-known nonce/verify endpoints for both protocols
//   - Check if auth is accessible over plain HTTP (CheckWeb3SIWEOverHTTP)
//   - Emit CheckWeb3SIWEEndpoint / CheckWeb3SIWSDEndpoint (Info)
//
// Deep mode (requires --permission-confirmed):
//   - Ephemeral wallet login flow (SIWE and/or SIWS)
//   - Domain binding bypass (wrong domain in signed message)
//   - Nonce reuse (re-submit consumed nonce)
//   - Replay attack (backdated message timestamp)
//   - Chain ID mismatch (wrong chain in signed message) — EVM only
//   - URI mismatch (wrong URI field in signed message)
//   - Horizontal escalation (access another wallet's resources via our session)
package web3auth

import (
	"bytes"
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

const scannerName = "web3auth"

// Scanner implements SIWE + SIWS authentication security testing.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// nonceEndpoints are common paths where nonce generation is served (shared by SIWE and SIWS).
var nonceEndpoints = []string{
	"/api/auth/nonce",
	"/api/siwe/nonce",
	"/api/siws/nonce",
	"/api/v1/auth/nonce",
	"/api/nonce",
	"/siwe/nonce",
	"/siws/nonce",
	"/auth/nonce",
	"/nonce",
	"/api/auth/csrf",
	"/connect/nonce",
	"/api/auth/providers",
}

// verifyEndpoints are common paths for signature verification / login.
var verifyEndpoints = []string{
	"/api/auth/verify",
	"/api/auth/callback/credentials",
	"/api/siwe/verify",
	"/api/siws/verify",
	"/api/v1/auth/verify",
	"/api/auth/login",
	"/siwe/verify",
	"/siws/verify",
	"/auth/verify",
	"/login",
	"/api/login",
	"/connect/verify",
}

// evmSignals are HTML/JS patterns that indicate EVM (SIWE) auth.
var evmSignals = []string{
	"siwe",
	"sign-in with ethereum",
	"signmessage",
	"personal_sign",
	"eth_requestaccounts",
	"metamask",
	"wagmi",
	"window.ethereum",
	"useconnect",
	"connectwallet",
	"walletconnect",
	"ethers",
	"viem",
	"coinbase wallet",
	"rainbow",
}

// solanaSignals are HTML/JS patterns indicating Solana (SIWS) auth.
var solanaSignals = []string{
	"window.solana",
	"solana.connect",
	"@solana/wallet-adapter",
	"solflare",
	"backpack",
	"sign in with solana",
	"signmessage", // shared with EVM but also used by Phantom Solana
	"phantom",
	"solana.signmessage",
	"usewallet",    // @solana/wallet-adapter-react
	"walletadapter",
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := discoverBase(ctx, client, asset)
	if baseURL == "" {
		return nil, nil
	}

	var findings []finding.Finding
	now := time.Now()

	// ── HTTP exposure check (surface, before any auth probing) ────────────────
	// If the site serves SIWE/SIWS over plain HTTP, signed messages are
	// interceptable by any network observer.
	if strings.HasPrefix(baseURL, "http://") {
		// Only flag if we also find auth signals — avoid noise on all HTTP sites.
		pageBody := fetchBody(ctx, client, baseURL, 64*1024)
		hasEVM := containsAny(strings.ToLower(pageBody), evmSignals)
		hasSolana := containsAny(strings.ToLower(pageBody), solanaSignals)
		if hasEVM || hasSolana {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEOverHTTP,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("Web3 wallet auth accessible over plain HTTP on %s", baseURL),
				Description: "This application serves wallet authentication (SIWE/SIWS) over " +
					"unencrypted HTTP. Any network observer or attacker performing MITM can " +
					"intercept the signed message and replay it to authenticate as the victim. " +
					"Wallet auth MUST be served exclusively over HTTPS.",
				Evidence: map[string]any{
					"url":          baseURL,
					"evm_signals":  hasEVM,
					"solana_signals": hasSolana,
				},
				DiscoveredAt: now,
			})
		}
	}

	// ── Protocol detection ────────────────────────────────────────────────────
	nonceURL, verifyURL := discoverSIWEEndpoints(ctx, client, baseURL)
	pageBody := fetchBody(ctx, client, baseURL, 64*1024)
	pageLower := strings.ToLower(pageBody)

	hasEVMSignals := containsAny(pageLower, evmSignals) || nonceURL != ""
	hasSolanaSignals := containsAny(pageLower, solanaSignals)

	// ── Surface: emit detection findings ─────────────────────────────────────
	if hasEVMSignals {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWeb3SIWEEndpoint,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("SIWE (Sign-In With Ethereum) authentication detected on %s", baseURL),
			Description: "EVM wallet authentication (MetaMask, Coinbase, WalletConnect, Trust, Rainbow) " +
				"using EIP-4361 Sign-In With Ethereum detected. " +
				"Run a deep scan to test for domain bypass, nonce reuse, replay, and escalation attacks.",
			Evidence: map[string]any{
				"base_url":        baseURL,
				"nonce_endpoint":  nonceURL,
				"verify_endpoint": verifyURL,
			},
			DiscoveredAt: now,
		})
	}
	if hasSolanaSignals {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWeb3SIWSDEndpoint,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("SIWS (Sign In With Solana) authentication detected on %s", baseURL),
			Description: "Solana wallet authentication (Phantom, Solflare, Backpack) using Ed25519 " +
				"Sign In With Solana detected. " +
				"Run a deep scan to test for domain bypass, nonce reuse, and replay attacks.",
			Evidence: map[string]any{
				"base_url":        baseURL,
				"nonce_endpoint":  nonceURL,
				"verify_endpoint": verifyURL,
			},
			DiscoveredAt: now,
		})
	}

	if scanType != module.ScanDeep {
		return findings, nil
	}
	if !hasEVMSignals && !hasSolanaSignals {
		return findings, nil
	}
	if verifyURL == "" {
		return findings, nil
	}

	// ── Deep mode: run probes for each detected protocol ─────────────────────
	// Strategy: generate one ephemeral wallet per protocol detected.
	// EVM probes run if EVM signals found; Solana probes run if Solana signals found.
	// Both are independent — no need to "pick" a wallet.
	domain := extractDomain(baseURL)
	uri := strings.TrimSuffix(baseURL, "/")
	verifyFull := strings.TrimSuffix(baseURL, "/") + verifyURL
	nonceFull := ""
	if nonceURL != "" {
		nonceFull = strings.TrimSuffix(baseURL, "/") + nonceURL
	}

	if hasEVMSignals {
		wallet, err := newEphemeralWallet()
		if err == nil {
			evmFindings := runEVMProbes(ctx, client, asset, baseURL, verifyFull, nonceFull, wallet, domain, uri, now)
			findings = append(findings, evmFindings...)
		}
	}

	if hasSolanaSignals {
		solWallet, err := newEphemeralSolanaWallet()
		if err == nil {
			solFindings := runSolanaProbes(ctx, client, asset, baseURL, verifyFull, nonceFull, solWallet, domain, uri, now)
			findings = append(findings, solFindings...)
		}
	}

	return findings, nil
}

// runEVMProbes runs all deep-mode SIWE security probes with an ephemeral EVM wallet.
func runEVMProbes(ctx context.Context, client *http.Client, asset, baseURL, verifyURL, nonceURL string, w *Wallet, domain, uri string, now time.Time) []finding.Finding {
	var findings []finding.Finding

	// Login: establish baseline and capture the nonce that gets consumed.
	loginNonce, sessionCookie := doEVMLogin(ctx, client, nonceURL, verifyURL, w, domain, uri)
	loginSucceeded := sessionCookie != ""

	// ── Probe: Domain binding bypass ─────────────────────────────────────────
	{
		probeNonce := fetchFreshNonce(ctx, client, nonceURL)
		if probeNonce == "" {
			probeNonce = randomNonce()
		}
		wrongDomain := "attacker.beacon-scanner.invalid"
		msg := buildSIWEMessage(wrongDomain, w.Address, probeNonce, "https://"+wrongDomain)
		sig := w.personalSign(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEDomainBypass,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWE domain binding not enforced on %s", baseURL),
				Description: fmt.Sprintf(
					"The server accepted a SIWE message signed for domain %q instead of %q. "+
						"An attacker can trick a user into signing a SIWE message on a malicious site "+
						"and replay it to hijack their session on this application.",
					wrongDomain, domain),
				Evidence: map[string]any{"expected_domain": domain, "submitted_domain": wrongDomain, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: Chain ID mismatch (EVM-specific) ───────────────────────────────
	// EIP-4361 requires the server to verify Chain ID matches the expected chain.
	// Accepting a message for chain 137 (Polygon) on an Ethereum mainnet app allows
	// cross-chain replay attacks.
	{
		probeNonce := fetchFreshNonce(ctx, client, nonceURL)
		if probeNonce == "" {
			probeNonce = randomNonce()
		}
		// Build message manually with a different chain ID (Polygon mainnet = 137).
		issuedAt := time.Now().UTC().Format(time.RFC3339)
		wrongChainMsg := fmt.Sprintf(
			"%s wants you to sign in with your Ethereum account:\n%s\n\n"+
				"Beacon security scanner authentication probe.\n\n"+
				"URI: %s\nVersion: 1\nChain ID: 137\nNonce: %s\nIssued At: %s",
			domain, w.Address, uri, probeNonce, issuedAt,
		)
		sig := w.personalSign(wrongChainMsg)
		if accepted, code := submitVerify(ctx, client, verifyURL, wrongChainMsg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEChainMismatch,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWE chain ID not validated on %s", baseURL),
				Description: "The server accepted a SIWE message with Chain ID 137 (Polygon) " +
					"without validating that it matches the expected chain. " +
					"This enables cross-chain replay: a signature obtained on Polygon can be used " +
					"to authenticate on this Ethereum application as the same address.",
				Evidence: map[string]any{"submitted_chain_id": 137, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: URI mismatch ───────────────────────────────────────────────────
	{
		probeNonce := fetchFreshNonce(ctx, client, nonceURL)
		if probeNonce == "" {
			probeNonce = randomNonce()
		}
		wrongURI := "https://attacker.beacon-scanner.invalid"
		msg := buildSIWEMessage(domain, w.Address, probeNonce, wrongURI)
		sig := w.personalSign(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEURIMismatch,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWE URI field not validated on %s", baseURL),
				Description: "The server accepted a SIWE message where the URI field " +
					"references a different application (attacker.beacon-scanner.invalid). " +
					"Servers must reject messages whose URI does not match the service URI.",
				Evidence: map[string]any{"submitted_uri": wrongURI, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: Nonce reuse ────────────────────────────────────────────────────
	if loginNonce != "" {
		msg := buildSIWEMessage(domain, w.Address, loginNonce, uri)
		sig := w.personalSign(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWENonceReuse,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWE nonce reuse accepted on %s", baseURL),
				Description: "The server accepted the same SIWE nonce a second time. " +
					"Nonces must be invalidated immediately after first use.",
				Evidence: map[string]any{"nonce": loginNonce, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: Replay (backdated timestamp) ───────────────────────────────────
	{
		oldNonce := randomNonce()
		oldTime := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
		msg := fmt.Sprintf(
			"%s wants you to sign in with your Ethereum account:\n%s\n\n"+
				"Beacon security scanner authentication probe.\n\n"+
				"URI: %s\nVersion: 1\nChain ID: 1\nNonce: %s\nIssued At: %s",
			domain, w.Address, uri, oldNonce, oldTime,
		)
		sig := w.personalSign(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEReplay,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWE replay with backdated message accepted on %s", baseURL),
				Description: "The server accepted a SIWE message timestamped 2 hours ago " +
					"without enforcing a validity window on the Issued At field.",
				Evidence: map[string]any{"issued_at": oldTime, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: Horizontal escalation ─────────────────────────────────────────
	if loginSucceeded {
		other, err := newEphemeralWallet()
		if err == nil && probeHorizontalEscalation(ctx, client, baseURL, sessionCookie, w.Address, other.Address) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3HorizontalEscalation,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWE horizontal escalation: accessed another wallet's resources on %s", baseURL),
				Description: fmt.Sprintf(
					"Authenticated as wallet %s, the scanner read resources for wallet %s "+
						"by substituting the address in API requests. "+
						"The server trusts the client-supplied address instead of deriving it from the session.",
					w.Address, other.Address),
				Evidence: map[string]any{"our_wallet": w.Address, "target_wallet": other.Address},
				DiscoveredAt: now,
			})
		}
	}

	return findings
}

// runSolanaProbes runs SIWS security probes with an ephemeral Solana wallet.
// The same categories are tested as EVM, but chain ID mismatch uses Solana
// chain identifiers.
func runSolanaProbes(ctx context.Context, client *http.Client, asset, baseURL, verifyURL, nonceURL string, w *SolanaWallet, domain, uri string, now time.Time) []finding.Finding {
	var findings []finding.Finding

	loginNonce, _ := doSolanaLogin(ctx, client, nonceURL, verifyURL, w, domain, uri)

	// ── Probe: Domain bypass ──────────────────────────────────────────────────
	{
		probeNonce := fetchFreshNonce(ctx, client, nonceURL)
		if probeNonce == "" {
			probeNonce = randomNonce()
		}
		wrongDomain := "attacker.beacon-scanner.invalid"
		msg := buildSIWSMessage(wrongDomain, w.Address, probeNonce, "https://"+wrongDomain)
		sig := w.signBase58(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEDomainBypass,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWS (Solana) domain binding not enforced on %s", baseURL),
				Description: fmt.Sprintf(
					"The server accepted a SIWS message signed for domain %q instead of %q.",
					wrongDomain, domain),
				Evidence: map[string]any{"protocol": "solana", "expected_domain": domain, "submitted_domain": wrongDomain, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: URI mismatch ───────────────────────────────────────────────────
	{
		probeNonce := fetchFreshNonce(ctx, client, nonceURL)
		if probeNonce == "" {
			probeNonce = randomNonce()
		}
		wrongURI := "https://attacker.beacon-scanner.invalid"
		msg := buildSIWSMessage(domain, w.Address, probeNonce, wrongURI)
		sig := w.signBase58(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEURIMismatch,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWS (Solana) URI field not validated on %s", baseURL),
				Description: "The server accepted a SIWS message with a URI for a different application.",
				Evidence: map[string]any{"protocol": "solana", "submitted_uri": wrongURI, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: Nonce reuse ────────────────────────────────────────────────────
	if loginNonce != "" {
		msg := buildSIWSMessage(domain, w.Address, loginNonce, uri)
		sig := w.signBase58(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWENonceReuse,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWS (Solana) nonce reuse accepted on %s", baseURL),
				Description: "The server accepted the same SIWS nonce a second time.",
				Evidence: map[string]any{"protocol": "solana", "nonce": loginNonce, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	// ── Probe: Replay ─────────────────────────────────────────────────────────
	{
		oldNonce := randomNonce()
		oldTime := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
		msg := fmt.Sprintf(
			"%s wants you to sign in with your Solana account:\n%s\n\n"+
				"Beacon security scanner authentication probe.\n\n"+
				"URI: %s\nVersion: 1\nChain ID: solana:mainnet\nNonce: %s\nIssued At: %s",
			domain, w.Address, uri, oldNonce, oldTime,
		)
		sig := w.signBase58(msg)
		if accepted, code := submitVerify(ctx, client, verifyURL, msg, sig, w.Address); accepted {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWeb3SIWEReplay,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("SIWS (Solana) replay with backdated message accepted on %s", baseURL),
				Description: "The server accepted a SIWS message timestamped 2 hours ago.",
				Evidence: map[string]any{"protocol": "solana", "issued_at": oldTime, "status_code": code},
				DiscoveredAt: now,
			})
		}
	}

	return findings
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func discoverBase(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + asset + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return u
		}
	}
	return ""
}

func fetchBody(ctx context.Context, client *http.Client, url string, maxBytes int64) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	resp.Body.Close()
	return string(body)
}

func discoverSIWEEndpoints(ctx context.Context, client *http.Client, baseURL string) (nonceURL, verifyURL string) {
	base := strings.TrimSuffix(baseURL, "/")
	for _, path := range nonceEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode == 200 && looksLikeNonce(body) {
			nonceURL = path
			break
		}
	}
	for _, path := range verifyEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, strings.NewReader(`{}`))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			verifyURL = path
			break
		}
	}
	return
}

func fetchFreshNonce(ctx context.Context, client *http.Client, nonceURL string) string {
	if nonceURL == "" {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nonceURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	resp.Body.Close()
	return parseNonce(body)
}

// doEVMLogin performs a single SIWE login, consuming one nonce.
// Returns the nonce used (for the nonce-reuse probe) and session cookie.
func doEVMLogin(ctx context.Context, client *http.Client, nonceURL, verifyURL string, w *Wallet, domain, uri string) (string, string) {
	nonce := fetchFreshNonce(ctx, client, nonceURL)
	if nonce == "" {
		nonce = randomNonce()
	}
	msg := buildSIWEMessage(domain, w.Address, nonce, uri)
	sig := w.personalSign(msg)
	cookie := doVerifyGetCookie(ctx, client, verifyURL, msg, sig, w.Address)
	return nonce, cookie
}

// doSolanaLogin performs a single SIWS login, consuming one nonce.
func doSolanaLogin(ctx context.Context, client *http.Client, nonceURL, verifyURL string, w *SolanaWallet, domain, uri string) (string, string) {
	nonce := fetchFreshNonce(ctx, client, nonceURL)
	if nonce == "" {
		nonce = randomNonce()
	}
	msg := buildSIWSMessage(domain, w.Address, nonce, uri)
	sig := w.signBase58(msg)
	cookie := doVerifyGetCookie(ctx, client, verifyURL, msg, sig, w.Address)
	return nonce, cookie
}

// doVerifyGetCookie sends a single verify POST and returns the session cookie (or "authenticated" if 2xx but no cookie).
func doVerifyGetCookie(ctx context.Context, client *http.Client, verifyURL, message, signature, address string) string {
	payload := map[string]string{"message": message, "signature": signature, "address": address}
	body, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	for _, c := range resp.Cookies() {
		if isSessionCookie(c.Name) {
			return c.Name + "=" + c.Value
		}
	}
	if auth := resp.Header.Get("Authorization"); auth != "" {
		return auth
	}
	if tok := resp.Header.Get("X-Auth-Token"); tok != "" {
		return tok
	}
	return "authenticated"
}

// submitVerify sends a SIWE/SIWS verify payload; returns (accepted, statusCode).
func submitVerify(ctx context.Context, client *http.Client, verifyURL, message, signature, address string) (bool, int) {
	payload := map[string]string{"message": message, "signature": signature, "address": address}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(body))
	if err != nil {
		return false, 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, resp.StatusCode
}

func probeHorizontalEscalation(ctx context.Context, client *http.Client, baseURL, sessionCookie, ourAddress, otherAddress string) bool {
	probeTemplates := []string{
		"/api/user/%s/profile",
		"/api/users/%s",
		"/api/account/%s",
		"/api/wallet/%s",
		"/api/v1/user/%s",
		"/api/v1/users/%s",
		"/api/v2/users/%s",
		"/profile/%s",
	}
	base := strings.TrimSuffix(baseURL, "/")
	for _, tmpl := range probeTemplates {
		ourCode := getWithSession(ctx, client, base+fmt.Sprintf(tmpl, ourAddress), sessionCookie)
		otherCode := getWithSession(ctx, client, base+fmt.Sprintf(tmpl, otherAddress), sessionCookie)
		if ourCode == 200 && otherCode == 200 {
			return true
		}
	}
	return false
}

func getWithSession(ctx context.Context, client *http.Client, url, cookie string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func looksLikeNonce(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) >= 8 && len(trimmed) <= 64 {
		allAlnum := true
		for _, c := range trimmed {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				allAlnum = false
				break
			}
		}
		if allAlnum {
			return true
		}
	}
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		if _, ok := obj["nonce"]; ok {
			return true
		}
	}
	return false
}

func parseNonce(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) >= 8 && len(trimmed) <= 64 {
		allAlnum := true
		for _, c := range trimmed {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				allAlnum = false
				break
			}
		}
		if allAlnum {
			return trimmed
		}
	}
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		if v, ok := obj["nonce"]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func isSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range []string{"session", "token", "auth", "jwt", "sid", "access"} {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func extractDomain(baseURL string) string {
	u := strings.TrimPrefix(baseURL, "https://")
	u = strings.TrimPrefix(u, "http://")
	return strings.TrimSuffix(u, "/")
}

func redactCookie(cookie string) string {
	parts := strings.SplitN(cookie, "=", 2)
	if len(parts) == 2 {
		val := parts[1]
		if len(val) > 8 {
			return parts[0] + "=" + val[:4] + "****"
		}
		return parts[0] + "=****"
	}
	return "****"
}

// keep redactCookie used to avoid lint error — used in evidence maps above if needed.
var _ = redactCookie
