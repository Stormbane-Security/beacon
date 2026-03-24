package web3auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// mockSIWEServer creates a test HTTP server that implements a minimal SIWE flow.
// - GET /api/auth/nonce  → returns a nonce
// - POST /api/auth/verify → accepts any well-formed SIWE payload, returns session cookie
// usedNonces tracks which nonces have been consumed so we can test reuse.
func mockSIWEServer(t *testing.T, rejectNonceReuse bool, rejectWrongDomain bool) *httptest.Server {
	t.Helper()
	usedNonces := map[string]bool{}
	var nonceCounter atomic.Int64
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><button id="connectWallet">Sign In With Ethereum</button></body></html>`))
	})

	mux.HandleFunc("/api/auth/nonce", func(w http.ResponseWriter, r *http.Request) {
		n := nonceCounter.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"nonce":"testNonce%d"}`, n)
	})

	mux.HandleFunc("/api/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Message   string `json:"message"`
			Signature string `json:"signature"`
			Address   string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad request", 400)
			return
		}

		// Extract nonce from message for reuse check.
		nonce := ""
		for _, line := range strings.Split(payload.Message, "\n") {
			if strings.HasPrefix(line, "Nonce: ") {
				nonce = strings.TrimPrefix(line, "Nonce: ")
			}
		}

		if rejectNonceReuse && usedNonces[nonce] {
			http.Error(w, "nonce already used", 400)
			return
		}
		// Domain check: only inspect the first line of the message, which contains
		// the domain. This avoids false rejections when the attacker domain appears
		// only in the URI or other fields.
		if rejectWrongDomain {
			firstLine := strings.SplitN(payload.Message, "\n", 2)[0]
			if strings.Contains(firstLine, "attacker.beacon-scanner.invalid") {
				http.Error(w, "domain mismatch", 401)
				return
			}
		}

		usedNonces[nonce] = true
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "mock-session-token"})
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})

	return httptest.NewServer(mux)
}

// TestSIWE_WalletGeneration verifies ephemeral wallet creation and address derivation.
func TestSIWE_WalletGeneration(t *testing.T) {
	w, err := newEphemeralWallet()
	if err != nil {
		t.Fatalf("newEphemeralWallet() error: %v", err)
	}
	if !strings.HasPrefix(w.Address, "0x") {
		t.Errorf("Address should start with 0x, got: %s", w.Address)
	}
	if len(w.Address) != 42 {
		t.Errorf("Address should be 42 chars (0x + 40 hex), got %d: %s", len(w.Address), w.Address)
	}
}

// TestSIWE_TwoWalletsHaveDifferentAddresses verifies key generation is non-deterministic.
func TestSIWE_TwoWalletsHaveDifferentAddresses(t *testing.T) {
	w1, _ := newEphemeralWallet()
	w2, _ := newEphemeralWallet()
	if w1.Address == w2.Address {
		t.Error("Two ephemeral wallets should not have the same address")
	}
}

// TestSIWE_PersonalSignLength verifies the signature is 65 bytes (130 hex chars + 0x).
func TestSIWE_PersonalSignLength(t *testing.T) {
	w, _ := newEphemeralWallet()
	sig := w.personalSign("hello world")
	if !strings.HasPrefix(sig, "0x") {
		t.Errorf("Signature should start with 0x, got: %s", sig)
	}
	if len(sig) != 132 { // 0x + 130 hex chars = 65 bytes
		t.Errorf("Signature should be 132 chars (0x+130), got %d", len(sig))
	}
}

// TestSIWE_SurfaceDetectsEndpoint verifies that a server with SIWE endpoints
// triggers a CheckWeb3SIWEEndpoint finding in surface mode.
func TestSIWE_SurfaceDetectsEndpoint(t *testing.T) {
	srv := mockSIWEServer(t, true, true)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEEndpoint {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWEEndpoint finding in surface mode, got none")
	}
}

// TestSIWE_PageSignalDetected verifies SIWE detection via page content (no nonce endpoint).
func TestSIWE_PageSignalDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><script>if (window.ethereum) connectWallet();</script></body></html>`))
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEEndpoint {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWEEndpoint from page signal, got none")
	}
}

// TestSIWE_DomainBypassDetected verifies that a server which doesn't validate
// the domain in the SIWE message is flagged.
func TestSIWE_DomainBypassDetected(t *testing.T) {
	// Server that accepts ANY domain in the message.
	srv := mockSIWEServer(t, true, false /* don't reject wrong domain */)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEDomainBypass {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWEDomainBypass finding when domain not validated")
	}
}

// TestSIWE_DomainBypassNotFlaggedWhenEnforced verifies that a properly
// configured server (rejects wrong domain) does not produce a false positive.
func TestSIWE_DomainBypassNotFlaggedWhenEnforced(t *testing.T) {
	srv := mockSIWEServer(t, true, true /* reject wrong domain */)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEDomainBypass {
			t.Error("Got false positive CheckWeb3SIWEDomainBypass when server correctly enforces domain")
		}
	}
}

// TestSIWE_NonceReuseDetected verifies that a server accepting the same nonce
// twice is flagged as CheckWeb3SIWENonceReuse.
func TestSIWE_NonceReuseDetected(t *testing.T) {
	// Server that does NOT invalidate nonces after first use.
	srv := mockSIWEServer(t, false /* accept nonce reuse */, true)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWENonceReuse {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWENonceReuse finding when nonce reuse accepted")
	}
}

// TestSIWE_NonceReuseNotFlaggedWhenRejected verifies correct servers don't get
// a false positive nonce-reuse finding.
func TestSIWE_NonceReuseNotFlaggedWhenRejected(t *testing.T) {
	srv := mockSIWEServer(t, true /* reject nonce reuse */, true)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWENonceReuse {
			t.Error("Got false positive CheckWeb3SIWENonceReuse when server correctly rejects reuse")
		}
	}
}

// TestSIWE_NoFindingsOnPlainServer verifies no web3auth findings on a server
// with no SIWE signals at all.
func TestSIWE_NoFindingsOnPlainServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><body><p>Hello world</p></body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected no findings on plain server, got %d", len(findings))
	}
}

// TestSIWE_LooksLikeNonce verifies nonce detection heuristic.
func TestSIWE_LooksLikeNonce(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`testNonce12345678`, true},
		{`{"nonce":"abc123xyz789"}`, true},
		{`{"nonce":"x","status":"ok"}`, true},
		{`{"status":"ok"}`, false},
		{`<html>not a nonce</html>`, false},
		{`ab`, false}, // too short
	}
	for _, c := range cases {
		got := looksLikeNonce([]byte(c.body))
		if got != c.want {
			t.Errorf("looksLikeNonce(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

// TestSIWS_WalletGeneration verifies Solana Ed25519 wallet creation.
func TestSIWS_WalletGeneration(t *testing.T) {
	w, err := newEphemeralSolanaWallet()
	if err != nil {
		t.Fatalf("newEphemeralSolanaWallet() error: %v", err)
	}
	// Solana addresses are base58-encoded 32-byte public keys — 32-44 chars.
	if len(w.Address) < 32 || len(w.Address) > 44 {
		t.Errorf("Solana address length should be 32-44, got %d: %s", len(w.Address), w.Address)
	}
	// Must not start with 0x (that's Ethereum format).
	if strings.HasPrefix(w.Address, "0x") {
		t.Errorf("Solana address should not start with 0x, got: %s", w.Address)
	}
}

// TestSIWS_TwoWalletsHaveDifferentAddresses verifies Solana key non-determinism.
func TestSIWS_TwoWalletsHaveDifferentAddresses(t *testing.T) {
	w1, _ := newEphemeralSolanaWallet()
	w2, _ := newEphemeralSolanaWallet()
	if w1.Address == w2.Address {
		t.Error("Two Solana wallets should not have the same address")
	}
}

// TestSIWS_SignatureLength verifies Ed25519 signature is 64 bytes (hex-encoded + 0x prefix = 130 chars).
func TestSIWS_SignatureLength(t *testing.T) {
	w, _ := newEphemeralSolanaWallet()
	sig := w.sign("hello solana")
	if !strings.HasPrefix(sig, "0x") {
		t.Errorf("Solana signature should start with 0x, got: %s", sig)
	}
	if len(sig) != 130 { // 0x + 128 hex chars = 64 bytes
		t.Errorf("Ed25519 signature should be 130 chars, got %d", len(sig))
	}
}

// TestSIWS_BuildMessageContainsFields verifies SIWS message construction.
func TestSIWS_BuildMessageContainsFields(t *testing.T) {
	w, _ := newEphemeralSolanaWallet()
	msg := buildSIWSMessage("example.com", w.Address, "nonce99", "https://example.com")
	if !strings.Contains(msg, "example.com") {
		t.Error("SIWS message missing domain")
	}
	if !strings.Contains(msg, w.Address) {
		t.Error("SIWS message missing Solana address")
	}
	if !strings.Contains(msg, "nonce99") {
		t.Error("SIWS message missing nonce")
	}
	if !strings.Contains(msg, "solana:mainnet") {
		t.Error("SIWS message missing Solana chain ID")
	}
}

// TestWeb3Auth_DetectsEVMAndSolanaSignals verifies both protocol signals are detected.
func TestWeb3Auth_DetectsEVMAndSolanaSignals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>
			<script>if (window.ethereum) connectEVM();</script>
			<script>if (window.solana) connectPhantom();</script>
		</body></html>`))
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	hasEVM := false
	hasSolana := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEEndpoint {
			hasEVM = true
		}
		if f.CheckID == finding.CheckWeb3SIWSDEndpoint {
			hasSolana = true
		}
	}
	if !hasEVM {
		t.Error("Expected CheckWeb3SIWEEndpoint for window.ethereum signal")
	}
	if !hasSolana {
		t.Error("Expected CheckWeb3SIWSDEndpoint for window.solana signal")
	}
}

// TestSIWE_ChainMismatchDetected verifies chain ID mismatch is caught.
func TestSIWE_ChainMismatchDetected(t *testing.T) {
	// Server that accepts any chain ID.
	srv := mockSIWEServer(t, true, true)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEChainMismatch {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWEChainMismatch when chain ID not validated")
	}
}

// TestSIWE_URIMismatchDetected verifies URI mismatch is caught.
func TestSIWE_URIMismatchDetected(t *testing.T) {
	srv := mockSIWEServer(t, true, true)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEURIMismatch {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWEURIMismatch when URI not validated")
	}
}

// TestSIWE_BuildMessageContainsFields verifies SIWE message construction.
func TestSIWE_BuildMessageContainsFields(t *testing.T) {
	msg := buildSIWEMessage("example.com", "0xAbCd1234", "nonce99", "https://example.com")
	if !strings.Contains(msg, "example.com") {
		t.Error("SIWE message missing domain")
	}
	if !strings.Contains(msg, "0xAbCd1234") {
		t.Error("SIWE message missing address")
	}
	if !strings.Contains(msg, "nonce99") {
		t.Error("SIWE message missing nonce")
	}
	if !strings.Contains(msg, "https://example.com") {
		t.Error("SIWE message missing URI")
	}
	if !strings.Contains(msg, "Chain ID: 1") {
		t.Error("SIWE message missing chain ID")
	}
}

// TestSIWS_SignBase58IsNotHexPrefixed verifies that signBase58 returns a
// base58-encoded signature (no "0x" prefix) while sign() returns hex.
// Both must produce 64-byte Ed25519 signatures but in different encodings.
func TestSIWS_SignBase58IsNotHexPrefixed(t *testing.T) {
	w, err := newEphemeralSolanaWallet()
	if err != nil {
		t.Fatalf("newEphemeralSolanaWallet() error: %v", err)
	}
	sig := w.signBase58("hello solana")
	if strings.HasPrefix(sig, "0x") {
		t.Errorf("signBase58 must return base58 (no 0x prefix), got: %s", sig)
	}
	// Base58 uses only alphanumeric characters without 0, O, I, l.
	for _, c := range sig {
		if strings.ContainsRune("0OIl", c) {
			t.Errorf("base58 must not contain ambiguous char %q in: %s", c, sig)
		}
	}
}

// TestSIWE_SIWEOverHTTP_FlaggedWhenHTTPAndEVMSignals tests that the scanner
// emits CheckWeb3SIWEOverHTTP when the server is plain HTTP and has EVM signals.
func TestSIWE_SIWEOverHTTP_FlaggedWhenHTTPAndEVMSignals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><script>if (window.ethereum) { connectWallet(); }</script></body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// httptest.NewServer starts on HTTP — confirms the scanner treats it as plain HTTP.
	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEOverHTTP {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWEOverHTTP when SIWE is served over plain HTTP")
	}
}

// TestSIWE_ReplayDetected verifies that a server accepting backdated messages
// is flagged as CheckWeb3SIWEReplay.
func TestSIWE_ReplayDetected(t *testing.T) {
	// Server that does not validate the Issued At field — any timestamp accepted.
	srv := mockSIWEServer(t, false /* accept nonce reuse */, false /* accept any domain */)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEReplay {
			found = true
		}
	}
	if !found {
		t.Error("Expected CheckWeb3SIWEReplay when server accepts backdated messages")
	}
}

// TestSIWE_ChainMismatchNotFlaggedWhenEnforced verifies correct servers
// (those that reject wrong chain ID) do not produce a false positive.
func TestSIWE_ChainMismatchNotFlaggedWhenEnforced(t *testing.T) {
	var mux http.ServeMux
	var nonceCounter atomic.Int64

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>Sign In With Ethereum</body></html>`))
	})
	mux.HandleFunc("/api/auth/nonce", func(w http.ResponseWriter, r *http.Request) {
		n := nonceCounter.Add(1)
		fmt.Fprintf(w, `{"nonce":"chainTestNonce%d"}`, n)
	})
	mux.HandleFunc("/api/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		// Reject any message with chain ID other than 1.
		if strings.Contains(payload.Message, "Chain ID: 137") {
			http.Error(w, "wrong chain", 401)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess"})
		w.WriteHeader(200)
	})

	srv := httptest.NewServer(&mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEChainMismatch {
			t.Error("Got false positive CheckWeb3SIWEChainMismatch when server enforces chain ID")
		}
	}
}

// TestSIWE_URIMismatchNotFlaggedWhenEnforced verifies that a server rejecting
// wrong URI values does not produce a false positive finding.
func TestSIWE_URIMismatchNotFlaggedWhenEnforced(t *testing.T) {
	var mux http.ServeMux
	var nonceCounter atomic.Int64

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>Sign In With Ethereum</body></html>`))
	})
	mux.HandleFunc("/api/auth/nonce", func(w http.ResponseWriter, r *http.Request) {
		n := nonceCounter.Add(1)
		fmt.Fprintf(w, `{"nonce":"uriTestNonce%d"}`, n)
	})
	mux.HandleFunc("/api/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		// Reject messages where URI field references an external domain.
		for _, line := range strings.Split(payload.Message, "\n") {
			if strings.HasPrefix(line, "URI: ") {
				if strings.Contains(line, "attacker.beacon-scanner.invalid") {
					http.Error(w, "invalid uri", 401)
					return
				}
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess"})
		w.WriteHeader(200)
	})

	srv := httptest.NewServer(&mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3SIWEURIMismatch {
			t.Error("Got false positive CheckWeb3SIWEURIMismatch when server enforces URI validation")
		}
	}
}
