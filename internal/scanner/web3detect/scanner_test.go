package web3detect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// TestWeb3Detect_WalletLibInHTML verifies that a page containing
// window.ethereum produces a CheckWeb3WalletLibDetected finding.
func TestWeb3Detect_WalletLibInHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body>
<script>
if (typeof window.ethereum !== 'undefined') {
  connectWallet();
}
</script>
</body></html>`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3WalletLibDetected {
			found = true
			if f.Severity != finding.SeverityInfo {
				t.Errorf("expected Info severity, got %s", f.Severity)
			}
			libs, ok := f.Evidence["libraries"]
			if !ok {
				t.Error("evidence should contain 'libraries' key")
			}
			libSlice, _ := libs.([]string)
			foundLib := false
			for _, l := range libSlice {
				if l == "window.ethereum" {
					foundLib = true
				}
			}
			if !foundLib {
				t.Errorf("expected 'window.ethereum' in libraries, got %v", libSlice)
			}
		}
	}
	if !found {
		t.Error("expected a CheckWeb3WalletLibDetected finding, got none")
	}
}

// TestWeb3Detect_RPCEndpointInJS verifies that an Infura URL in a JS file
// produces a CheckWeb3RPCEndpointExposed finding.
func TestWeb3Detect_RPCEndpointInJS(t *testing.T) {
	rpcURL := "https://mainnet.infura.io/v3/abc123secretkey"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintln(w, `<html><head><script src="/app.js"></script></head><body></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `const provider = new ethers.providers.JsonRpcProvider("%s");`, rpcURL)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3RPCEndpointExposed {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
			urls, ok := f.Evidence["rpc_urls"]
			if !ok {
				t.Error("evidence should contain 'rpc_urls' key")
			}
			urlSlice, _ := urls.([]string)
			if len(urlSlice) == 0 {
				t.Error("rpc_urls should not be empty")
			}
		}
	}
	if !found {
		t.Error("expected a CheckWeb3RPCEndpointExposed finding, got none")
	}
}

// TestWeb3Detect_ContractAddressFound verifies that a page containing a
// 0x-prefixed 40-hex address produces a CheckWeb3ContractFound finding.
func TestWeb3Detect_ContractAddressFound(t *testing.T) {
	contractAddr := "0xdAC17F958D2ee523a2206206994597C13D831ec7" // USDT on mainnet

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
<script>
const CONTRACT_ADDRESS = "%s";
</script>
</body></html>`, contractAddr)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3ContractFound {
			found = true
			if f.Severity != finding.SeverityInfo {
				t.Errorf("expected Info severity, got %s", f.Severity)
			}
			addrs, ok := f.Evidence["addresses"]
			if !ok {
				t.Error("evidence should contain 'addresses' key")
			}
			addrSlice, _ := addrs.([]string)
			if len(addrSlice) == 0 {
				t.Error("addresses should not be empty")
			}
		}
	}
	if !found {
		t.Error("expected a CheckWeb3ContractFound finding, got none")
	}
}

// TestWeb3Detect_NoWeb3Signals verifies that a plain non-web3 page produces
// no findings.
func TestWeb3Detect_NoWeb3Signals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><h1>Welcome to my website</h1></body></html>`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-web3 page, got %d: %v", len(findings), findings)
	}
}

// TestWeb3Detect_DeduplicatesFindings verifies that multiple contract
// addresses in the same page produce only one CheckWeb3ContractFound finding.
func TestWeb3Detect_DeduplicatesFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Three distinct contract addresses on the same page.
		fmt.Fprintln(w, `<html><body><script>
const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const DAI  = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
</script></body></html>`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	contractFindings := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3ContractFound {
			contractFindings++
		}
	}
	if contractFindings != 1 {
		t.Errorf("expected exactly 1 CheckWeb3ContractFound finding (deduplicated), got %d", contractFindings)
	}
}
